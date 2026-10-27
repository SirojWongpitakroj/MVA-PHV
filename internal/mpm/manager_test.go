package mpm

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
	"github.com/SirojWongpitakroj/mva-phv/internal/hmf"
	"github.com/SirojWongpitakroj/mva-phv/internal/hpbf"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
	"github.com/SirojWongpitakroj/mva-phv/internal/mva"
)

type testIDs struct {
	mu   sync.Mutex
	next uint64
}

type fixedIDs struct{ id uuid.UUID }

func (g fixedIDs) NewID() (uuid.UUID, error) { return g.id, nil }

func (g *testIDs) NewID() (uuid.UUID, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.next++
	var id uuid.UUID
	id[15] = byte(g.next)
	id[14] = byte(g.next >> 8)
	return id, nil
}

type testEncrypt struct{}

func (testEncrypt) Encrypt(_ context.Context, _ uuid.UUID, _ Descriptor, plain []byte) (Encrypted, error) {
	return Encrypted{Ciphertext: append([]byte(nil), plain...), Digest: sha256.Sum256(plain)}, nil
}

type testLocator struct{}

func (testLocator) CommitLocator(id uuid.UUID, d Descriptor, a Address) ([32]byte, error) {
	b, err := domain.Serialize([]byte("TESTLOC"), id, d.RegionID, d.SiteID, d.DeviceID, d.Type, d.TS, a.RegionID, uint64(a.ShardID), uint64(a.SegmentID), uint64(a.LeafID))
	return sha256.Sum256(b), err
}

type testShard struct {
	active *Segment
	next   int64
	leafs  [][32]byte
	opened time.Time
}
type testHMF struct {
	mu             sync.Mutex
	shards         map[merkle.TreeID]*testShard
	pending        []Segment
	persisted      map[merkle.TreeID]bool
	candidate      []Segment
	candidateEpoch uint64
	finalized      uint64
	max            int64
	age            time.Duration
	inserted       []RecordAddress
	reserved       map[merkle.TreeID]bool
}
type RecordAddress struct {
	Address Address
	Leaf    [32]byte
}

func newTestHMF(max int64, age time.Duration) *testHMF {
	return &testHMF{shards: map[merkle.TreeID]*testShard{}, persisted: map[merkle.TreeID]bool{}, reserved: map[merkle.TreeID]bool{}, max: max, age: age}
}
func (h *testHMF) SelectShard(rid, site, dev string) (int64, error) {
	if rid != "r0" && rid != "r1" {
		return 0, fmt.Errorf("unknown region")
	}
	b, _ := domain.Serialize([]byte("HMF-SHARD-MAP"), rid, site, dev)
	digest := sha256.Sum256(b)
	return int64(digest[0] % 4), nil
}
func (h *testHMF) seal(sh *testShard, now time.Time) {
	seg := *sh.active
	seg.LeafCount = int64(len(sh.leafs))
	seg.Root = sha256.Sum256(fmt.Append(nil, sh.leafs))
	seg.SealedAt = now
	h.pending = append(h.pending, seg)
	sh.active = nil
	sh.leafs = nil
}

type testReservation struct {
	h       *testHMF
	address Address
	key     merkle.TreeID
}

func (r *testReservation) Address() Address { return r.address }
func (r *testReservation) Commit(leaf [32]byte, now time.Time) error {
	r.h.mu.Lock()
	defer r.h.mu.Unlock()
	if !r.h.reserved[r.key] {
		return errors.New("reservation completed")
	}
	sh := r.h.shards[r.key]
	if sh.active == nil || sh.active.ID.SegmentID != r.address.SegmentID || int64(len(sh.leafs)) != r.address.LeafID {
		return errors.New("position changed")
	}
	sh.leafs = append(sh.leafs, leaf)
	r.h.inserted = append(r.h.inserted, RecordAddress{r.address, leaf})
	delete(r.h.reserved, r.key)
	if int64(len(sh.leafs)) >= r.h.max || now.Sub(sh.opened) >= r.h.age {
		r.h.seal(sh, now)
	}
	return nil
}
func (r *testReservation) Abort() error {
	r.h.mu.Lock()
	defer r.h.mu.Unlock()
	if !r.h.reserved[r.key] {
		return errors.New("reservation completed")
	}
	delete(r.h.reserved, r.key)
	sh := r.h.shards[r.key]
	if sh.active != nil && len(sh.leafs) == 0 {
		sh.active = nil
		sh.next--
	}
	return nil
}
func (h *testHMF) Reserve(rid, site, dev string, now time.Time) (Reservation, error) {
	sid, err := h.SelectShard(rid, site, dev)
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	key := merkle.TreeID{Type: merkle.TreeShard, RegionID: rid, ShardID: sid}
	if h.reserved[key] {
		return nil, errors.New("Shard busy")
	}
	sh := h.shards[key]
	if sh == nil {
		sh = &testShard{}
		h.shards[key] = sh
	}
	if sh.active != nil && now.Sub(sh.opened) >= h.age {
		h.seal(sh, now)
	}
	if sh.active == nil {
		sh.active = &Segment{ID: merkle.TreeID{Type: merkle.TreeSegment, RegionID: rid, ShardID: sid, SegmentID: sh.next}, OpenedAt: now, MaxLeaves: int(h.max)}
		sh.next++
		sh.opened = now
	}
	a := Address{RegionID: rid, ShardID: sid, SegmentID: sh.active.ID.SegmentID, LeafID: int64(len(sh.leafs))}
	h.reserved[key] = true
	return &testReservation{h: h, address: a, key: key}, nil
}
func (h *testHMF) SealExpired(now time.Time) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	for key, sh := range h.shards {
		if h.reserved[key] {
			continue
		}
		if sh.active != nil && now.Sub(sh.opened) >= h.age {
			h.seal(sh, now)
		}
	}
	return nil
}
func (h *testHMF) PendingSegments() []Segment {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]Segment(nil), h.pending...)
}
func (h *testHMF) PendingSegmentNodes(id merkle.TreeID) ([]merkle.MerkleNode, error) {
	return []merkle.MerkleNode{{Level: 0, Index: 0, Hash: sha256.Sum256(fmt.Append(nil, id))}}, nil
}
func (h *testHMF) AcknowledgeSegmentPersisted(id merkle.TreeID) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.persisted[id] = true
	return nil
}
func (h *testHMF) PrepareFinalization(epoch uint64) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.candidateEpoch != 0 {
		return nil
	}
	h.candidateEpoch = epoch
	h.candidate = append([]Segment(nil), h.pending...)
	return nil
}
func (h *testHMF) Commitment() ([32]byte, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return sha256.Sum256(fmt.Append(nil, h.candidateEpoch, h.candidate)), nil
}
func (h *testHMF) ValidateFinalization(epoch uint64) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.candidateEpoch != epoch {
		return errors.New("epoch mismatch")
	}
	for _, s := range h.candidate {
		if !h.persisted[s.ID] {
			return errors.New("not persisted")
		}
	}
	return nil
}
func (h *testHMF) CommitFinalization(epoch uint64) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.candidateEpoch != epoch {
		return errors.New("epoch mismatch")
	}
	for _, s := range h.candidate {
		if !h.persisted[s.ID] {
			return errors.New("not persisted")
		}
	}
	h.pending = h.pending[len(h.candidate):]
	h.finalized = epoch
	h.candidateEpoch = 0
	h.candidate = nil
	return nil
}

type testMVA struct {
	mu        sync.Mutex
	received  []Record
	prepared  []Record
	finalized uint64
}

func (v *testMVA) Ingest(r Record) (MVAUpdate, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.received = append(v.received, r)
	return MVAUpdate{}, nil
}
func (v *testMVA) Prepare(_ uint64, records []Record) ([32]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.prepared = append([]Record(nil), records...)
	return sha256.Sum256(fmt.Append(nil, records)), nil
}
func (v *testMVA) Promote(epoch uint64) error {
	v.mu.Lock()
	v.finalized = epoch
	v.mu.Unlock()
	return nil
}
func (v *testMVA) ValidateCandidate(uint64) error { return nil }

type tokenCall struct {
	region            string
	shard             int64
	site, device, typ string
}
type testHPBF struct {
	mu        sync.Mutex
	received  []tokenCall
	prepared  []Record
	finalized uint64
}

func (v *testHPBF) AddToken(region string, shard int64, site, device, typ string) (HPBFUpdate, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.received = append(v.received, tokenCall{region, shard, site, device, typ})
	return HPBFUpdate{RegionID: region, ShardID: shard}, nil
}
func (v *testHPBF) Prepare(_ uint64, records []Record) ([32]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.prepared = append([]Record(nil), records...)
	return sha256.Sum256(fmt.Append(nil, records)), nil
}
func (v *testHPBF) Promote(epoch uint64) error {
	v.mu.Lock()
	v.finalized = epoch
	v.mu.Unlock()
	return nil
}
func (v *testHPBF) ValidateCandidate(uint64) error { return nil }

type testEvidence struct {
	mu            sync.Mutex
	accepted      []Record
	sealed        []Segment
	candidates    []Candidate
	failSeal      bool
	failCandidate bool
	failAccepted  bool
}

func (e *testEvidence) PersistAccepted(_ context.Context, r Record, _ MVAUpdate, _ HPBFUpdate) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failAccepted {
		return errors.New("accepted log unavailable")
	}
	e.accepted = append(e.accepted, r)
	return nil
}
func (e *testEvidence) PersistSealed(_ context.Context, s Segment, _ []merkle.MerkleNode) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failSeal {
		return errors.New("disk unavailable")
	}
	e.sealed = append(e.sealed, s)
	return nil
}
func (e *testEvidence) PersistCandidate(_ context.Context, c Candidate) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.failCandidate {
		return errors.New("disk unavailable")
	}
	e.candidates = append(e.candidates, c)
	return nil
}

type testCheckpoints struct {
	mu    sync.Mutex
	roots map[uint64][32]byte
	fail  bool
}

func (s *testCheckpoints) Commit(_ context.Context, e uint64, r [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("anchor unavailable")
	}
	if old, ok := s.roots[e]; ok && old != r {
		return errors.New("conflicting checkpoint")
	}
	s.roots[e] = r
	return nil
}
func (s *testCheckpoints) GetCheckpoint(_ context.Context, e uint64) ([32]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.roots[e]
	if !ok {
		return r, errors.New("not found")
	}
	return r, nil
}

type rig struct {
	manager *Manager
	h       *testHMF
	v       *testMVA
	b       *testHPBF
	e       *testEvidence
	c       *testCheckpoints
}

func newRig(t *testing.T, max int64) *rig {
	t.Helper()
	r := &rig{h: newTestHMF(max, time.Hour), v: &testMVA{}, b: &testHPBF{}, e: &testEvidence{}, c: &testCheckpoints{roots: map[uint64][32]byte{}}}
	var err error
	r.manager, err = New(Options{HMF: r.h, MVA: r.v, HPBF: r.b, Encryptor: testEncrypt{}, Locator: testLocator{}, Evidence: r.e, Checkpoints: r.c, IDs: &testIDs{}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func input(device string) Input {
	return Input{RegionID: "r0", SiteID: "site", DeviceID: device, Type: "alarm", TS: time.Unix(100, 0), Plaintext: []byte(device)}
}

func TestIngestBindsSameAddressAcrossStructures(t *testing.T) {
	r := newRig(t, 2)
	ctx := context.Background()
	now := time.Unix(200, 0)
	a, err := r.manager.Ingest(ctx, input("a"), now)
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.manager.Ingest(ctx, input("a"), now)
	if err != nil {
		t.Fatal(err)
	}
	if a.Address.ShardID != b.Address.ShardID || a.Address.LeafID != 0 || b.Address.LeafID != 1 {
		t.Fatalf("unstable positions: %+v %+v", a, b)
	}
	if len(r.v.received) != 2 || len(r.b.received) != 2 || len(r.e.accepted) != 2 || r.v.received[0].Address != a.Address || r.h.inserted[0].Address != a.Address {
		t.Fatal("structures received different records or addresses")
	}
	if r.b.received[0] != (tokenCall{"r0", a.Address.ShardID, "site", "a", "alarm"}) {
		t.Fatalf("wrong HPBF token inputs: %+v", r.b.received[0])
	}
	want, err := (testLocator{}).CommitLocator(a.LogID, r.v.received[0].Descriptor, a.Address)
	if err != nil || want != a.Locator {
		t.Fatal("locator did not bind address")
	}
	wantLeaf, err := logLeaf(a.LogID, a.Locator, r.v.received[0].Log.Digest)
	if err != nil || wantLeaf != a.HMFLeaf || wantLeaf != r.h.inserted[0].Leaf {
		t.Fatal("HMF leaf mismatch")
	}
	if len(r.manager.PendingSegments()) != 1 || !r.h.persisted[r.manager.PendingSegments()[0].ID] {
		t.Fatal("sealed segment not persisted and acknowledged")
	}
	other := input("a")
	other.RegionID = "r1"
	regionReceipt, err := r.manager.Ingest(ctx, other, now)
	if err != nil || regionReceipt.Address.RegionID != "r1" {
		t.Fatalf("region-scoped placement failed: %v", err)
	}
	for i := 0; i < 30; i++ {
		sid, err := r.h.SelectShard("r0", "site", fmt.Sprint(i))
		if err != nil {
			t.Fatal(err)
		}
		again, _ := r.h.SelectShard("r0", "site", fmt.Sprint(i))
		if sid != again {
			t.Fatal("unstable placement")
		}
	}
	if _, err := r.h.SelectShard("missing", "site", "a"); err == nil {
		t.Fatal("unknown region accepted")
	}
}

func TestCandidateSealedOnlyAndCheckpointRetry(t *testing.T) {
	r := newRig(t, 2)
	ctx := context.Background()
	now := time.Unix(200, 0)
	for i := 0; i < 2; i++ {
		if _, err := r.manager.Ingest(ctx, input("a"), now); err != nil {
			t.Fatal(err)
		}
	}
	c, err := r.manager.PrepareFinalization(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Records) != 2 || len(c.Segments) != 1 {
		t.Fatalf("wrong candidate: %+v", c)
	}
	if len(r.v.prepared) != 2 || len(r.b.prepared) != 2 {
		t.Fatal("MVA and HPBF did not prepare the same sealed set")
	}
	if want, _ := checkpointHash(1, c.Roots); c.Checkpoint != want {
		t.Fatal("checkpoint hash mismatch")
	}
	for i := 0; i < 2; i++ {
		if _, err := r.manager.Ingest(ctx, input("a"), now); err != nil {
			t.Fatal(err)
		}
	}
	retry, err := r.manager.PrepareFinalization(ctx, 1)
	if err != nil || retry.Checkpoint != c.Checkpoint || len(retry.Records) != 2 {
		t.Fatal("candidate changed after later seal")
	}
	if len(r.manager.PendingSegments()) != 2 {
		t.Fatal("following epoch segment missing")
	}
	r.c.fail = true
	if _, err := r.manager.CommitFinalization(ctx, 1); err == nil {
		t.Fatal("failed checkpoint promoted")
	}
	if epoch, _ := r.manager.Finalized(); epoch != 0 || r.h.finalized != 0 || r.v.finalized != 0 || r.b.finalized != 0 {
		t.Fatal("partial promotion")
	}
	r.c.fail = false
	if _, err := r.manager.CommitFinalization(ctx, 2); err == nil {
		t.Fatal("mismatched epoch promoted")
	}
	if got, err := r.manager.CommitFinalization(ctx, 1); err != nil || got != c.Checkpoint {
		t.Fatalf("retry: %v", err)
	}
	if epoch, _ := r.manager.Finalized(); epoch != 1 || r.h.finalized != 1 || r.v.finalized != 1 || r.b.finalized != 1 {
		t.Fatal("joint promotion failed")
	}
	if len(r.manager.PendingSegments()) != 1 {
		t.Fatal("later pending segment was cleared")
	}
	c2, err := r.manager.PrepareFinalization(ctx, 2)
	if err != nil || len(c2.Records) != 2 || c2.Checkpoint == c.Checkpoint {
		t.Fatalf("second candidate: %v", err)
	}
	if _, err := r.manager.CommitFinalization(ctx, 2); err != nil {
		t.Fatal(err)
	}
	old, err := r.c.GetCheckpoint(ctx, 1)
	if err != nil || old != c.Checkpoint {
		t.Fatal("historical checkpoint disappeared")
	}
}

func TestPersistenceFailureLeavesSegmentUnacknowledged(t *testing.T) {
	r := newRig(t, 1)
	r.e.failSeal = true
	_, err := r.manager.Ingest(context.Background(), input("a"), time.Unix(200, 0))
	if err == nil {
		t.Fatal("expected persistence failure")
	}
	segment := r.manager.PendingSegments()[0]
	if r.h.persisted[segment.ID] {
		t.Fatal("failed evidence acknowledged")
	}
	r.e.failSeal = false
	if _, err := r.manager.PrepareFinalization(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if !r.h.persisted[segment.ID] {
		t.Fatal("retry did not persist segment")
	}
}

func TestConcurrentIngestionHasUniquePhysicalPositions(t *testing.T) {
	r := newRig(t, 100)
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	positions := make(chan Address, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			receipt, err := r.manager.Ingest(context.Background(), input("a"), time.Unix(200, 0))
			if err != nil {
				errs <- err
				return
			}
			positions <- receipt.Address
		}()
	}
	wg.Wait()
	close(errs)
	close(positions)
	for err := range errs {
		t.Fatal(err)
	}
	seen := map[Address]bool{}
	for a := range positions {
		if seen[a] {
			t.Fatalf("duplicate position %+v", a)
		}
		seen[a] = true
	}
	if len(seen) != 40 {
		t.Fatalf("got %d positions", len(seen))
	}
}

func TestExpiredSegmentPersistsWhenNextInsertOpensNewSegment(t *testing.T) {
	r := newRig(t, 10)
	ctx := context.Background()
	start := time.Unix(200, 0)
	first, err := r.manager.Ingest(ctx, input("a"), start)
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.manager.Ingest(ctx, input("a"), start.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if first.Address.SegmentID == second.Address.SegmentID {
		t.Fatal("expired segment received another log")
	}
	segments := r.manager.PendingSegments()
	if len(segments) != 1 || !r.h.persisted[segments[0].ID] {
		t.Fatal("expired segment was not persisted")
	}
	c, err := r.manager.PrepareFinalization(ctx, 1)
	if err != nil || len(c.Records) != 1 || c.Records[0].Log.LogID != first.LogID {
		t.Fatalf("active record entered candidate: %v", err)
	}
}

func TestCandidateEvidenceFailureIsRetryable(t *testing.T) {
	r := newRig(t, 1)
	ctx := context.Background()
	if _, err := r.manager.Ingest(ctx, input("a"), time.Unix(200, 0)); err != nil {
		t.Fatal(err)
	}
	r.e.failCandidate = true
	if _, err := r.manager.PrepareFinalization(ctx, 1); err == nil {
		t.Fatal("candidate persisted despite failure")
	}
	if _, ok := r.manager.Prepared(); ok {
		t.Fatal("failed candidate exposed as prepared")
	}
	if _, err := r.manager.CommitFinalization(ctx, 1); err == nil {
		t.Fatal("failed evidence allowed checkpoint")
	}
	r.e.failCandidate = false
	c, err := r.manager.PrepareFinalization(ctx, 1)
	if err != nil || len(c.Records) != 1 {
		t.Fatalf("candidate retry failed: %v", err)
	}
}

type failingHPBF struct{ testHPBF }

func (*failingHPBF) AddToken(string, int64, string, string, string) (HPBFUpdate, error) {
	return HPBFUpdate{}, errors.New("filter unavailable")
}

func TestPartialWorkingUpdateCannotFinalize(t *testing.T) {
	r := newRig(t, 1)
	r.manager.opts.HPBF = &failingHPBF{}
	if _, err := r.manager.Ingest(context.Background(), input("a"), time.Unix(200, 0)); err == nil {
		t.Fatal("expected HPBF update failure")
	}
	if _, err := r.manager.PrepareFinalization(context.Background(), 1); !errors.Is(err, ErrIncompleteWorkingState) {
		t.Fatalf("partial working state finalized: %v", err)
	}
}

func TestDuplicateLogIDRejectedBeforeAuthenticatedUpdates(t *testing.T) {
	r := newRig(t, 3)
	r.manager.opts.IDs = fixedIDs{id: uuid.UUID{1}}
	ctx := context.Background()
	if _, err := r.manager.Ingest(ctx, input("a"), time.Unix(200, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.manager.Ingest(ctx, input("a"), time.Unix(200, 0)); err == nil {
		t.Fatal("duplicate LogID accepted")
	}
	if len(r.v.received) != 1 || len(r.b.received) != 1 || len(r.h.inserted) != 1 {
		t.Fatal("duplicate reached authenticated structures")
	}
}

type blockingCheckpoint struct {
	*testCheckpoints
	entered chan struct{}
	release chan struct{}
}

func (s *blockingCheckpoint) Commit(ctx context.Context, epoch uint64, root [32]byte) error {
	close(s.entered)
	select {
	case <-s.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	return s.testCheckpoints.Commit(ctx, epoch, root)
}

func TestIngestionContinuesDuringCheckpointCommit(t *testing.T) {
	r := newRig(t, 1)
	ctx := context.Background()
	if _, err := r.manager.Ingest(ctx, input("a"), time.Unix(200, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.manager.PrepareFinalization(ctx, 1); err != nil {
		t.Fatal(err)
	}
	block := &blockingCheckpoint{testCheckpoints: r.c, entered: make(chan struct{}), release: make(chan struct{})}
	r.manager.opts.Checkpoints = block
	finished := make(chan error, 1)
	go func() { _, err := r.manager.CommitFinalization(ctx, 1); finished <- err }()
	select {
	case <-block.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("checkpoint not entered")
	}
	ingested := make(chan error, 1)
	go func() { _, err := r.manager.Ingest(ctx, input("a"), time.Unix(200, 0)); ingested <- err }()
	select {
	case err := <-ingested:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ingestion blocked by checkpoint wait")
	}
	close(block.release)
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if len(r.manager.PendingSegments()) != 1 {
		t.Fatal("new segment was cleared with old candidate")
	}
}

func TestConcreteAdaptersCoordinateSealedCandidates(t *testing.T) {
	h, err := hmf.NewHMF(1, 2, 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	v, err := mva.NewMVA(1, 3)
	if err != nil {
		t.Fatal(err)
	}
	b, err := hpbf.NewHPBF(1, 2, 100, 0.00001)
	if err != nil {
		t.Fatal(err)
	}
	evidence := &testEvidence{}
	checkpoints := &testCheckpoints{roots: map[uint64][32]byte{}}
	manager, err := New(Options{HMF: &HMFAdapter{Tree: h}, MVA: &MVAAdapter{Tree: v},
		HPBF: &HPBFAdapter{Tree: b}, Encryptor: testEncrypt{}, Locator: CanonicalLocator{},
		Evidence: evidence, Checkpoints: checkpoints, IDs: &testIDs{}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Unix(200, 0)
	firstInput := input("device")
	firstInput.RegionID = "0"
	initialRoot, _ := h.FinalizedRoot()
	first, err := manager.Ingest(ctx, firstInput, now)
	if err != nil {
		t.Fatal(err)
	}
	if first.Address.RegionID != "0" || first.Address.LeafID != 0 || len(evidence.accepted) != 1 || len(evidence.sealed) != 1 {
		t.Fatal("concrete adapters did not persist one bound and sealed record")
	}
	sealed := evidence.sealed[0]
	if sealed.ID.SegmentID != first.Address.SegmentID || sealed.Root == ([32]byte{}) ||
		sealed.OpenedAt != now || sealed.SealedAt != now || sealed.MaxLeaves != 1 {
		t.Fatalf("HMF adapter returned incomplete Segment metadata: %+v", sealed)
	}
	if evidence.accepted[0].Address != first.Address || evidence.accepted[0].Locator != first.Locator ||
		evidence.accepted[0].HMFLeaf != first.HMFLeaf || v.Regions[0].IDView.LeafCount != 1 {
		t.Fatal("MVA, HMF, and persistence received different records")
	}
	candidate, err := manager.PrepareFinalization(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidate.Records) != 1 || candidate.Records[0].Address != first.Address ||
		v.Candidate == nil || b.Candidate == nil || h.Candidate == nil ||
		candidate.Roots.MVA != v.Candidate.Root || candidate.Roots.HPBF != b.Candidate.Global.RootHash {
		t.Fatal("concrete components did not prepare the same sealed record")
	}
	if root, _ := h.FinalizedRoot(); root != initialRoot || v.Finalized != nil || b.Finalized.Epoch != 0 {
		t.Fatal("preparation published a candidate")
	}
	secondInput := firstInput
	secondInput.TS = now.Add(time.Second)
	second, err := manager.Ingest(ctx, secondInput, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if second.Address.SegmentID != first.Address.SegmentID+1 {
		t.Fatal("next log did not use a new Segment")
	}
	if retry, err := manager.PrepareFinalization(ctx, 1); err != nil || retry.Checkpoint != candidate.Checkpoint || len(retry.Records) != 1 {
		t.Fatalf("later log entered prepared candidate: %v", err)
	}
	checkpoints.fail = true
	if _, err := manager.CommitFinalization(ctx, 1); err == nil {
		t.Fatal("failed checkpoint promoted")
	}
	if epoch, _ := manager.Finalized(); epoch != 0 || v.Finalized != nil || b.Finalized.Epoch != 0 {
		t.Fatal("checkpoint failure advanced a component")
	}
	checkpoints.fail = false
	if _, err := manager.CommitFinalization(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if epoch, roots := manager.Finalized(); epoch != 1 || roots != candidate.Roots ||
		v.Finalized.Epoch != 1 || b.Finalized.Epoch != 1 || v.Finalized.Regions["0"].IDView.LeafCount != 1 {
		t.Fatal("promotion did not publish the same epoch across components")
	}
	if pending := manager.PendingSegments(); len(pending) != 1 || pending[0].ID.SegmentID != second.Address.SegmentID {
		t.Fatal("promotion cleared a Segment sealed after preparation")
	}
	next, err := manager.PrepareFinalization(ctx, 2)
	if err != nil || len(next.Records) != 1 || next.Records[0].Address != second.Address ||
		v.Candidate.Regions["0"].IDView.LeafCount != 2 {
		t.Fatalf("next candidate is not cumulative: %v", err)
	}
}

type unavailableEncryptor struct{}

func (unavailableEncryptor) Encrypt(context.Context, uuid.UUID, Descriptor, []byte) (Encrypted, error) {
	return Encrypted{}, errors.New("encryption unavailable")
}

type unavailableLocator struct{}

func (unavailableLocator) CommitLocator(uuid.UUID, Descriptor, Address) ([32]byte, error) {
	return [32]byte{}, errors.New("locator unavailable")
}

func TestMPMEarlyFailureAbortsAddressReservation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*rig)
	}{
		{name: "encryption", setup: func(r *rig) { r.manager.opts.Encryptor = unavailableEncryptor{} }},
		{name: "locator", setup: func(r *rig) { r.manager.opts.Locator = unavailableLocator{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, 2)
			tc.setup(r)
			if _, err := r.manager.Ingest(context.Background(), input("device"), time.Unix(200, 0)); err == nil {
				t.Fatal("expected failure")
			}
			if len(r.h.reserved) != 0 || len(r.h.inserted) != 0 || len(r.v.received) != 0 || len(r.b.received) != 0 || len(r.e.accepted) != 0 {
				t.Fatal("early failure left a reservation or authenticated update")
			}
			if err := r.manager.workingError(); err != nil {
				t.Fatalf("recoverable failure poisoned manager: %v", err)
			}
			r.manager.opts.Encryptor = testEncrypt{}
			r.manager.opts.Locator = testLocator{}
			receipt, err := r.manager.Ingest(context.Background(), input("device"), time.Unix(200, 0))
			if err != nil || receipt.Address.SegmentID != 0 || receipt.Address.LeafID != 0 {
				t.Fatalf("position not reusable: %+v, %v", receipt.Address, err)
			}
		})
	}
}

type unavailableMVA struct{ *testMVA }

func (*unavailableMVA) Ingest(Record) (MVAUpdate, error) {
	return MVAUpdate{}, errors.New("MVA unavailable")
}

type unavailableCommitReservation struct{ Reservation }

func (unavailableCommitReservation) Commit([32]byte, time.Time) error {
	return errors.New("HMF append unavailable")
}

type unavailableCommitHMF struct{ *testHMF }

func (h *unavailableCommitHMF) Reserve(rid, site, device string, now time.Time) (Reservation, error) {
	r, err := h.testHMF.Reserve(rid, site, device, now)
	if err != nil {
		return nil, err
	}
	return unavailableCommitReservation{Reservation: r}, nil
}

func TestMPMPartialFailuresBlockFinalization(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*rig)
	}{
		{name: "MVA update", setup: func(r *rig) { r.manager.opts.MVA = &unavailableMVA{testMVA: r.v} }},
		{name: "HMF commit", setup: func(r *rig) { r.manager.opts.HMF = &unavailableCommitHMF{testHMF: r.h} }},
		{name: "accepted evidence", setup: func(r *rig) { r.e.failAccepted = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, 1)
			tc.setup(r)
			if _, err := r.manager.Ingest(context.Background(), input("device"), time.Unix(200, 0)); err == nil {
				t.Fatal("expected partial failure")
			}
			if _, err := r.manager.PrepareFinalization(context.Background(), 1); !errors.Is(err, ErrIncompleteWorkingState) {
				t.Fatalf("partial state became a candidate: %v", err)
			}
			if len(r.c.roots) != 0 {
				t.Fatal("partial state reached checkpoint store")
			}
		})
	}
}

type driftingMVA struct {
	*testMVA
	drift bool
}

func (v *driftingMVA) Prepare(epoch uint64, records []Record) ([32]byte, error) {
	if v.drift {
		return [32]byte{99}, nil
	}
	return v.testMVA.Prepare(epoch, records)
}

func TestMPMRejectsChangedRootBeforeCheckpoint(t *testing.T) {
	r := newRig(t, 1)
	v := &driftingMVA{testMVA: r.v}
	r.manager.opts.MVA = v
	ctx := context.Background()
	if _, err := r.manager.Ingest(ctx, input("device"), time.Unix(200, 0)); err != nil {
		t.Fatal(err)
	}
	if _, err := r.manager.PrepareFinalization(ctx, 1); err != nil {
		t.Fatal(err)
	}
	v.drift = true
	if _, err := r.manager.CommitFinalization(ctx, 1); err == nil {
		t.Fatal("changed candidate root was anchored")
	}
	if len(r.c.roots) != 0 || r.h.finalized != 0 || r.v.finalized != 0 || r.b.finalized != 0 {
		t.Fatal("changed root advanced checkpoint or component")
	}
}

func TestMPMRejectsInvalidInputBeforeAllocation(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("missing dependencies accepted")
	}
	r := newRig(t, 2)
	bad := input("device")
	bad.SiteID = ""
	if _, err := r.manager.Ingest(context.Background(), bad, time.Unix(200, 0)); err == nil {
		t.Fatal("missing Site accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.manager.Ingest(ctx, input("device"), time.Unix(200, 0)); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context: %v", err)
	}
	if len(r.h.shards) != 0 || len(r.v.received) != 0 || len(r.b.received) != 0 {
		t.Fatal("invalid input allocated an address")
	}
}

func TestMPMEmptyPendingEpochDoesNotIncludeActiveLog(t *testing.T) {
	r := newRig(t, 3)
	ctx := context.Background()
	receipt, err := r.manager.Ingest(ctx, input("device"), time.Unix(200, 0))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.manager.PendingSegments()) != 0 {
		t.Fatal("active Segment entered pending")
	}
	candidate, err := r.manager.PrepareFinalization(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidate.Records) != 0 || len(candidate.Segments) != 0 || len(r.v.prepared) != 0 || len(r.b.prepared) != 0 {
		t.Fatal("active record entered empty pending candidate")
	}
	if _, err := r.manager.CommitFinalization(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if epoch, _ := r.manager.Finalized(); epoch != 1 {
		t.Fatal("empty epoch did not finalize")
	}
	if len(r.h.inserted) != 1 || r.h.inserted[0].Address != receipt.Address || len(r.manager.PendingSegments()) != 0 {
		t.Fatal("empty epoch discarded or sealed the active Segment")
	}
}
