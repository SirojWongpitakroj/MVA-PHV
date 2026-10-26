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
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
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
}
type RecordAddress struct {
	Address Address
	Leaf    [32]byte
}

func newTestHMF(max int64, age time.Duration) *testHMF {
	return &testHMF{shards: map[merkle.TreeID]*testShard{}, persisted: map[merkle.TreeID]bool{}, max: max, age: age}
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
func (h *testHMF) Insert(rid, site, dev string, now time.Time, build func(Address) ([32]byte, error)) (Address, error) {
	sid, err := h.SelectShard(rid, site, dev)
	if err != nil {
		return Address{}, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	key := merkle.TreeID{Type: merkle.TreeShard, RegionID: rid, ShardID: sid}
	sh := h.shards[key]
	if sh == nil {
		sh = &testShard{}
		h.shards[key] = sh
	}
	if sh.active != nil && now.Sub(sh.opened) >= h.age {
		h.seal(sh, now)
	}
	if sh.active == nil {
		sh.active = &Segment{ID: merkle.TreeID{Type: merkle.TreeSegment, RegionID: rid, ShardID: sid, SegmentID: sh.next}}
		sh.next++
		sh.opened = now
	}
	a := Address{RegionID: rid, ShardID: sid, SegmentID: sh.active.ID.SegmentID, LeafID: int64(len(sh.leafs))}
	leaf, err := build(a)
	if err != nil {
		return Address{}, err
	}
	sh.leafs = append(sh.leafs, leaf)
	h.inserted = append(h.inserted, RecordAddress{a, leaf})
	if int64(len(sh.leafs)) >= h.max {
		h.seal(sh, now)
	}
	return a, nil
}
func (h *testHMF) SealExpired(now time.Time) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, sh := range h.shards {
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
func (v *testMVA) Promote(epoch uint64) { v.mu.Lock(); v.finalized = epoch; v.mu.Unlock() }

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
func (v *testHPBF) Promote(epoch uint64) { v.mu.Lock(); v.finalized = epoch; v.mu.Unlock() }

type testEvidence struct {
	mu            sync.Mutex
	accepted      []Record
	sealed        []Segment
	candidates    []Candidate
	failSeal      bool
	failCandidate bool
}

func (e *testEvidence) PersistAccepted(_ context.Context, r Record, _ MVAUpdate, _ HPBFUpdate) error {
	e.mu.Lock()
	defer e.mu.Unlock()
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
