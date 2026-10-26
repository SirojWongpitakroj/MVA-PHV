package mpm

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"time"
	"uuid"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

var ErrIncompleteWorkingState = errors.New("MPM working state is incomplete and cannot be finalized")

type randomIDs struct{}

func (randomIDs) NewID() (uuid.UUID, error) {
	var id uuid.UUID
	if _, err := rand.Read(id[:]); err != nil {
		return id, err
	}
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return id, nil
}

func formatID(id int64) string { return strconv.FormatInt(id, 10) }

func logLeaf(id uuid.UUID, locator, digest [32]byte) ([32]byte, error) {
	encoded, err := domain.Serialize([]byte("LOG"), id, locator[:], digest[:])
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

func checkpointHash(epoch uint64, roots Roots) ([32]byte, error) {
	encoded, err := domain.Serialize([]byte("CHECKPOINT"), epoch, roots.MVA[:], roots.HMF[:], roots.HPBF[:])
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

// Manager owns the joint lifecycle. The gate gives preparation a stable set of
// accepted records; separate shard locks permit ingestion into different shards.
type Manager struct {
	opts              Options
	gate              sync.RWMutex
	finalize          sync.Mutex
	mu                sync.Mutex
	shardLocks        map[merkle.TreeID]*sync.Mutex
	seenIDs           map[uuid.UUID]struct{}
	records           map[merkle.TreeID][]Record
	persisted         map[merkle.TreeID]struct{}
	candidate         *Candidate
	candidatePrepared bool
	finalizedEpoch    uint64
	finalizedRoots    Roots
	poison            error
}

// MPM is the public name of the MVA-PHV manager.
type MPM = Manager

func NewMPM(options Options) (*MPM, error) { return New(options) }

func New(options Options) (*Manager, error) {
	if options.HMF == nil || options.MVA == nil || options.HPBF == nil || options.Encryptor == nil ||
		options.Locator == nil || options.Evidence == nil || options.Checkpoints == nil {
		return nil, fmt.Errorf("new MPM: HMF, MVA, HPBF, encryptor, locator, evidence, and checkpoint store are required")
	}
	if options.IDs == nil {
		options.IDs = randomIDs{}
	}
	return &Manager{opts: options, shardLocks: make(map[merkle.TreeID]*sync.Mutex),
		seenIDs: make(map[uuid.UUID]struct{}), records: make(map[merkle.TreeID][]Record),
		persisted: make(map[merkle.TreeID]struct{}), finalizedEpoch: options.InitialEpoch,
		finalizedRoots: options.InitialRoots}, nil
}

func (m *Manager) lockForShard(rid string, sid int64) *sync.Mutex {
	id := merkle.TreeID{Type: merkle.TreeShard, RegionID: rid, ShardID: sid}
	m.mu.Lock()
	defer m.mu.Unlock()
	lock := m.shardLocks[id]
	if lock == nil {
		lock = new(sync.Mutex)
		m.shardLocks[id] = lock
	}
	return lock
}

func (m *Manager) markIncomplete(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.poison == nil {
		m.poison = fmt.Errorf("%w: %v", ErrIncompleteWorkingState, err)
	}
}

func (m *Manager) workingError() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.poison
}

func (m *Manager) Ingest(ctx context.Context, input Input, now time.Time) (Receipt, error) {
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	if input.RegionID == "" || input.SiteID == "" || input.DeviceID == "" || input.Type == "" || input.TS.IsZero() {
		return Receipt{}, fmt.Errorf("ingest MPM: region, site, device, type, and timestamp are required")
	}
	if err := m.workingError(); err != nil {
		return Receipt{}, err
	}
	sid, err := m.opts.HMF.SelectShard(input.RegionID, input.SiteID, input.DeviceID)
	if err != nil {
		return Receipt{}, fmt.Errorf("ingest MPM: select shard: %w", err)
	}
	lock := m.lockForShard(input.RegionID, sid)
	m.gate.RLock()
	defer m.gate.RUnlock()
	lock.Lock()
	defer lock.Unlock()
	if err := m.workingError(); err != nil {
		return Receipt{}, err
	}
	id, err := m.opts.IDs.NewID()
	if err != nil {
		return Receipt{}, fmt.Errorf("ingest MPM: assign LogID: %w", err)
	}
	m.mu.Lock()
	_, duplicate := m.seenIDs[id]
	if !duplicate {
		m.seenIDs[id] = struct{}{}
	}
	m.mu.Unlock()
	if duplicate {
		return Receipt{}, fmt.Errorf("ingest MPM: duplicate LogID %s", id)
	}
	desc := Descriptor{RegionID: input.RegionID, SiteID: input.SiteID, DeviceID: input.DeviceID, Type: input.Type, TS: input.TS}
	encrypted, err := m.opts.Encryptor.Encrypt(ctx, id, desc, input.Plaintext)
	if err != nil {
		return Receipt{}, fmt.Errorf("ingest MPM: encrypt log: %w", err)
	}
	log := domain.Log{LogID: id, RegionID: input.RegionID, SiteID: input.SiteID, DevID: input.DeviceID,
		Type: input.Type, TS: input.TS, Ciphertext: encrypted.Ciphertext, Nonce: encrypted.Nonce,
		Tag: encrypted.Tag, AD: encrypted.AD, Digest: encrypted.Digest}
	var record Record
	var mvaUpdate MVAUpdate
	var hpbfUpdate HPBFUpdate
	enteredBuild := false
	address, err := m.opts.HMF.Insert(input.RegionID, input.SiteID, input.DeviceID, now, func(address Address) ([32]byte, error) {
		enteredBuild = true
		if address.RegionID != input.RegionID || address.ShardID != sid || address.SegmentID < 0 || address.LeafID < 0 {
			return [32]byte{}, fmt.Errorf("reserved HMF address does not match selected shard")
		}
		locator, err := m.opts.Locator.CommitLocator(id, desc, address)
		if err != nil {
			return [32]byte{}, fmt.Errorf("locator commitment: %w", err)
		}
		leaf, err := logLeaf(id, locator, encrypted.Digest)
		if err != nil {
			return [32]byte{}, fmt.Errorf("HMF leaf commitment: %w", err)
		}
		record = Record{Log: log, Descriptor: desc, Address: address, AcceptedAt: now, Locator: locator, HMFLeaf: leaf}
		mvaUpdate, err = m.opts.MVA.Ingest(record)
		if err != nil {
			return [32]byte{}, fmt.Errorf("MVA update: %w", err)
		}
		hpbfUpdate, err = m.opts.HPBF.AddToken(address.RegionID, address.ShardID, desc.SiteID, desc.DeviceID, desc.Type)
		if err != nil {
			return [32]byte{}, fmt.Errorf("HPBF update: %w", err)
		}
		return leaf, nil
	})
	if err != nil {
		if enteredBuild {
			m.markIncomplete(err)
		}
		return Receipt{}, fmt.Errorf("ingest MPM: HMF insert: %w", err)
	}
	if !enteredBuild || address != record.Address || address.ShardID != sid {
		err = fmt.Errorf("HMF did not append the reserved address")
		m.markIncomplete(err)
		return Receipt{}, fmt.Errorf("ingest MPM: %w", err)
	}
	if err = m.opts.Evidence.PersistAccepted(ctx, record, mvaUpdate, hpbfUpdate); err != nil {
		m.markIncomplete(err)
		return Receipt{LogID: id, Address: address, Locator: record.Locator, HMFLeaf: record.HMFLeaf}, fmt.Errorf("ingest MPM: persist accepted record: %w", err)
	}
	segID := merkle.TreeID{Type: merkle.TreeSegment, RegionID: address.RegionID, ShardID: address.ShardID, SegmentID: address.SegmentID}
	// Ciphertext is already durable. Pending preparation needs only the
	// descriptor, physical address, LogID, and commitments in memory.
	record.Log.Ciphertext = nil
	record.Log.Nonce = nil
	record.Log.Tag = nil
	record.Log.AD = nil
	m.mu.Lock()
	m.records[segID] = append(m.records[segID], record)
	m.mu.Unlock()
	shardID := merkle.TreeID{Type: merkle.TreeShard, RegionID: address.RegionID, ShardID: address.ShardID}
	if err := m.persistPending(ctx, &shardID); err != nil {
		return Receipt{LogID: id, Address: address, Locator: record.Locator, HMFLeaf: record.HMFLeaf}, err
	}
	return Receipt{LogID: id, Address: address, Locator: record.Locator, HMFLeaf: record.HMFLeaf}, nil
}

// persistPending is called while either the selected shard lock or the
// exclusive gate is held. A failed write leaves HMF's proof nodes unacknowledged.
func (m *Manager) persistPending(ctx context.Context, only *merkle.TreeID) error {
	for _, segment := range m.opts.HMF.PendingSegments() {
		if only != nil && (segment.ID.RegionID != only.RegionID || segment.ID.ShardID != only.ShardID) {
			continue
		}
		m.mu.Lock()
		_, done := m.persisted[segment.ID]
		records := slices.Clone(m.records[segment.ID])
		m.mu.Unlock()
		if done {
			continue
		}
		if segment.ID.Type != merkle.TreeSegment || segment.LeafCount <= 0 || int64(len(records)) != segment.LeafCount {
			return fmt.Errorf("persist MPM segment %v: %d records for %d leaves", segment.ID, len(records), segment.LeafCount)
		}
		for i, record := range records {
			if record.Address.LeafID != int64(i) {
				return fmt.Errorf("persist MPM segment %v: noncanonical leaf %d", segment.ID, i)
			}
		}
		nodes, err := m.opts.HMF.PendingSegmentNodes(segment.ID)
		if err != nil {
			return fmt.Errorf("persist MPM segment nodes %v: %w", segment.ID, err)
		}
		if err := m.opts.Evidence.PersistSealed(ctx, segment, nodes); err != nil {
			return fmt.Errorf("persist MPM sealed segment %v: %w", segment.ID, err)
		}
		if err := m.opts.HMF.AcknowledgeSegmentPersisted(segment.ID); err != nil {
			m.markIncomplete(err)
			return fmt.Errorf("acknowledge MPM segment %v: %w", segment.ID, err)
		}
		m.mu.Lock()
		m.persisted[segment.ID] = struct{}{}
		m.mu.Unlock()
	}
	return nil
}

func (m *Manager) SealExpired(ctx context.Context, now time.Time) error {
	m.gate.Lock()
	defer m.gate.Unlock()
	if err := m.workingError(); err != nil {
		return err
	}
	if err := m.opts.HMF.SealExpired(now); err != nil {
		return fmt.Errorf("seal MPM expired segments: %w", err)
	}
	return m.persistPending(ctx, nil)
}

func (m *Manager) PendingSegments() []Segment {
	m.gate.RLock()
	defer m.gate.RUnlock()
	return slices.Clone(m.opts.HMF.PendingSegments())
}

func copyCandidate(c Candidate) Candidate {
	c.Segments = slices.Clone(c.Segments)
	c.Records = slices.Clone(c.Records)
	for i := range c.Records {
		c.Records[i].Log.Ciphertext = slices.Clone(c.Records[i].Log.Ciphertext)
		c.Records[i].Log.Nonce = slices.Clone(c.Records[i].Log.Nonce)
		c.Records[i].Log.Tag = slices.Clone(c.Records[i].Log.Tag)
		c.Records[i].Log.AD = slices.Clone(c.Records[i].Log.AD)
	}
	return c
}

func (m *Manager) Prepared() (Candidate, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.candidate == nil {
		return Candidate{}, false
	}
	if !m.candidatePrepared {
		return Candidate{}, false
	}
	return copyCandidate(*m.candidate), true
}

func (m *Manager) Finalized() (uint64, Roots) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.finalizedEpoch, m.finalizedRoots
}

func (m *Manager) PrepareFinalization(ctx context.Context, epoch uint64) (Candidate, error) {
	m.finalize.Lock()
	defer m.finalize.Unlock()
	m.gate.Lock()
	defer m.gate.Unlock()
	if err := m.workingError(); err != nil {
		return Candidate{}, err
	}
	m.mu.Lock()
	if m.candidate != nil && m.candidate.Epoch != epoch {
		other := m.candidate.Epoch
		m.mu.Unlock()
		return Candidate{}, fmt.Errorf("prepare MPM: candidate epoch %d conflicts with %d", other, epoch)
	}
	if m.candidatePrepared {
		c := copyCandidate(*m.candidate)
		m.mu.Unlock()
		return c, nil
	}
	prior := m.candidate
	want := m.finalizedEpoch + 1
	m.mu.Unlock()
	if epoch != want {
		return Candidate{}, fmt.Errorf("prepare MPM: epoch %d, want %d", epoch, want)
	}
	if prior == nil {
		if err := m.persistPending(ctx, nil); err != nil {
			return Candidate{}, err
		}
	}
	segments := m.opts.HMF.PendingSegments()
	if prior != nil {
		segments = slices.Clone(prior.Segments)
	}
	// HMF owns canonical pending order. Each captured sealed segment contributes
	// exactly its persisted records; active segments have no entry here.
	var records []Record
	m.mu.Lock()
	if prior != nil {
		records = slices.Clone(prior.Records)
	}
	for _, segment := range segments {
		if prior != nil {
			break
		}
		if _, ok := m.persisted[segment.ID]; !ok {
			m.mu.Unlock()
			return Candidate{}, fmt.Errorf("prepare MPM: segment %v is not persisted", segment.ID)
		}
		part := m.records[segment.ID]
		if int64(len(part)) != segment.LeafCount {
			m.mu.Unlock()
			return Candidate{}, fmt.Errorf("prepare MPM: segment %v has incomplete records", segment.ID)
		}
		records = append(records, part...)
	}
	m.mu.Unlock()
	if prior == nil {
		records = copyCandidate(Candidate{Records: records}).Records
		m.mu.Lock()
		m.candidate = &Candidate{Epoch: epoch, Segments: slices.Clone(segments), Records: slices.Clone(records)}
		m.mu.Unlock()
	}
	if err := m.opts.HMF.PrepareFinalization(epoch); err != nil {
		return Candidate{}, fmt.Errorf("prepare MPM HMF: %w", err)
	}
	hmfRoot, err := m.opts.HMF.Commitment()
	if err != nil {
		return Candidate{}, fmt.Errorf("prepare MPM HMF root: %w", err)
	}
	mvaRoot, err := m.opts.MVA.Prepare(epoch, records)
	if err != nil {
		return Candidate{}, fmt.Errorf("prepare MPM MVA: %w", err)
	}
	hpbfRoot, err := m.opts.HPBF.Prepare(epoch, records)
	if err != nil {
		return Candidate{}, fmt.Errorf("prepare MPM HPBF: %w", err)
	}
	c := Candidate{Epoch: epoch, Roots: Roots{MVA: mvaRoot, HMF: hmfRoot, HPBF: hpbfRoot}, Segments: slices.Clone(segments), Records: slices.Clone(records)}
	c.Checkpoint, err = checkpointHash(epoch, c.Roots)
	if err != nil {
		return Candidate{}, fmt.Errorf("prepare MPM checkpoint: %w", err)
	}
	if err := m.opts.Evidence.PersistCandidate(ctx, copyCandidate(c)); err != nil {
		return Candidate{}, fmt.Errorf("prepare MPM evidence: %w", err)
	}
	m.mu.Lock()
	m.candidate = &c
	m.candidatePrepared = true
	m.mu.Unlock()
	return copyCandidate(c), nil
}

func (m *Manager) CommitFinalization(ctx context.Context, epoch uint64) ([32]byte, error) {
	m.finalize.Lock()
	defer m.finalize.Unlock()
	m.mu.Lock()
	c := m.candidate
	if c == nil || !m.candidatePrepared {
		m.mu.Unlock()
		return [32]byte{}, fmt.Errorf("commit MPM: no prepared candidate")
	}
	if c.Epoch != epoch {
		m.mu.Unlock()
		return [32]byte{}, fmt.Errorf("commit MPM: candidate epoch %d, got %d", c.Epoch, epoch)
	}
	checkpoint := c.Checkpoint
	m.mu.Unlock()
	if err := m.opts.Checkpoints.Commit(ctx, epoch, checkpoint); err != nil {
		// A timeout can mean that the checkpoint was stored but the reply was lost.
		stored, getErr := m.opts.Checkpoints.GetCheckpoint(ctx, epoch)
		if getErr != nil || stored != checkpoint {
			return [32]byte{}, fmt.Errorf("commit MPM checkpoint: %w", err)
		}
	}
	m.gate.Lock()
	defer m.gate.Unlock()
	if err := m.opts.HMF.CommitFinalization(epoch); err != nil {
		return [32]byte{}, fmt.Errorf("promote MPM HMF: %w", err)
	}
	// Port contracts require these two promotions to be infallible after prepare.
	m.opts.MVA.Promote(epoch)
	m.opts.HPBF.Promote(epoch)
	m.mu.Lock()
	for _, segment := range c.Segments {
		delete(m.records, segment.ID)
		delete(m.persisted, segment.ID)
	}
	for _, record := range c.Records {
		delete(m.seenIDs, record.Log.LogID)
	}
	m.finalizedEpoch = epoch
	m.finalizedRoots = c.Roots
	m.candidate = nil
	m.candidatePrepared = false
	m.mu.Unlock()
	return checkpoint, nil
}
