package mpm

import (
	"context"
	"time"
	"uuid"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
	"github.com/SirojWongpitakroj/mva-phv/internal/mva"
)

// Input is a plaintext record accepted by the manager. Encryption follows
// LogID assignment so the ciphertext's associated data can bind that ID.
type Input struct {
	RegionID  string
	SiteID    string
	DeviceID  string
	Type      string
	TS        time.Time
	Plaintext []byte
}

type Descriptor struct {
	RegionID string
	SiteID   string
	DeviceID string
	Type     string
	TS       time.Time
}

type Address struct {
	RegionID  string
	ShardID   int64
	SegmentID int64
	LeafID    int64
}

func (a Address) MVA() mva.PhysicalAddress {
	return mva.PhysicalAddress{
		RegionID:  a.RegionID,
		ShardID:   formatID(a.ShardID),
		SegmentID: formatID(a.SegmentID),
		LeafID:    formatID(a.LeafID),
	}
}

type Record struct {
	Log        domain.Log
	Descriptor Descriptor
	Address    Address
	AcceptedAt time.Time // HMF insertion time, distinct from the event timestamp.
	Locator    [32]byte  // c_i
	HMFLeaf    [32]byte  // d_i
}

// A nonzero Receipt may accompany a persistence error: the physical HMF
// append already happened, and callers must reconcile that LogID rather than
// submit the same record as a new ingestion.
type Receipt struct {
	LogID   uuid.UUID
	Address Address
	Locator [32]byte
	HMFLeaf [32]byte
}

// Segment carries the immutable sealed root plus recovery metadata needed by
// the evidence repository. HMF's adapter must capture OpenedAt before sealing.
type Segment struct {
	ID        merkle.TreeID
	Root      [32]byte
	LeafCount int64
	Height    int
	MaxLeaves int
	OpenedAt  time.Time
	SealedAt  time.Time
}

type MVAUpdate struct {
	IDView       mva.LocatorUpdate
	AttrView     mva.LocatorUpdate
	WorkingEpoch uint64
	TreeOrder    int // B+ Tree order needed to restore working pages.
}

// HPBFUpdate carries the changed working filter for restart persistence.
// The HPBF adapter, not MPM, constructs and serializes Bloom-filter bits.
type HPBFUpdate struct {
	RegionID     string
	ShardID      int64
	WorkingEpoch uint64
	BitCount     uint64
	HashCount    uint64
	Words        []uint64 // Snapshot after AddToken; adapters must copy it.
}

type Roots struct {
	MVA  [32]byte
	HMF  [32]byte
	HPBF [32]byte
}

type Candidate struct {
	Epoch      uint64
	Roots      Roots
	Checkpoint [32]byte
	Segments   []Segment
	Records    []Record
}

// HMF owns the address allocator. Insert must invoke build exactly once with a
// reserved stable address before appending the returned d_i. A build error
// must leave that address unused. This reservation API is not yet present on
// the concrete hmf.HMF and requires a small adapter/API addition later.
type HMF interface {
	SelectShard(rid, siteID, devID string) (int64, error)
	Insert(rid, siteID, devID string, now time.Time, build func(Address) ([32]byte, error)) (Address, error)
	SealExpired(now time.Time) error
	PendingSegments() []Segment
	PendingSegmentNodes(id merkle.TreeID) ([]merkle.MerkleNode, error)
	AcknowledgeSegmentPersisted(id merkle.TreeID) error
	PrepareFinalization(epoch uint64) error
	Commitment() ([32]byte, error)
	CommitFinalization(epoch uint64) error
}

// MVA and HPBF adapters must prepare from the supplied sealed records only,
// retain the candidate for same-epoch retry, and make Promote infallible for
// a successfully prepared epoch. Current concrete Commitment methods publish
// immediately, so they cannot satisfy this contract without staged APIs.
type MVA interface {
	// Ingest returns immutable changed-page snapshots for persistence.
	Ingest(record Record) (MVAUpdate, error)
	Prepare(epoch uint64, sealed []Record) ([32]byte, error)
	Promote(epoch uint64)
}

type HPBF interface {
	AddToken(regionID string, shardID int64, siteID, devID, typ string) (HPBFUpdate, error)
	Prepare(epoch uint64, sealed []Record) ([32]byte, error)
	Promote(epoch uint64)
}

type Encrypted struct {
	Ciphertext []byte
	Nonce      []byte
	Tag        []byte
	AD         []byte
	Digest     [32]byte
}

type Encryptor interface {
	Encrypt(ctx context.Context, id uuid.UUID, descriptor Descriptor, plaintext []byte) (Encrypted, error)
}

// LocatorCommitter supplies the canonical locator commitment formula. The
// repository has no such formula yet; MPM must not guess its hash preimage.
type LocatorCommitter interface {
	CommitLocator(id uuid.UUID, descriptor Descriptor, address Address) ([32]byte, error)
}

type EvidenceRepository interface {
	// PersistAccepted must durably store the encrypted log and working recovery
	// updates before MPM reports success. It must reject a LogID collision even
	// after process restart; MPM's in-memory set covers concurrent local calls.
	PersistAccepted(ctx context.Context, record Record, mva MVAUpdate, hpbf HPBFUpdate) error
	// PersistSealed is idempotent for the same immutable Segment and proof nodes.
	PersistSealed(ctx context.Context, segment Segment, nodes []merkle.MerkleNode) error
	// PersistCandidate stores authentication evidence before checkpoint commit.
	// Cassandra's adapter obtains changed upper HMF nodes, MVA manifests, and
	// HPBF partitions from its CandidateEvidenceSource. Current component APIs
	// do not yet expose all of these snapshots.
	PersistCandidate(ctx context.Context, candidate Candidate) error
}

// A real or mock implementation must be append-only: conflicting commits for
// one epoch fail, while an identical retry is safe and historical reads work.
type CheckpointStore interface {
	Commit(ctx context.Context, epoch uint64, checkpoint [32]byte) error
	GetCheckpoint(ctx context.Context, epoch uint64) ([32]byte, error)
}

type IDGenerator interface {
	NewID() (uuid.UUID, error)
}

type Options struct {
	HMF         HMF
	MVA         MVA
	HPBF        HPBF
	Encryptor   Encryptor
	Locator     LocatorCommitter
	Evidence    EvidenceRepository
	Checkpoints CheckpointStore
	IDs         IDGenerator // nil selects cryptographically random UUIDv4.
	// On restart these must come from the trusted checkpoint and match each
	// component's restored finalized state; MPM does not reconstruct it here.
	InitialEpoch uint64
	InitialRoots Roots
}
