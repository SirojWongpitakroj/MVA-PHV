package phv

import (
	"context"
	"time"
	"uuid"

	"github.com/SirojWongpitakroj/mva-phv/internal/hpbf"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
	"github.com/SirojWongpitakroj/mva-phv/internal/mpm"
	"github.com/SirojWongpitakroj/mva-phv/internal/mva"
)

// NodeKey identifies a position, not a hash. Equal hashes at different
// positions are distinct evidence.
type NodeKey struct {
	Tree  merkle.TreeID
	Level int
	Index int64
}

type Node struct {
	Key          NodeKey
	Hash         [32]byte
	VersionEpoch uint64 // zero for immutable Segment nodes
}

type SelectedRecord struct {
	LogID      uuid.UUID
	Descriptor mpm.Descriptor
	// For a Log-ID query the ID view authenticates the address and locator;
	// the descriptor is recovered from CP associated data and checked against the locator.
	DescriptorFromLog bool
	Address           mpm.Address
	Locator           [32]byte
}

type EncryptedRecord struct {
	SelectedRecord
	Ciphertext []byte
	Nonce      []byte
	Tag        []byte
	AD         []byte
	Version    uint16   // CP encryption format, checked before proof assembly.
	Digest     [32]byte // derived from CP bytes by PHV, never trusted from CP
	HMFLeaf    [32]byte // derived from Digest and authenticated MVA metadata
}

type Request struct {
	Epoch      uint64
	Query      mva.LocatorQuery
	Tokens     [3][]byte
	UsePruning bool
}

type Resolution struct {
	Epoch   uint64
	Records []SelectedRecord
	Proof   *mva.MVAProof
}

// TrustedRoots must return roots from an already finalized checkpoint. The
// Cassandra evidence store must not implement this interface by itself.
type TrustedRoots interface {
	Roots(ctx context.Context, epoch uint64) (mpm.Roots, error)
}

// Pruner authenticates every excluded partition against the selected HPBF
// root before returning its candidates. A nil Pruner means no pruning.
type Pruner interface {
	Prune(ctx context.Context, epoch uint64, tokens [3][]byte, root [32]byte) (Pruning, error)
}

type Pruning struct {
	Regions []merkle.TreeID
	Shards  []merkle.TreeID
	Proof   *hpbf.HPBFProof
}

// Resolver authenticates query membership and completeness against root.
// It must never derive membership by scanning the log repository.
type Resolver interface {
	Resolve(ctx context.Context, epoch uint64, query mva.LocatorQuery, regions []merkle.TreeID, root [32]byte) (Resolution, error)
}

// Repository reads only internal CLS authentication evidence. Ciphertext comes
// through the independent external Cloud Provider reader.
type Repository interface {
	LeafCount(ctx context.Context, epoch uint64, tree merkle.TreeID) (int64, error)
	FetchNodes(ctx context.Context, epoch uint64, tree merkle.TreeID, positions []NodeKey) ([]Node, error)
}

// PartitionMapper optionally exposes opaque physical retrieval groups. PHV
// uses only identity equality; the repository owns the storage layout.
type PartitionMapper interface{ NodePartition(NodeKey) (string, error) }

type TreePlan struct {
	Tree      merkle.TreeID
	LeafCount int64
	Selected  []int64
	Frontier  []NodeKey
}

type RetrievalGroup struct {
	Tree      merkle.TreeID
	Partition string
	Positions []NodeKey
	Leaves    []int64 // selected Segment leaves for proof planning; CP is fetched by LogID
}

type Plan struct {
	Epoch         uint64
	Topology      Topology
	Selected      []SelectedRecord
	Trees         []TreePlan // Segment, Shard, Region, then Global
	Groups        []RetrievalGroup
	NaiveNodes    int
	UniqueNodes   int
	SegmentGroups int
}

type Metrics struct {
	SelectedRecords         int
	NaiveNodes              int
	UniqueNodes             int
	DeduplicatedNodes       int
	DeduplicationRatio      float64
	NaiveNodeBytes          int64
	FrontierNodeBytes       int64
	NaiveHashOperations     int
	HashOperations          int
	SegmentGroups           int
	ShardGroups             int
	RegionGroups            int
	GlobalGroups            int
	RetrievalGroups         int
	RepositoryCalls         int
	EvidenceBytes           int64
	ProofBytes              int64
	StoragePartitions       int
	MaxConcurrent           int
	HPBFPruningTime         time.Duration
	MVAResolutionTime       time.Duration
	MVAProofBytes           int64
	PlanningTime            time.Duration
	RetrievalTime           time.Duration
	CLSRetrievalTime        time.Duration
	CiphertextRetrievalTime time.Duration
	AssemblyTime            time.Duration
	VerificationTime        time.Duration
	TotalTime               time.Duration
	LocalizationBranches    int
	LocalizationExpanded    int
	PrunedBranches          int
	LocalizationTime        time.Duration
}

type Proof struct {
	Epoch         uint64
	Topology      Topology
	Roots         mpm.Roots
	Query         mva.LocatorQuery
	Tokens        [3][]byte
	Selected      []SelectedRecord
	MVA           *mva.MVAProof
	HPBF          *hpbf.HPBFProof
	PrunedRegions []merkle.TreeID
	PrunedShards  []merkle.TreeID
	Trees         []TreePlan
	Nodes         []Node
	Logs          []EncryptedRecord
	Root          [32]byte
}

type Failure struct {
	Tree       merkle.TreeID
	Index      int64
	LogID      uuid.UUID
	Unresolved bool
	Reason     string
}

type Result struct {
	Proof             Proof
	Verified          bool
	Failures          []Failure
	Metrics           Metrics
	IntegrityError    error
	LocalizationError error
	Unresolved        bool
}
