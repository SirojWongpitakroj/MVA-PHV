package hmf

import (
	"sync"
	"time"

	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

type HMFConfig struct {
	RegionIDs          []string
	NumShardsPerRegion int
	MaxSegmentLeaves   int
}

type HMF struct {
	mu sync.RWMutex

	MaxSegmentSize int
	SealInterval   time.Duration
	Working        *HMFWorkingState
	Candidate      *HMFState
	Finalized      *HMFState

	regionIDs        []string
	activeShards     map[merkle.TreeID]struct{}
	reservations     map[merkle.TreeID]*Reservation
	nextReservation  uint64
	pendingSealed    []*SegmentTree
	candidatePending int
	candidateChanges []HMFChangedNode
}

// HMFChangedNode is one candidate Merkle node to version in evidence storage.
type HMFChangedNode struct {
	TreeID merkle.TreeID
	Node   merkle.MerkleNode
}

type HMFCandidateShard struct {
	TreeID       merkle.TreeID
	Root         [32]byte
	SegmentCount int64
	Height       int
	Frontiers    []merkle.MerkleNode
}

type HMFCandidateRegion struct {
	TreeID     merkle.TreeID
	Root       [32]byte
	ShardCount int64
	Height     int
}

type HMFCandidateEvidence struct {
	Epoch             uint64
	GlobalRoot        [32]byte
	GlobalRegionCount int64
	GlobalHeight      int
	Nodes             []HMFChangedNode
	Shards            []HMFCandidateShard
	Regions           []HMFCandidateRegion
}

type HMFWorkingState struct {
	Global  *GlobalTree
	Regions map[string]*HMFWorkingRegion
}

type HMFWorkingRegion struct {
	Tree   *RegionTree
	Shards map[int64]*HMFWorkingShard
}

type HMFWorkingShard struct {
	Tree      *ShardTree //does not contain active segments
	Active    *SegmentTree
	OpenedAt  time.Time
	nextSegID int64
}

// HMFState is a candidate or authoritative finalized hierarchy.
type HMFState struct {
	Epoch   uint64
	Global  *GlobalTree
	Regions map[string]*HMFRegionState
	nodes   []*hmfSparseNode
}

type HMFRegionState struct {
	Tree   *RegionTree
	Shards map[int64]*HMFShardState
	nodes  []*hmfSparseNode
}

type HMFShardState struct {
	Tree *ShardTree
}

// SparseNode overrides the finalized roots with affected path in calcualtion
type hmfSparseNode struct {
	left, right *hmfSparseNode
	value       *merkle.MerkleNode
}

type SegmentTree struct {
	*merkle.MerkleTree
	*builder
	MaxLeaves int
	Sealed    bool
	OpenedAt  time.Time
	SealedAt  time.Time
	persisted bool
}

// in-memory segment builder
type builder struct {
	levels [][]merkle.MerkleNode
}

type ShardTree struct {
	*merkle.MerkleTree
	frontiers []merkle.MerkleNode
}

type RegionTree struct {
	*merkle.MerkleTree
	levels    [][]merkle.MerkleNode
	numShards int
}

type GlobalTree struct {
	*merkle.MerkleTree
	levels     [][]merkle.MerkleNode
	numRegions int
}

// HMFUpdate contains every hierarchy node changed when a segment is sealed.
type HMFUpdate struct {
	SegmentTreeID    merkle.TreeID
	SegmentNodes     []merkle.MerkleNode
	SegmentRoot      [32]byte
	SegmentLeaves    int64
	SegmentHeight    int
	ShardLeafIndex   int64
	SegmentMaxLeaves int
	SegmentMaxAge    time.Duration
	SegmentCreatedAt time.Time
	SegmentStartedAt time.Time
	SegmentEndedAt   time.Time
	SegmentSealedAt  time.Time

	ShardTreeID    merkle.TreeID
	ShardNodes     []merkle.MerkleNode
	ShardRoot      [32]byte
	ShardLeaves    int64
	ShardHeight    int
	ShardFrontiers []merkle.MerkleNode

	RegionTreeID          merkle.TreeID
	RegionNodes           []merkle.MerkleNode
	RegionRoot            [32]byte
	RegionLeaves          int64
	RegionHeight          int
	RegionParentLeafIndex int64

	GlobalTreeID          merkle.TreeID
	GlobalNodes           []merkle.MerkleNode
	GlobalRoot            [32]byte
	GlobalLeaves          int64
	GlobalHeight          int
	GlobalParentLeafIndex int64
}
