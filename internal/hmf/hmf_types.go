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
	pendingSealed    []*SegmentTree
	candidatePending int
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
