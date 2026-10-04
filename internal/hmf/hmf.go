package hmf

import (
	"time"
)

type HMFConfig struct {
	RegionIDs          []string
	NumShardsPerRegion int
	MaxSegmentLeaves   int
}

// HMFUpdate contains every hierarchy node changed when a segment is sealed.
type HMFUpdate struct {
	SegmentTreeID    TreeID
	SegmentNodes     []MerkleNode
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

	ShardTreeID    TreeID
	ShardNodes     []MerkleNode
	ShardRoot      [32]byte
	ShardLeaves    int64
	ShardHeight    int
	ShardFrontiers []MerkleNode

	RegionTreeID          TreeID
	RegionNodes           []MerkleNode
	RegionRoot            [32]byte
	RegionLeaves          int64
	RegionHeight          int
	RegionParentLeafIndex int64

	GlobalTreeID          TreeID
	GlobalNodes           []MerkleNode
	GlobalRoot            [32]byte
	GlobalLeaves          int64
	GlobalHeight          int
	GlobalParentLeafIndex int64
}
