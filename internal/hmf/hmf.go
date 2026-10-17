package hmf

import (
	"time"

	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

type HMFConfig struct {
	RegionIDs          []string
	NumShardsPerRegion int
	MaxSegmentLeaves   int
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
