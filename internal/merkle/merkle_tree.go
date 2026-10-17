package merkle

import (
	"crypto/sha256"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
)

type TreeType string

const (
	TreeGlobal  TreeType = "Global"
	TreeRegion  TreeType = "Region"
	TreeShard   TreeType = "Shard"
	TreeSegment TreeType = "Segment"
)

type TreeID struct {
	Type      TreeType
	RegionID  string
	ShardID   int64
	SegmentID int64
}

type MerkleNode struct {
	Level int
	Index int64
	Hash  [32]byte
}

func (node *MerkleNode) ComputeInternalHash(tag string, left, right [32]byte) error {
	encoded, err := domain.Serialize([]byte(tag), left[:], right[:])
	if err != nil {
		return err
	}
	node.Hash = sha256.Sum256(encoded)
	return nil
}

type MerkleTree struct {
	TreeID    TreeID
	Root      [32]byte
	LeafCount int64
	Height    int
}
