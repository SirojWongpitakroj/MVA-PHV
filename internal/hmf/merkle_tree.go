package hmf

import (
	"crypto/sha256"
	"fmt"

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

func (node *MerkleNode) serializeInternalHash(treeType TreeType, left, right [32]byte) ([]byte, error) {
	var tag string
	switch treeType {
	case TreeSegment:
		tag = "SEGINT"
	case TreeShard:
		tag = "SHARDINT"
	case TreeRegion:
		tag = "REGINT"
	case TreeGlobal:
		tag = "GLOBALINT"
	default:
		return nil, fmt.Errorf("serialize internal hash: unknown tree type %q", treeType)
	}

	return domain.Serialize([]byte(tag), left[:], right[:])
}

func (node *MerkleNode) computeInternalHash(treeType TreeType, left, right [32]byte) error {
	encoded, err := node.serializeInternalHash(treeType, left, right)
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
