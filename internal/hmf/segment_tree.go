package hmf

import (
	"crypto/sha256"
	"fmt"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
	"uuid"
)

type SegmentTree struct {
	*MerkleTree
	*builder
	MaxLeaves int
	Sealed    bool
}

// in-memory segment builder
type builder struct {
	levels [][]MerkleNode
}

// NewSegmentTree initiate a new MerkleTree
func NewSegmentTree(regionID string, shardID, segmentID int64, maxLeaves int) *SegmentTree {
	tree := &SegmentTree{
		MerkleTree: &MerkleTree{
			TreeID: TreeID{
				Type:      TreeSegment,
				RegionID:  regionID,
				ShardID:   shardID,
				SegmentID: segmentID,
			},
		},
		MaxLeaves: maxLeaves,
		Sealed:    false,
		builder: &builder{
			levels: make([][]MerkleNode, 1),
		},
	}

	tree.levels[0] = make([]MerkleNode, 0, maxLeaves)
	return tree
}

// leafHash computes H(LOG || LogID || h || H(h)).
func leafHash(logID uuid.UUID, h [32]byte) ([32]byte, error) {
	innerHash := sha256.Sum256(h[:])
	encoded, err := domain.Serialize([]byte("LOG"), logID, h[:], innerHash[:])
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}

// Append inserts a log into the mutable tree.
func (tree *SegmentTree) Append(logID uuid.UUID, h [32]byte) error { // h = c_i
	if tree.Sealed {
		return fmt.Errorf("append segment tree: segment tree sealed")
	}
	if tree.LeafCount >= int64(tree.MaxLeaves) {
		return fmt.Errorf("append segment tree: segment tree is full")
	}

	hash, err := leafHash(logID, h)
	if err != nil {
		return err
	}
	tree.levels[0] = append(tree.levels[0], MerkleNode{
		Level: 0,
		Index: tree.LeafCount,
		Hash:  hash,
	})

	tree.LeafCount++
	return nil
}

// Build immutable segment tree and return all nodes for persistence.
func (tree *SegmentTree) buildInternalNode() ([]MerkleNode, error) {
	if tree.LeafCount == 0 {
		return nil, fmt.Errorf("build segment tree: segment tree has no leaves")
	}

	updates := append([]MerkleNode(nil), tree.levels[0]...)
	for level := 1; len(tree.levels[level-1]) > 1; level++ {
		children := tree.levels[level-1]
		nodes := make([]MerkleNode, 0, (len(children)+1)/2)

		for index := 0; index < len(children); index += 2 {
			node := MerkleNode{
				Level: level,
				Index: int64(index / 2),
				Hash:  children[index].Hash,
			}
			if index+1 < len(children) {
				if err := node.computeInternalHash(tree.TreeID.Type, children[index].Hash, children[index+1].Hash); err != nil {
					return nil, err
				}
			}
			nodes = append(nodes, node)
			updates = append(updates, node)
		}

		tree.levels = append(tree.levels, nodes)
	}

	tree.Height = len(tree.levels) - 1
	tree.Root = tree.levels[tree.Height][0].Hash
	return updates, nil
}

func (tree *SegmentTree) Seal() ([]MerkleNode, error) {
	if tree.Sealed {
		return nil, fmt.Errorf("seal segment tree: the tree is already sealed")
	}
	updates, err := tree.buildInternalNode()
	if err != nil {
		return nil, err
	}
	tree.Sealed = true

	return updates, nil
}
