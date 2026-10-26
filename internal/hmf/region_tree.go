package hmf

import (
	"crypto/sha256"
	"fmt"
	"math/bits"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

func NewRegionTree(regionID string, numShards int) *RegionTree {
	if numShards <= 0 {
		panic("new region tree: numShards must be positive")
	}

	treeHeight := bits.Len(uint(numShards - 1))

	tree := RegionTree{
		MerkleTree: &merkle.MerkleTree{
			TreeID: merkle.TreeID{
				Type:     merkle.TreeRegion,
				RegionID: regionID,
			},
			LeafCount: int64(numShards),
			Height:    treeHeight,
		},
		levels:    make([][]merkle.MerkleNode, treeHeight+1),
		numShards: numShards,
	}

	nodeCount := numShards
	for level := 0; level <= treeHeight; level++ {
		tree.levels[level] = make([]merkle.MerkleNode, nodeCount)
		nodeCount = (nodeCount + 1) / 2
	}
	if _, err := tree.Build(make([][32]byte, numShards)); err != nil {
		panic(err)
	}
	return &tree
}

func (tree *RegionTree) setRoot(merkleRoot [32]byte) error {
	encodedID, err := domain.Serialize(string(tree.TreeID.Type), tree.TreeID.RegionID)
	if err != nil {
		return err
	}
	encodedRoot, err := domain.Serialize(
		[]byte("TREE"), encodedID, uint64(tree.LeafCount), merkleRoot[:],
	)
	if err != nil {
		return err
	}
	tree.Root = sha256.Sum256(encodedRoot)
	return nil
}

func (tree *RegionTree) Build(shardHashes [][32]byte) ([]merkle.MerkleNode, error) {
	if tree.numShards != len(shardHashes) {
		return nil, fmt.Errorf("build shard tree: number of shard-root leaves incorrect")
	}

	updates := []merkle.MerkleNode{}

	//insert shard root (leaf)
	for i, h := range shardHashes {
		leaf := merkle.MerkleNode{
			Level: 0,
			Index: int64(i),
			Hash:  h,
		}
		tree.levels[0][i] = leaf
		updates = append(updates, leaf)
	}

	//build internal node
	for l := 1; l <= tree.Height; l++ {
		for parentIndex := range tree.levels[l] {
			leftIndex := parentIndex * 2
			rightIndex := leftIndex + 1
			internalNode := merkle.MerkleNode{
				Level: l,
				Index: int64(parentIndex),
				Hash:  tree.levels[l-1][leftIndex].Hash,
			}
			if rightIndex < len(tree.levels[l-1]) {
				if err := internalNode.ComputeInternalHash(
					"REGINT",
					tree.levels[l-1][leftIndex].Hash,
					tree.levels[l-1][rightIndex].Hash,
				); err != nil {
					return nil, err
				}
			}
			tree.levels[l][parentIndex] = internalNode
			updates = append(updates, internalNode)
		}
	}

	if err := tree.setRoot(tree.levels[tree.Height][0].Hash); err != nil {
		return nil, err
	}
	return updates, nil
}

func (tree *RegionTree) recomputePath(shardIndex int, updates []merkle.MerkleNode) ([]merkle.MerkleNode, error) {
	if shardIndex < 0 || int64(shardIndex) >= tree.LeafCount {
		return updates, fmt.Errorf("recompute region path: shard index %d out of range", shardIndex)
	}
	if len(tree.levels) != tree.Height+1 || int64(len(tree.levels[0])) != tree.LeafCount {
		return updates, fmt.Errorf("recompute region path: invalid in-memory tree layout")
	}

	index := shardIndex
	for level := 1; level <= tree.Height; level++ {
		parentIndex := index / 2
		childLevel := tree.levels[level-1]
		leftIndex := parentIndex * 2
		rightIndex := leftIndex + 1

		if parentIndex >= len(tree.levels[level]) {
			return updates, fmt.Errorf("recompute region path: parent index %d out of range at level %d", parentIndex, level)
		}

		parent := merkle.MerkleNode{
			Level: level,
			Index: int64(parentIndex),
			Hash:  childLevel[leftIndex].Hash,
		}
		if rightIndex < len(childLevel) {
			if err := parent.ComputeInternalHash(
				"REGINT",
				childLevel[leftIndex].Hash,
				childLevel[rightIndex].Hash,
			); err != nil {
				return updates, err
			}
		}
		siblingIndex := leftIndex
		if index%2 == 0 {
			siblingIndex = rightIndex
		}
		if siblingIndex < len(childLevel) {
			updates = append(updates, childLevel[siblingIndex])
		}

		tree.levels[level][parentIndex] = parent
		updates = append(updates, parent)
		index = parentIndex
	}

	root := tree.levels[tree.Height][0]
	if err := tree.setRoot(root.Hash); err != nil {
		return updates, err
	}
	return updates, nil
}

func (tree *RegionTree) updateShardRoot(shardIndex int, shardRoot [32]byte) ([]merkle.MerkleNode, error) {
	if shardIndex < 0 || shardIndex >= tree.numShards {
		return nil, fmt.Errorf("update region tree: shard index %d out of range", shardIndex)
	}

	//update shard root
	leaf := merkle.MerkleNode{
		Level: 0,
		Index: int64(shardIndex),
		Hash:  shardRoot,
	}
	tree.levels[0][shardIndex] = leaf

	updates, err := tree.recomputePath(shardIndex, []merkle.MerkleNode{leaf})
	if err != nil {
		return nil, err
	}

	return updates, nil
}
