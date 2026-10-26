package hmf

import (
	"crypto/sha256"
	"fmt"
	"math/bits"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

func NewGlobalTree(numRegions int) *GlobalTree {
	if numRegions <= 0 {
		panic("new global tree: numRegions must be positive")
	}

	treeHeight := bits.Len(uint(numRegions - 1))

	tree := GlobalTree{
		MerkleTree: &merkle.MerkleTree{
			TreeID: merkle.TreeID{
				Type: merkle.TreeGlobal,
			},
			LeafCount: int64(numRegions),
			Height:    treeHeight,
		},
		levels:     make([][]merkle.MerkleNode, treeHeight+1),
		numRegions: numRegions,
	}

	nodeCount := numRegions
	for level := 0; level <= treeHeight; level++ {
		tree.levels[level] = make([]merkle.MerkleNode, nodeCount)
		nodeCount = (nodeCount + 1) / 2
	}
	if _, err := tree.Build(make([][32]byte, numRegions)); err != nil {
		panic(err)
	}
	return &tree
}

func (tree *GlobalTree) setRoot(merkleRoot [32]byte) error {
	encodedID, err := domain.Serialize(string(tree.TreeID.Type))
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

func (tree *GlobalTree) Build(regionHashes [][32]byte) ([]merkle.MerkleNode, error) {
	if len(regionHashes) != tree.numRegions {
		return nil, fmt.Errorf("build global tree: got %d region roots, want %d", len(regionHashes), tree.numRegions)
	}

	updates := []merkle.MerkleNode{}
	for index, hash := range regionHashes {
		leaf := merkle.MerkleNode{
			Level: 0,
			Index: int64(index),
			Hash:  hash,
		}
		tree.levels[0][index] = leaf
		updates = append(updates, leaf)
	}

	for level := 1; level <= tree.Height; level++ {
		for parentIndex := range tree.levels[level] {
			leftIndex := parentIndex * 2
			rightIndex := leftIndex + 1
			parent := merkle.MerkleNode{
				Level: level,
				Index: int64(parentIndex),
				Hash:  tree.levels[level-1][leftIndex].Hash,
			}
			if rightIndex < len(tree.levels[level-1]) {
				if err := parent.ComputeInternalHash(
					"GLOBALINT",
					tree.levels[level-1][leftIndex].Hash,
					tree.levels[level-1][rightIndex].Hash,
				); err != nil {
					return nil, err
				}
			}
			tree.levels[level][parentIndex] = parent
			updates = append(updates, parent)
		}
	}

	if err := tree.setRoot(tree.levels[tree.Height][0].Hash); err != nil {
		return nil, err
	}
	return updates, nil
}

func (tree *GlobalTree) recomputePath(regionIndex int, updates []merkle.MerkleNode) ([]merkle.MerkleNode, error) {
	if regionIndex < 0 || regionIndex >= tree.numRegions {
		return nil, fmt.Errorf("recompute global path: region index %d out of range", regionIndex)
	}

	index := regionIndex
	for level := 1; level <= tree.Height; level++ {
		parentIndex := index / 2
		children := tree.levels[level-1]
		leftIndex := parentIndex * 2
		rightIndex := leftIndex + 1

		parent := merkle.MerkleNode{
			Level: level,
			Index: int64(parentIndex),
			Hash:  children[leftIndex].Hash,
		}
		if rightIndex < len(children) {
			if err := parent.ComputeInternalHash(
				"GLOBALINT",
				children[leftIndex].Hash,
				children[rightIndex].Hash,
			); err != nil {
				return updates, err
			}
		}
		siblingIndex := leftIndex
		if index%2 == 0 {
			siblingIndex = rightIndex
		}
		if siblingIndex < len(children) {
			updates = append(updates, children[siblingIndex])
		}

		tree.levels[level][parentIndex] = parent
		updates = append(updates, parent)
		index = parentIndex
	}

	if err := tree.setRoot(tree.levels[tree.Height][0].Hash); err != nil {
		return updates, err
	}
	return updates, nil
}

func (tree *GlobalTree) UpdateRegionRoot(regionIndex int, regionRoot [32]byte) ([]merkle.MerkleNode, error) {
	if regionIndex < 0 || regionIndex >= tree.numRegions {
		return nil, fmt.Errorf("update global tree: region index %d out of range", regionIndex)
	}

	leaf := merkle.MerkleNode{
		Level: 0,
		Index: int64(regionIndex),
		Hash:  regionRoot,
	}
	tree.levels[0][regionIndex] = leaf

	return tree.recomputePath(regionIndex, []merkle.MerkleNode{leaf})
}
