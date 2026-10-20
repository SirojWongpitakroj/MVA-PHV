package hpbf

import (
	"fmt"
	"math/bits"

	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

type GlobalHPBF struct {
	*merkle.MerkleTree
	levels   [][]merkle.MerkleNode
	RootHash [32]byte
	Regions  map[string]*RegionHBPF
}

func NewGlobalHPBF(numRegions int) (*GlobalHPBF, error) {
	if numRegions <= 0 {
		return nil, fmt.Errorf("new global bloom filter tree: numRegions must be positive")
	}

	height := bits.Len(uint(numRegions - 1))
	tree := &GlobalHPBF{
		MerkleTree: &merkle.MerkleTree{
			TreeID:    merkle.TreeID{Type: merkle.TreeGlobal},
			LeafCount: int64(numRegions),
			Height:    height,
		},
		levels:  make([][]merkle.MerkleNode, height+1),
		Regions: make(map[string]*RegionHBPF, numRegions),
	}

	nodeCount := numRegions
	for level := range tree.levels {
		tree.levels[level] = make([]merkle.MerkleNode, nodeCount)
		nodeCount = (nodeCount + 1) / 2
	}
	return tree, nil
}

func (tree *GlobalHPBF) updateInternalNodes() ([][]merkle.MerkleNode, error) {
	updates := make([][]merkle.MerkleNode, tree.Height)
	for level := 1; level <= tree.Height; level++ {
		nodes := make([]merkle.MerkleNode, len(tree.levels[level]))
		children := tree.levels[level-1]
		for parentIndex := range nodes {
			leftIndex := parentIndex * 2
			rightIndex := leftIndex + 1
			parent := merkle.MerkleNode{
				Level: level,
				Index: int64(parentIndex),
				Hash:  children[leftIndex].Hash,
			}
			if rightIndex < len(children) {
				if err := parent.ComputeInternalHash("HBPFGLOBALINT", children[leftIndex].Hash, children[rightIndex].Hash); err != nil {
					return nil, err
				}
			}
			nodes[parentIndex] = parent
			tree.levels[level][parentIndex] = parent
		}
		updates[level-1] = nodes
	}
	return updates, nil
}

func (tree *GlobalHPBF) Commitment(regionHashes [][32]byte) ([][]merkle.MerkleNode, error) {
	if tree == nil || tree.MerkleTree == nil {
		return nil, fmt.Errorf("commit global bloom filter tree: tree is nil")
	}
	if len(regionHashes) != int(tree.LeafCount) {
		return nil, fmt.Errorf("commit global bloom filter tree: got %d region hashes, want %d", len(regionHashes), tree.LeafCount)
	}

	for index, hash := range regionHashes {
		tree.levels[0][index] = merkle.MerkleNode{
			Level: 0,
			Index: int64(index),
			Hash:  hash,
		}
	}

	updates, err := tree.updateInternalNodes()
	if err != nil {
		return nil, err
	}

	tree.RootHash = tree.levels[tree.Height][0].Hash
	tree.MerkleTree.Root = tree.RootHash
	return updates, nil
}
