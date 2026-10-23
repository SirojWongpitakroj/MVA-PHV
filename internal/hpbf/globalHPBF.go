package hpbf

import (
	"fmt"
	"math/bits"
	"sort"

	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

type GlobalHPBF struct {
	*merkle.MerkleTree
	levels   [][]merkle.MerkleNode
	RootHash [32]byte
	Regions  map[string]*RegionHPBF
	epoch    uint64
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
		Regions: make(map[string]*RegionHPBF, numRegions),
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

func (tree *GlobalHPBF) Commitment(regionHashes [][32]byte, epoch uint64) (GlobalHPBFPartition, error) {
	if tree == nil || tree.MerkleTree == nil {
		return GlobalHPBFPartition{}, fmt.Errorf("commit global bloom filter tree: tree is nil")
	}
	if len(regionHashes) != int(tree.LeafCount) {
		return GlobalHPBFPartition{}, fmt.Errorf("commit global bloom filter tree: got %d region hashes, want %d", len(regionHashes), tree.LeafCount)
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
		return GlobalHPBFPartition{}, err
	}

	tree.RootHash = tree.levels[tree.Height][0].Hash
	tree.MerkleTree.Root = tree.RootHash
	tree.epoch = epoch
	return GlobalHPBFPartition{
		RootHash:      tree.RootHash,
		InternalNodes: updates,
		Epoch:         epoch,
	}, nil
}

func (tree *GlobalHPBF) generateProof() (HPBFProof, error) {
	if tree == nil || tree.MerkleTree == nil {
		return HPBFProof{}, fmt.Errorf("generate global proof: tree is nil")
	}
	if tree.Height < 0 || len(tree.Regions) != int(tree.LeafCount) ||
		len(tree.levels) != tree.Height+1 || len(tree.levels[tree.Height]) != 1 ||
		tree.RootHash == ([32]byte{}) || tree.levels[tree.Height][0].Hash != tree.RootHash {
		return HPBFProof{}, fmt.Errorf("generate global proof: tree is incomplete")
	}

	proof := HPBFProof{
		TreeID:  tree.TreeID,
		Epoch:   tree.epoch,
		Regions: make([]RegionHPBFProof, 0, len(tree.Regions)),
		Levels:  copyMerkleLevels(tree.levels),
	}
	regionIDs := make([]string, 0, len(tree.Regions))
	for regionID := range tree.Regions {
		regionIDs = append(regionIDs, regionID)
	}
	sort.Strings(regionIDs)
	if len(tree.levels[0]) != len(regionIDs) {
		return HPBFProof{}, fmt.Errorf("generate global proof: region leaves are incomplete")
	}
	for index, regionID := range regionIDs {
		region := tree.Regions[regionID]
		if region == nil || region.TreeID.RegionID != regionID ||
			tree.levels[0][index].Hash != region.Root {
			return HPBFProof{}, fmt.Errorf("generate global proof: region %q has no committed leaf", regionID)
		}
		regionProof, err := region.generateProof()
		if err != nil {
			return HPBFProof{}, fmt.Errorf("generate global proof: region %q: %w", regionID, err)
		}
		proof.Regions = append(proof.Regions, regionProof)
	}
	return proof, nil
}

func (tree *GlobalHPBF) PruneRegions(tokens [3][]byte) ([]merkle.TreeID, HPBFProof) {
	proof, err := tree.generateProof()
	if err != nil {
		return nil, HPBFProof{}
	}

	var matches []merkle.TreeID
	for regionID, region := range tree.Regions {
		containsAll := true
		for _, token := range tokens {
			if !region.BloomFilter.Contains(token) {
				containsAll = false
				break
			}
		}
		if containsAll {
			matches = append(matches, merkle.TreeID{
				Type:     merkle.TreeRegion,
				RegionID: regionID,
			})
		}
	}
	return matches, proof
}
