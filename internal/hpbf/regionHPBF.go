package hpbf

import (
	"fmt"
	"math/bits"
	"slices"

	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

type RegionHPBF struct {
	*merkle.MerkleTree
	levels [][]merkle.MerkleNode
	Shards map[int64]*ShardHPBF
	Root   [32]byte
	*BloomFilter
}

func NewRegionHPBF(regionID string, numShards, n int, p float64) (*RegionHPBF, error) {
	if numShards <= 0 {
		return nil, fmt.Errorf("new region bloom filter tree: numShards must be positive")
	}
	bf, err := newBloomFilter(n, p)
	if err != nil {
		return nil, err
	}

	height := bits.Len(uint(numShards - 1))
	tree := &RegionHPBF{
		MerkleTree: &merkle.MerkleTree{
			TreeID: merkle.TreeID{
				Type:     merkle.TreeRegion,
				RegionID: regionID,
			},
			LeafCount: int64(numShards),
			Height:    height,
		},
		levels:      make([][]merkle.MerkleNode, height+1),
		Shards:      make(map[int64]*ShardHPBF, numShards),
		BloomFilter: bf,
	}

	nodeCount := numShards
	for level := range tree.levels {
		tree.levels[level] = make([]merkle.MerkleNode, nodeCount)
		nodeCount = (nodeCount + 1) / 2
	}
	return tree, nil
}

func (tree *RegionHPBF) updateBloomFilter(shardBF *BloomFilter) error {
	if tree == nil {
		return fmt.Errorf("update region bloom filter: region bloom filter is nil")
	}
	if shardBF == nil {
		return fmt.Errorf("update region bloom filter: shard bloom filter is nil")
	}
	if tree.BloomFilter == nil {
		return fmt.Errorf("update region bloom filter: region bloom filter is nil")
	}
	return tree.BloomFilter.Merge(*shardBF)
}

func (tree *RegionHPBF) updateInternalNodes() ([][]merkle.MerkleNode, error) {
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
				if err := parent.ComputeInternalHash("HBPFREGINT", children[leftIndex].Hash, children[rightIndex].Hash); err != nil {
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

func (tree *RegionHPBF) Commitment(shardHashes [][32]byte, shardBFs []*BloomFilter, epoch, index uint64) (RegionHPBFPartition, error) {
	if tree == nil || tree.MerkleTree == nil {
		return RegionHPBFPartition{}, fmt.Errorf("commit region bloom filter tree: tree is nil")
	}
	if len(shardHashes) != int(tree.LeafCount) {
		return RegionHPBFPartition{}, fmt.Errorf("commit region bloom filter tree: got %d shard hashes, want %d", len(shardHashes), tree.LeafCount)
	}
	if len(shardBFs) != int(tree.LeafCount) {
		return RegionHPBFPartition{}, fmt.Errorf("commit region bloom filter tree: got %d shard filters, want %d", len(shardBFs), tree.LeafCount)
	}
	type result struct {
		updates [][]merkle.MerkleNode
		err     error
	}
	results := make(chan result, 2)
	go func() {
		for _, shardBF := range shardBFs {
			if err := tree.updateBloomFilter(shardBF); err != nil {
				results <- result{err: err}
				return
			}
		}
		results <- result{}
	}()

	//update shardHashes in RegionHPBF
	for i, hash := range shardHashes {
		tree.levels[0][i] = merkle.MerkleNode{
			Level: 0,
			Index: int64(i),
			Hash:  hash,
		}
	}

	go func() {
		updates, err := tree.updateInternalNodes()
		results <- result{updates: updates, err: err}
	}()

	var updates [][]merkle.MerkleNode
	var resultErr error
	//check no error
	for range 2 {
		completed := <-results
		if completed.err != nil && resultErr == nil {
			resultErr = completed.err
		}
		if completed.updates != nil {
			updates = completed.updates
		}
	}
	if resultErr != nil {
		return RegionHPBFPartition{}, resultErr
	}

	tree.Root = tree.levels[tree.Height][0].Hash
	return RegionHPBFPartition{
		TreeID:        tree.TreeID,
		BloomFilter:   tree.BloomFilter,
		RootHash:      tree.Root,
		InternalNodes: updates,
		Epoch:         epoch,
		Index:         index,
	}, nil
}

func (tree *RegionHPBF) generateProof() (RegionHPBFProof, error) {
	if tree == nil || tree.MerkleTree == nil {
		return RegionHPBFProof{}, fmt.Errorf("generate region proof: tree is nil")
	}
	if tree.Height < 0 || tree.BloomFilter == nil || len(tree.Shards) != int(tree.LeafCount) || len(tree.levels) != tree.Height+1 ||
		len(tree.levels[tree.Height]) != 1 || tree.Root == ([32]byte{}) ||
		tree.levels[tree.Height][0].Hash != tree.Root {
		return RegionHPBFProof{}, fmt.Errorf("generate region proof: tree is incomplete")
	}

	proof := RegionHPBFProof{
		TreeID:      tree.TreeID,
		BloomFilter: *tree.BloomFilter.Clone(),
		Shards:      make([]ShardHPBFProof, 0, len(tree.Shards)),
		Levels:      copyMerkleLevels(tree.levels),
	}
	shardIDs := make([]int64, 0, len(tree.Shards))
	for shardID := range tree.Shards {
		shardIDs = append(shardIDs, shardID)
	}
	slices.Sort(shardIDs)
	for _, shardID := range shardIDs {
		shard := tree.Shards[shardID]
		if shard == nil || shard.bloomFilter == nil || shard.TreeID.Type != merkle.TreeShard ||
			shard.RegionID != tree.TreeID.RegionID || shard.ShardID != shardID {
			return RegionHPBFProof{}, fmt.Errorf("generate region proof: shard %d is invalid", shardID)
		}
		proof.Shards = append(proof.Shards, ShardHPBFProof{
			TreeID:      shard.TreeID,
			BloomFilter: *shard.bloomFilter.Clone(),
		})
	}
	return proof, nil
}

func (tree *RegionHPBF) PruneShards(tokens [3][]byte) ([]merkle.TreeID, RegionHPBFProof) {
	proof, err := tree.generateProof()
	if err != nil {
		return nil, RegionHPBFProof{}
	}

	var matches []merkle.TreeID
	for shardID, shard := range tree.Shards {
		containsAll := true
		for _, token := range tokens {
			if !shard.bloomFilter.Contains(token) {
				containsAll = false
				break
			}
		}
		if containsAll { //candidate shards
			matches = append(matches, merkle.TreeID{
				Type:     merkle.TreeShard,
				RegionID: tree.TreeID.RegionID,
				ShardID:  shardID,
			})
		}
	}
	return matches, proof
}
