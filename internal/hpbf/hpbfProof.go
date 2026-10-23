package hpbf

import "github.com/SirojWongpitakroj/mva-phv/internal/merkle"

type HPBFProof struct {
	merkle.TreeID
	Epoch   uint64
	Regions []RegionHPBFProof // regions covered by this query
	Levels  [][][32]byte      // finalized Global HPBF Merkle levels
}

type RegionHPBFProof struct {
	merkle.TreeID
	Shards []ShardHPBFProof // ALL shards in this evaluated region
	Levels [][][32]byte     // finalized Regional HPBF Merkle levels
	BloomFilter
}

type ShardHPBFProof struct {
	merkle.TreeID
	BloomFilter
}

// copyMerkleLevels snapshots node hashes without sharing the tree's level slices.
func copyMerkleLevels(levels [][]merkle.MerkleNode) [][][32]byte {
	result := make([][][32]byte, len(levels))
	for level, nodes := range levels {
		result[level] = make([][32]byte, len(nodes))
		for index, node := range nodes {
			result[level][index] = node.Hash
		}
	}
	return result
}
