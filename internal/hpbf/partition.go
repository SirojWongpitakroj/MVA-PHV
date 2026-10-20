package hpbf

import "github.com/SirojWongpitakroj/mva-phv/internal/merkle"

// ShardHPBFPartition records one shard at its canonical region leaf position.
type ShardHPBFPartition struct {
	TreeID      merkle.TreeID // TreeShard with RegionID and ShardID.
	BloomFilter *BloomFilter
	Commitment  [32]byte
	Epoch       uint64
	Index       uint64
}

// RegionHPBFPartition records a region filter and its Merkle commitment.
type RegionHPBFPartition struct {
	TreeID        merkle.TreeID // TreeRegion with RegionID.
	BloomFilter   *BloomFilter
	RootHash      [32]byte
	InternalNodes [][]merkle.MerkleNode
	Epoch         uint64
	Index         uint64
}

// GlobalHPBFPartition records the global Merkle commitment for one epoch.
type GlobalHPBFPartition struct {
	RootHash      [32]byte
	InternalNodes [][]merkle.MerkleNode
	Epoch         uint64
}
