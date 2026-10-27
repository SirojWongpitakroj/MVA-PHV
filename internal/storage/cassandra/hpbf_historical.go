package cassandra

import (
	"context"
	"fmt"
	"sort"

	"github.com/SirojWongpitakroj/mva-phv/internal/hpbf"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
	"github.com/SirojWongpitakroj/mva-phv/internal/phv"
)

var _ phv.HPBFProofSource = (*Store)(nil)

func historicalLevels(leaves [][32]byte, rows []EpochNode) ([][][32]byte, error) {
	if len(leaves) == 0 {
		return nil, fmt.Errorf("cassandra HPBF: missing leaves")
	}
	levels := [][][32]byte{leaves}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Level != rows[j].Level {
			return rows[i].Level < rows[j].Level
		}
		return rows[i].Index < rows[j].Index
	})
	for _, row := range rows {
		if row.Level <= 0 || row.Level > 64 || row.Index < 0 {
			return nil, fmt.Errorf("cassandra HPBF: invalid node position")
		}
		for len(levels) <= int(row.Level) {
			levels = append(levels, nil)
		}
		if int64(len(levels[row.Level])) != row.Index {
			return nil, fmt.Errorf("cassandra HPBF: missing or duplicate internal node")
		}
		levels[row.Level] = append(levels[row.Level], row.Hash)
	}
	return levels, nil
}

// LoadHPBFProof reconstructs one epoch's proof from the commitment manifest,
// reusable filter versions, and versioned internal nodes. It never reads
// mutable working filters.
func (s *Store) LoadHPBFProof(ctx context.Context, epoch uint64) (hpbf.HPBFProof, error) {
	regions, err := s.ListHPBFRegionRoots(ctx, epoch)
	if err != nil {
		return hpbf.HPBFProof{}, err
	}
	if len(regions) == 0 {
		return hpbf.HPBFProof{}, fmt.Errorf("cassandra HPBF: empty Region manifest")
	}
	sort.Slice(regions, func(i, j int) bool { return regions[i].RegionIndex < regions[j].RegionIndex })
	proof := hpbf.HPBFProof{TreeID: merkle.TreeID{Type: merkle.TreeGlobal}, Epoch: epoch}
	globalLeaves := make([][32]byte, 0, len(regions))
	for i, region := range regions {
		if region.RegionIndex != int64(i) || region.RegionID == "" {
			return hpbf.HPBFProof{}, fmt.Errorf("cassandra HPBF: invalid Region order")
		}
		globalLeaves = append(globalLeaves, region.Root)
		filter, err := s.GetHPBFRegionFilter(ctx, region.RegionID, epoch)
		if err != nil {
			return hpbf.HPBFProof{}, err
		}
		words, err := filter.Words()
		if err != nil {
			return hpbf.HPBFProof{}, err
		}
		bf, err := hpbf.RestoreBloomFilter(uint64(filter.BitCount), uint64(filter.HashCount), words)
		if err != nil {
			return hpbf.HPBFProof{}, err
		}
		part := hpbf.RegionHPBFProof{TreeID: merkle.TreeID{Type: merkle.TreeRegion, RegionID: region.RegionID}, BloomFilter: bf}
		shards, err := s.ListHPBFShardCommitments(ctx, epoch, region.RegionID)
		if err != nil {
			return hpbf.HPBFProof{}, err
		}
		sort.Slice(shards, func(i, j int) bool { return shards[i].ShardIndex < shards[j].ShardIndex })
		leaves := make([][32]byte, 0, len(shards))
		for j, shard := range shards {
			if shard.ShardIndex != int64(j) || shard.FilterVersionEpoch < 0 || uint64(shard.FilterVersionEpoch) > epoch {
				return hpbf.HPBFProof{}, fmt.Errorf("cassandra HPBF: invalid Shard manifest")
			}
			leaves = append(leaves, shard.Commitment)
			content, err := s.GetShardFilterVersion(ctx, region.RegionID, shard.ShardID, shard.FilterVersionEpoch)
			if err != nil {
				return hpbf.HPBFProof{}, err
			}
			words, err := content.Words()
			if err != nil {
				return hpbf.HPBFProof{}, err
			}
			bf, err := hpbf.RestoreBloomFilter(uint64(content.BitCount), uint64(content.HashCount), words)
			if err != nil {
				return hpbf.HPBFProof{}, err
			}
			part.Shards = append(part.Shards, hpbf.ShardHPBFProof{TreeID: merkle.TreeID{Type: merkle.TreeShard, RegionID: region.RegionID, ShardID: shard.ShardID}, BloomFilter: bf})
		}
		nodes, err := s.ListHPBFRegionNodes(ctx, region.RegionID, epoch)
		if err != nil {
			return hpbf.HPBFProof{}, err
		}
		part.Levels, err = historicalLevels(leaves, nodes)
		if err != nil {
			return hpbf.HPBFProof{}, err
		}
		proof.Regions = append(proof.Regions, part)
	}
	nodes, err := s.ListHPBFGlobalNodes(ctx, epoch)
	if err != nil {
		return hpbf.HPBFProof{}, err
	}
	proof.Levels, err = historicalLevels(globalLeaves, nodes)
	if err != nil {
		return hpbf.HPBFProof{}, err
	}
	return proof, nil
}
