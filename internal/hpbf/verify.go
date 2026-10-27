package hpbf

import (
	"fmt"
	"slices"
	"sort"

	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

func proofLevels(leaves [][32]byte, tag string) ([][][32]byte, error) {
	if len(leaves) == 0 {
		return nil, fmt.Errorf("verify HPBF: empty Merkle leaves")
	}
	levels := [][][32]byte{slices.Clone(leaves)}
	for len(levels[len(levels)-1]) > 1 {
		children := levels[len(levels)-1]
		parents := make([][32]byte, (len(children)+1)/2)
		for i := range parents {
			parents[i] = children[2*i]
			if 2*i+1 < len(children) {
				var node merkle.MerkleNode
				if err := node.ComputeInternalHash(tag, parents[i], children[2*i+1]); err != nil {
					return nil, err
				}
				parents[i] = node.Hash
			}
		}
		levels = append(levels, parents)
	}
	return levels, nil
}

func sameProofLevels(a, b [][][32]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !slices.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}

// ProofCandidates evaluates the three configured token levels against a proof.
// Its candidates are untrusted until VerifyProof authenticates the proof.
func ProofCandidates(proof HPBFProof, tokens [3][]byte) ([]merkle.TreeID, []merkle.TreeID) {
	var regions, shards []merkle.TreeID
	for _, region := range proof.Regions {
		contains := true
		for _, token := range tokens {
			if !region.BloomFilter.Contains(token) {
				contains = false
				break
			}
		}
		if !contains {
			continue
		}
		regions = append(regions, region.TreeID)
		for _, shard := range region.Shards {
			contains = true
			for _, token := range tokens {
				if !shard.BloomFilter.Contains(token) {
					contains = false
					break
				}
			}
			if contains {
				shards = append(shards, shard.TreeID)
			}
		}
	}
	return regions, shards
}

// VerifyProof authenticates every Shard filter, derived Region filter, and
// Merkle level against the finalized Global HPBF root before pruning is used.
func VerifyProof(proof HPBFProof, tokens [3][]byte, root [32]byte, claimedRegions, claimedShards []merkle.TreeID) error {
	if proof.TreeID.Type != merkle.TreeGlobal || len(proof.Regions) == 0 {
		return fmt.Errorf("verify HPBF: invalid Global proof")
	}
	regionRoots := make([][32]byte, 0, len(proof.Regions))
	var expectedRegions, expectedShards []merkle.TreeID
	lastRID := ""
	for _, region := range proof.Regions {
		rid := region.TreeID.RegionID
		if region.TreeID.Type != merkle.TreeRegion || rid == "" || lastRID != "" && rid <= lastRID || len(region.Shards) == 0 {
			return fmt.Errorf("verify HPBF: invalid Region order")
		}
		lastRID = rid
		leaves := make([][32]byte, 0, len(region.Shards))
		var merged *BloomFilter
		var regionShards []merkle.TreeID
		var lastSID int64 = -1
		for _, shard := range region.Shards {
			if shard.TreeID.Type != merkle.TreeShard || shard.TreeID.RegionID != rid || shard.TreeID.ShardID <= lastSID {
				return fmt.Errorf("verify HPBF: invalid Shard order")
			}
			lastSID = shard.TreeID.ShardID
			temporary := &ShardHPBF{TreeID: shard.TreeID, bloomFilter: shard.BloomFilter.Clone()}
			part, err := temporary.Commitment(proof.Epoch, 0)
			if err != nil {
				return err
			}
			leaves = append(leaves, part.Commitment)
			if merged == nil {
				merged = shard.BloomFilter.Clone()
			} else if err := merged.Merge(shard.BloomFilter); err != nil {
				return err
			}
			contains := true
			for _, token := range tokens {
				if !shard.BloomFilter.Contains(token) {
					contains = false
					break
				}
			}
			if contains {
				regionShards = append(regionShards, shard.TreeID)
			}
		}
		m, k, bits := merged.Snapshot()
		rm, rk, rbits := region.BloomFilter.Snapshot()
		if m != rm || k != rk || !slices.Equal(bits, rbits) {
			return fmt.Errorf("verify HPBF: Region filter is not its Shards' union")
		}
		contains := true
		for _, token := range tokens {
			if !region.BloomFilter.Contains(token) {
				contains = false
				break
			}
		}
		if contains {
			expectedRegions = append(expectedRegions, region.TreeID)
			expectedShards = append(expectedShards, regionShards...)
		}
		levels, err := proofLevels(leaves, "HBPFREGINT")
		if err != nil {
			return err
		}
		if !sameProofLevels(levels, region.Levels) {
			return fmt.Errorf("verify HPBF: invalid Region Merkle proof")
		}
		regionRoots = append(regionRoots, levels[len(levels)-1][0])
	}
	levels, err := proofLevels(regionRoots, "HBPFGLOBALINT")
	if err != nil {
		return err
	}
	if !sameProofLevels(levels, proof.Levels) || levels[len(levels)-1][0] != root {
		return fmt.Errorf("verify HPBF: proof differs from finalized root")
	}
	regions := slices.Clone(claimedRegions)
	shards := slices.Clone(claimedShards)
	sort.Slice(regions, func(i, j int) bool { return regions[i].RegionID < regions[j].RegionID })
	sort.Slice(shards, func(i, j int) bool {
		if shards[i].RegionID != shards[j].RegionID {
			return shards[i].RegionID < shards[j].RegionID
		}
		return shards[i].ShardID < shards[j].ShardID
	})
	if !slices.Equal(regions, expectedRegions) || !slices.Equal(shards, expectedShards) {
		return fmt.Errorf("verify HPBF: pruning differs from authenticated filters")
	}
	return nil
}
