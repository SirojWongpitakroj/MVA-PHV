package hpbf

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"sync"

	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

// HPBF keeps the last committed epoch separate from incoming tokens.
type HPBF struct {
	Finalized        *HPBFSnapshot
	Working          *HPBFSnapshot
	Candidate        *HPBFSnapshot
	candidateShards  []ShardHPBFPartition
	candidateRegions []RegionHPBFPartition
	candidateGlobal  GlobalHPBFPartition
	mu               sync.RWMutex
	numRegions       int
	numShards        int
	n                int
	p                float64
}

type HPBFSnapshot struct {
	Epoch  uint64
	Global *GlobalHPBF
}

// NewHPBF creates a working tree with numShards shards in each region.
func NewHPBF(numRegions, numShards, n int, p float64) (*HPBF, error) {
	working, err := newHPBFSnapshot(numRegions, numShards, n, p, 0)
	finalized, err := newHPBFSnapshot(numRegions, numShards, n, p, 0)
	if err != nil {
		return nil, err
	}
	return &HPBF{
		Working:    working,
		Finalized:  finalized,
		numRegions: numRegions,
		numShards:  numShards,
		n:          n,
		p:          p,
	}, nil
}

func newHPBFSnapshot(numRegions, numShards, n int, p float64, epoch uint64) (*HPBFSnapshot, error) {
	global, err := NewGlobalHPBF(numRegions)
	if err != nil {
		return nil, err
	}
	if numShards <= 0 {
		return nil, fmt.Errorf("new HPBF: numShards must be positive")
	}

	for i := range numRegions {
		regionID := strconv.Itoa(i)
		region, err := NewRegionHPBF(regionID, numShards, n, p)
		if err != nil {
			return nil, fmt.Errorf("new HPBF: region %q: %w", regionID, err)
		}
		for j := range numShards {
			shardID := int64(j)
			shard, err := newShardHPBF(regionID, shardID, n, p)
			if err != nil {
				return nil, fmt.Errorf("new HPBF: shard %d in region %q: %w", shardID, regionID, err)
			}
			region.Shards[shardID] = shard
		}
		global.Regions[regionID] = region
	}
	return &HPBFSnapshot{Epoch: epoch, Global: global}, nil
}

// AddToken places incoming tokens in the working epoch only.
func (h *HPBF) AddToken(regionID string, shardID int64, siteID, devID, typ string) error {
	if h == nil {
		return fmt.Errorf("add HPBF token: tree is nil")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.Working == nil || h.Working.Global == nil {
		return fmt.Errorf("add HPBF token: working tree is nil")
	}
	region := h.Working.Global.Regions[regionID]
	if region == nil {
		return fmt.Errorf("add HPBF token: region %q does not exist", regionID)
	}
	shard := region.Shards[shardID]
	if shard == nil {
		return fmt.Errorf("add HPBF token: shard %d in region %q does not exist", shardID, regionID)
	}
	return shard.AddToken(siteID, devID, typ)
}

// Commitment finalizes the working epoch and carries its filters into the next epoch.
func (h *HPBF) Commitment(epoch uint64) ([]ShardHPBFPartition, []RegionHPBFPartition, GlobalHPBFPartition, error) {
	if h == nil {
		return nil, nil, GlobalHPBFPartition{}, fmt.Errorf("commit HPBF: tree is nil")
	}
	h.mu.Lock() //prevent AddToken function called on Working snapshot
	defer h.mu.Unlock()
	if h.Working == nil {
		return nil, nil, GlobalHPBFPartition{}, fmt.Errorf("commit HPBF: working tree is nil")
	}
	if h.Finalized != nil && epoch != h.Working.Epoch {
		return nil, nil, GlobalHPBFPartition{}, fmt.Errorf("commit HPBF: got epoch %d, want %d", epoch, h.Working.Epoch)
	}
	if epoch == ^uint64(0) {
		return nil, nil, GlobalHPBFPartition{}, fmt.Errorf("commit HPBF: epoch cannot advance past %d", epoch)
	}
	// Prepare a separate tree for the next epoch before changing the current one.
	next, err := newHPBFSnapshot(h.numRegions, h.numShards, h.n, h.p, epoch+1)
	if err != nil {
		return nil, nil, GlobalHPBFPartition{}, err
	}
	working := h.Working
	global := working.Global

	// The global tree needs one region hash for each of its leaves.
	if global == nil || global.MerkleTree == nil {
		return nil, nil, GlobalHPBFPartition{}, fmt.Errorf("commit HPBF: global tree is nil")
	}
	if len(global.Regions) != int(global.LeafCount) {
		return nil, nil, GlobalHPBFPartition{}, fmt.Errorf("commit HPBF: got %d regions, want %d", len(global.Regions), global.LeafCount)
	}

	// Map iteration is random, so sort IDs to keep the Merkle leaf order stable.
	regionIDs := make([]string, 0, len(global.Regions))
	for id := range global.Regions {
		regionIDs = append(regionIDs, id)
	}
	sort.Strings(regionIDs) //global tree leaf = region

	regionHashes := make([][32]byte, 0, len(regionIDs))
	regionPartitions := make([]RegionHPBFPartition, 0, len(regionIDs))
	shardPartitions := make([]ShardHPBFPartition, 0, h.numRegions*h.numShards)
	for regionIndex, regionID := range regionIDs {
		// Check that this region has exactly the shards its tree expects.
		region := global.Regions[regionID]
		if region == nil || region.MerkleTree == nil || region.BloomFilter == nil {
			return nil, nil, GlobalHPBFPartition{}, fmt.Errorf("commit HPBF: region %q is nil or incomplete", regionID)
		}
		if region.TreeID.RegionID != regionID {
			return nil, nil, GlobalHPBFPartition{}, fmt.Errorf("commit HPBF: region %q has a different tree ID", regionID)
		}
		if len(region.Shards) != int(region.LeafCount) {
			return nil, nil, GlobalHPBFPartition{}, fmt.Errorf("commit HPBF: region %q has %d shards, want %d", regionID, len(region.Shards), region.LeafCount)
		}

		// Use the same shard order every time their hashes become region leaves.
		shardIDs := make([]int64, 0, len(region.Shards))
		for id := range region.Shards {
			shardIDs = append(shardIDs, id)
		}
		slices.Sort(shardIDs)

		// Each shard commitment provides both its hash and its Bloom filter.
		shardHashes := make([][32]byte, 0, len(shardIDs))
		shardBFs := make([]*BloomFilter, 0, len(shardIDs))
		for shardIndex, shardID := range shardIDs {
			shard := region.Shards[shardID]
			if shard == nil || shard.RegionID != regionID || shard.ShardID != shardID {
				return nil, nil, GlobalHPBFPartition{}, fmt.Errorf("commit HPBF: invalid shard %d in region %q", shardID, regionID)
			}
			partition, err := shard.Commitment(epoch, uint64(shardIndex))
			if err != nil {
				return nil, nil, GlobalHPBFPartition{}, fmt.Errorf("commit HPBF: shard %d in region %q: %w", shardID, regionID, err)
			}
			shardHashes = append(shardHashes, partition.Commitment)
			shardBFs = append(shardBFs, partition.BloomFilter)
			shardPartitions = append(shardPartitions, partition)
		}

		// Rebuild the region filter from the cumulative shard filters.
		oldBF := region.BloomFilter
		region.BloomFilter = &BloomFilter{
			bits: make([]uint64, len(oldBF.bits)),
			m:    oldBF.m,
			k:    oldBF.k,
		}
		// Merge the shard filters and compute the region Merkle root.
		regionPartition, err := region.Commitment(shardHashes, shardBFs, epoch, uint64(regionIndex))
		if err != nil {
			region.BloomFilter = oldBF
			return nil, nil, GlobalHPBFPartition{}, fmt.Errorf("commit HPBF: region %q: %w", regionID, err)
		}
		regionHashes = append(regionHashes, regionPartition.RootHash)
		regionPartitions = append(regionPartitions, regionPartition)
	}

	// Use the region roots as global leaves and return the global root hash.
	globalPartition, err := global.Commitment(regionHashes, epoch)
	if err != nil {
		return nil, nil, GlobalHPBFPartition{}, fmt.Errorf("commit HPBF: global tree: %w", err)
	}
	// Preserve all committed tokens in the next working tree. Hashes are
	// recomputed with the next epoch number when that tree is committed.
	for regionID, region := range global.Regions {
		nextRegion := next.Global.Regions[regionID]
		if nextRegion == nil {
			return nil, nil, GlobalHPBFPartition{}, fmt.Errorf("commit HPBF: next working tree has no region %q", regionID)
		}
		if err := nextRegion.BloomFilter.Merge(*region.BloomFilter); err != nil {
			return nil, nil, GlobalHPBFPartition{}, fmt.Errorf("commit HPBF: copy region %q filter: %w", regionID, err)
		}
		for shardID, shard := range region.Shards {
			nextShard := nextRegion.Shards[shardID]
			if nextShard == nil {
				return nil, nil, GlobalHPBFPartition{}, fmt.Errorf("commit HPBF: next working tree has no shard %d in region %q", shardID, regionID)
			}
			if err := nextShard.bloomFilter.Merge(*shard.bloomFilter); err != nil {
				return nil, nil, GlobalHPBFPartition{}, fmt.Errorf("commit HPBF: copy shard %d in region %q filter: %w", shardID, regionID, err)
			}
		}
	}
	working.Epoch = epoch
	h.Finalized = working
	h.Working = next
	return shardPartitions, regionPartitions, globalPartition, nil
}

// CandidateRegionShards searches the last finalized epoch and returns its proof.
func (h *HPBF) CandidateRegionShards(tokens [3][]byte) ([]merkle.TreeID, []merkle.TreeID, HPBFProof) {
	if h == nil {
		return nil, nil, HPBFProof{}
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.Finalized == nil || h.Finalized.Global == nil {
		return nil, nil, HPBFProof{}
	}

	global := h.Finalized.Global
	regions, proof := global.PruneRegions(tokens)
	var shards []merkle.TreeID
	for _, regionID := range regions {
		region := global.Regions[regionID.RegionID]
		if region != nil {
			matches, _ := region.PruneShards(tokens)
			shards = append(shards, matches...)
		}
	}
	return regions, shards, proof
}
