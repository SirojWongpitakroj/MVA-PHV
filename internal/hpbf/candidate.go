package hpbf

import (
	"fmt"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
	"slices"
)

func cloneNodeLevels(levels [][]merkle.MerkleNode) [][]merkle.MerkleNode {
	out := make([][]merkle.MerkleNode, len(levels))
	for i := range levels {
		out[i] = slices.Clone(levels[i])
	}
	return out
}

// TokenRecord is one sealed record's searchable descriptor and physical Shard.
type TokenRecord struct {
	RegionID               string
	ShardID                int64
	SiteID, DeviceID, Type string
}

// PrepareCandidate starts from the previous finalized filters and applies only
// the sealed records supplied by MPM. It leaves Finalized authoritative.
func (h *HPBF) PrepareCandidate(epoch uint64, sealed []TokenRecord) ([32]byte, error) {
	if h == nil {
		return [32]byte{}, fmt.Errorf("prepare HPBF candidate: HPBF is nil")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.Candidate != nil {
		if h.Candidate.Epoch != epoch {
			return [32]byte{}, fmt.Errorf("prepare HPBF candidate: epoch %d pending", h.Candidate.Epoch)
		}
		return h.candidateGlobal.RootHash, nil
	}
	if h.Finalized == nil || epoch <= h.Finalized.Epoch {
		return [32]byte{}, fmt.Errorf("prepare HPBF candidate: invalid epoch %d", epoch)
	}
	base, err := newHPBFSnapshot(h.numRegions, h.numShards, h.n, h.p, epoch)
	if err != nil {
		return [32]byte{}, err
	}
	for rid, region := range h.Finalized.Global.Regions {
		target := base.Global.Regions[rid]
		if target == nil {
			return [32]byte{}, fmt.Errorf("prepare HPBF candidate: missing Region %q", rid)
		}
		for sid, shard := range region.Shards {
			if target.Shards[sid] == nil || shard == nil || shard.bloomFilter == nil {
				return [32]byte{}, fmt.Errorf("prepare HPBF candidate: missing Shard %q/%d", rid, sid)
			}
			if err := target.Shards[sid].bloomFilter.Merge(*shard.bloomFilter); err != nil {
				return [32]byte{}, err
			}
		}
	}
	temp := &HPBF{Working: base, numRegions: h.numRegions, numShards: h.numShards, n: h.n, p: h.p}
	for _, record := range sealed {
		if err := temp.AddToken(record.RegionID, record.ShardID, record.SiteID, record.DeviceID, record.Type); err != nil {
			return [32]byte{}, err
		}
	}
	shards, regions, global, err := temp.Commitment(epoch)
	if err != nil {
		return [32]byte{}, err
	}
	h.Candidate = temp.Finalized
	h.candidateShards = shards
	h.candidateRegions = regions
	h.candidateGlobal = global
	// Ingestion after preparation belongs to the following working generation.
	if h.Working != nil {
		h.Working.Epoch = epoch + 1
	}
	return global.RootHash, nil
}

// CandidatePartitions returns the authenticated evidence for persistence.
func (h *HPBF) CandidatePartitions(epoch uint64) ([]ShardHPBFPartition, []RegionHPBFPartition, GlobalHPBFPartition, error) {
	if h == nil {
		return nil, nil, GlobalHPBFPartition{}, fmt.Errorf("HPBF candidate partitions: HPBF is nil")
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.Candidate == nil || h.Candidate.Epoch != epoch {
		return nil, nil, GlobalHPBFPartition{}, fmt.Errorf("HPBF candidate partitions: no candidate for epoch %d", epoch)
	}
	shards := make([]ShardHPBFPartition, len(h.candidateShards))
	for i, part := range h.candidateShards {
		shards[i] = part
		shards[i].BloomFilter = part.BloomFilter.Clone()
	}
	regions := make([]RegionHPBFPartition, len(h.candidateRegions))
	for i, part := range h.candidateRegions {
		regions[i] = part
		regions[i].BloomFilter = part.BloomFilter.Clone()
		regions[i].InternalNodes = cloneNodeLevels(part.InternalNodes)
	}
	global := h.candidateGlobal
	global.InternalNodes = cloneNodeLevels(global.InternalNodes)
	return shards, regions, global, nil
}

// CommitCandidate promotes only the already prepared epoch after anchoring.
func (h *HPBF) ValidateCandidate(epoch uint64) error {
	if h == nil {
		return fmt.Errorf("validate HPBF candidate: HPBF is nil")
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.Candidate == nil || h.Candidate.Epoch != epoch {
		return fmt.Errorf("validate HPBF candidate: no candidate for epoch %d", epoch)
	}
	return nil
}

func (h *HPBF) CommitCandidate(epoch uint64) error {
	if h == nil {
		return fmt.Errorf("commit HPBF candidate: HPBF is nil")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.Candidate == nil || h.Candidate.Epoch != epoch {
		return fmt.Errorf("commit HPBF candidate: no candidate for epoch %d", epoch)
	}
	h.Finalized = h.Candidate
	h.Candidate = nil
	h.candidateShards = nil
	h.candidateRegions = nil
	h.candidateGlobal = GlobalHPBFPartition{}
	return nil
}

// WorkingShardFilter snapshots the mutable filter after AddToken for recovery.
func (h *HPBF) WorkingShardFilter(rid string, sid int64) (epoch, m, k uint64, words []uint64, err error) {
	if h == nil {
		return 0, 0, 0, nil, fmt.Errorf("HPBF working filter: HPBF is nil")
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.Working == nil || h.Working.Global == nil || h.Working.Global.Regions[rid] == nil || h.Working.Global.Regions[rid].Shards[sid] == nil {
		return 0, 0, 0, nil, fmt.Errorf("HPBF working filter: unknown Shard %q/%d", rid, sid)
	}
	bf := h.Working.Global.Regions[rid].Shards[sid].bloomFilter
	if bf == nil {
		return 0, 0, 0, nil, fmt.Errorf("HPBF working filter: Bloom filter is nil")
	}
	workingEpoch := h.Working.Epoch
	if h.Finalized != nil && workingEpoch <= h.Finalized.Epoch {
		workingEpoch = h.Finalized.Epoch + 1
	}
	return workingEpoch, bf.m, bf.k, append([]uint64(nil), bf.bits...), nil
}
