package hmf

import (
	"fmt"
	"slices"

	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

// CandidateEvidence copies only changed authentication paths and compact state.
func (h *HMF) CandidateEvidence(epoch uint64) (HMFCandidateEvidence, error) {
	if h == nil {
		return HMFCandidateEvidence{}, fmt.Errorf("HMF candidate evidence: nil tree")
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.Candidate == nil || h.Candidate.Epoch != epoch {
		return HMFCandidateEvidence{}, fmt.Errorf("HMF candidate evidence: no candidate for epoch %d", epoch)
	}
	c := h.Candidate
	out := HMFCandidateEvidence{Epoch: epoch, GlobalRoot: c.Global.Root,
		GlobalRegionCount: c.Global.LeafCount, GlobalHeight: c.Global.Height,
		Nodes: slices.Clone(h.candidateChanges)}
	for _, rid := range h.regionIDs {
		region := c.Regions[rid]
		if region == nil {
			return HMFCandidateEvidence{}, fmt.Errorf("HMF candidate evidence: missing Region %q", rid)
		}
		if region != h.Finalized.Regions[rid] {
			out.Regions = append(out.Regions, HMFCandidateRegion{TreeID: region.Tree.TreeID,
				Root: region.Tree.Root, ShardCount: region.Tree.LeafCount, Height: region.Tree.Height})
		}
		ids := make([]int64, 0, len(region.Shards))
		for sid := range region.Shards {
			ids = append(ids, sid)
		}
		slices.Sort(ids)
		for _, sid := range ids {
			shard := region.Shards[sid]
			if shard == nil || shard.Tree == nil {
				return HMFCandidateEvidence{}, fmt.Errorf("HMF candidate evidence: missing Shard %q/%d", rid, sid)
			}
			if shard == h.Finalized.Regions[rid].Shards[sid] {
				continue
			}
			out.Shards = append(out.Shards, HMFCandidateShard{TreeID: merkle.TreeID{Type: merkle.TreeShard, RegionID: rid, ShardID: sid},
				Root: shard.Tree.Root, SegmentCount: shard.Tree.LeafCount, Height: shard.Tree.Height,
				Frontiers: shard.Tree.Frontiers()})
		}
	}
	return out, nil
}
