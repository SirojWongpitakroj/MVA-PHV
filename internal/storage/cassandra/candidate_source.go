package cassandra

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"

	"github.com/SirojWongpitakroj/mva-phv/internal/hmf"
	"github.com/SirojWongpitakroj/mva-phv/internal/hpbf"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
	"github.com/SirojWongpitakroj/mva-phv/internal/mpm"
	"github.com/SirojWongpitakroj/mva-phv/internal/mva"
)

// ComponentEvidenceSource converts prepared component snapshots into CQL rows.
// Store is read only here, to reuse unchanged HPBF filter-content versions.
type ComponentEvidenceSource struct {
	Store *Store
	HMF   *hmf.HMF
	MVA   *mva.MVA
	HPBF  *hpbf.HPBF
}

var _ CandidateEvidenceSource = (*ComponentEvidenceSource)(nil)

func (s *ComponentEvidenceSource) CandidateEvidence(ctx context.Context, candidate mpm.Candidate) (CandidateEvidence, error) {
	if s == nil || s.Store == nil || s.HMF == nil || s.MVA == nil || s.HPBF == nil {
		return CandidateEvidence{}, fmt.Errorf("candidate evidence: components or store missing")
	}
	epoch, err := signedEpoch(candidate.Epoch)
	if err != nil {
		return CandidateEvidence{}, err
	}
	var out CandidateEvidence
	if err := s.hmfEvidence(candidate, epoch, &out); err != nil {
		return CandidateEvidence{}, err
	}
	if err := s.mvaEvidence(candidate, epoch, &out); err != nil {
		return CandidateEvidence{}, err
	}
	if err := s.hpbfEvidence(ctx, candidate, epoch, &out); err != nil {
		return CandidateEvidence{}, err
	}
	return out, nil
}

func (s *ComponentEvidenceSource) hmfEvidence(candidate mpm.Candidate, epoch int64, out *CandidateEvidence) error {
	evidence, err := s.HMF.CandidateEvidence(candidate.Epoch)
	if err != nil {
		return err
	}
	if evidence.GlobalRoot != candidate.Roots.HMF {
		return fmt.Errorf("candidate evidence: HMF root differs")
	}
	out.HMFGlobal = GlobalState{Scope: "GLOBAL", Epoch: epoch, Root: evidence.GlobalRoot,
		RegionCount: evidence.GlobalRegionCount, TreeHeight: int32(evidence.GlobalHeight)}
	// A batch can update the same path repeatedly. Persist only its final value.
	type key struct {
		id    merkle.TreeID
		level int
		index int64
	}
	final := make(map[key]merkle.MerkleNode)
	order := make([]key, 0, len(evidence.Nodes))
	for _, change := range evidence.Nodes {
		k := key{change.TreeID, change.Node.Level, change.Node.Index}
		if _, ok := final[k]; !ok {
			order = append(order, k)
		}
		final[k] = change.Node
	}
	for _, k := range order {
		kind, rid, sid := "", k.id.RegionID, k.id.ShardID
		switch k.id.Type {
		case merkle.TreeShard:
			kind = "SHARD"
		case merkle.TreeRegion:
			kind = "REGION"
			sid = -1
		case merkle.TreeGlobal:
			kind = "GLOBAL"
			rid = ""
			sid = -1
		default:
			return fmt.Errorf("candidate evidence: invalid HMF node tree %s", k.id.Type)
		}
		n := final[k]
		out.HMFNodes = append(out.HMFNodes, HierarchyNode{Kind: kind, RegionID: rid, ShardID: sid,
			MerkleNodeRecord: MerkleNodeRecord{Level: int32(n.Level), Index: n.Index, Hash: n.Hash}, VersionEpoch: epoch})
	}
	for _, shard := range evidence.Shards {
		frontier, err := EncodeFrontier(shard.Frontiers)
		if err != nil {
			return err
		}
		out.HMFShards = append(out.HMFShards, ShardState{RegionID: shard.TreeID.RegionID, ShardID: shard.TreeID.ShardID,
			Epoch: epoch, Root: shard.Root, SegmentCount: shard.SegmentCount, TreeHeight: int32(shard.Height), FrontierData: frontier})
	}
	for _, region := range evidence.Regions {
		out.HMFRegions = append(out.HMFRegions, RegionState{RegionID: region.TreeID.RegionID, Epoch: epoch,
			Root: region.Root, ShardCount: region.ShardCount, TreeHeight: int32(region.Height)})
	}
	return nil
}

func pagesByID(root *mva.Page) map[int64]*mva.Page {
	pages := make(map[int64]*mva.Page)
	var walk func(*mva.Page)
	walk = func(page *mva.Page) {
		if page == nil {
			return
		}
		if _, seen := pages[page.PageID]; seen {
			return
		}
		pages[page.PageID] = page
		for _, child := range page.Children {
			walk(child)
		}
	}
	walk(root)
	return pages
}

func candidatePageRows(tree *mva.LocatorTree, previous *mva.LocatorTree, view string, epoch int64) ([]PageVersion, error) {
	if tree == nil || tree.RootPage == nil {
		return nil, fmt.Errorf("candidate evidence: missing MVA view %s", view)
	}
	pages := pagesByID(tree.RootPage)
	var old map[int64]*mva.Page
	if previous != nil {
		old = pagesByID(previous.RootPage)
	}
	out := make([]PageVersion, 0, len(pages))
	for _, page := range pages {
		row, err := pageVersion(*page, view, epoch)
		if err != nil {
			return nil, err
		}
		if before := old[page.PageID]; before != nil {
			oldRow, err := pageVersion(*before, view, epoch)
			if err != nil {
				return nil, err
			}
			if reflect.DeepEqual(row, oldRow) {
				continue
			}
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PageID < out[j].PageID })
	return out, nil
}

func (s *ComponentEvidenceSource) mvaEvidence(candidate mpm.Candidate, epoch int64, out *CandidateEvidence) error {
	snapshot, err := s.MVA.CandidateSnapshot(candidate.Epoch)
	if err != nil {
		return err
	}
	if snapshot.Root != candidate.Roots.MVA {
		return fmt.Errorf("candidate evidence: MVA root differs")
	}
	for i := 0; i < len(snapshot.Regions); i++ {
		rid := strconv.Itoa(i)
		region := snapshot.Regions[rid]
		if region == nil {
			return fmt.Errorf("candidate evidence: missing MVA Region %s", rid)
		}
		var old *mva.RegionMVASnapshot
		if s.MVA.Finalized != nil {
			old = s.MVA.Finalized.Regions[rid]
		}
		views := []struct {
			name           string
			current, prior *mva.LocatorTree
		}{
			{name: "id", current: region.IDView}, {name: "attribute", current: region.AttrView}}
		if old != nil {
			views[0].prior = old.IDView
			views[1].prior = old.AttrView
		}
		for _, view := range views {
			pages, err := candidatePageRows(view.current, view.prior, view.name, epoch)
			if err != nil {
				return err
			}
			out.MVAPages = append(out.MVAPages, pages...)
			if view.current.Height > math.MaxInt32 || view.current.Order > math.MaxInt32 {
				return fmt.Errorf("candidate evidence: MVA view metadata exceeds CQL int")
			}
			out.MVAViews = append(out.MVAViews, ViewState{RegionID: rid, View: view.name, Epoch: epoch,
				RootPageID: view.current.RootPageID, RootHash: view.current.RootHash, TreeHeight: int32(view.current.Height),
				RecordCount: view.current.LeafCount, NextPageID: view.current.NextPageID, TreeOrder: int32(view.current.Order)})
		}
		out.MVARegions = append(out.MVARegions, MVARegionCommitment{Epoch: epoch, RegionIndex: int64(i), RegionID: rid,
			IDRoot: region.IDView.RootHash, AttrRoot: region.AttrView.RootHash, RegionRoot: region.Root})
	}
	for level, nodes := range snapshot.Levels {
		for index, hash := range nodes {
			out.MVAGlobalNodes = append(out.MVAGlobalNodes, EpochNode{Epoch: epoch,
				MerkleNodeRecord: MerkleNodeRecord{Level: int32(level), Index: int64(index), Hash: hash}})
		}
	}
	return nil
}

func bloomRecord(bf *hpbf.BloomFilter, rid string, sid, epoch int64) (FilterRecord, error) {
	m, k, words := bf.Snapshot()
	if m > math.MaxInt64 || k > math.MaxInt64 {
		return FilterRecord{}, fmt.Errorf("candidate evidence: Bloom metadata exceeds CQL bigint")
	}
	return FilterRecord{RegionID: rid, ShardID: sid, Epoch: epoch, BitCount: int64(m), HashCount: int64(k), Bits: FilterBits(words)}, nil
}

func (s *ComponentEvidenceSource) hpbfEvidence(ctx context.Context, candidate mpm.Candidate, epoch int64, out *CandidateEvidence) error {
	shards, regions, global, err := s.HPBF.CandidatePartitions(candidate.Epoch)
	if err != nil {
		return err
	}
	if global.RootHash != candidate.Roots.HPBF {
		return fmt.Errorf("candidate evidence: HPBF root differs")
	}
	for _, part := range shards {
		rid, sid := part.TreeID.RegionID, part.TreeID.ShardID
		filter, err := bloomRecord(part.BloomFilter, rid, sid, epoch)
		if err != nil {
			return err
		}
		version := epoch
		if candidate.Epoch > 0 {
			old, err := s.Store.GetShardFilterAt(ctx, rid, sid, candidate.Epoch-1)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
			if err == nil && old.BitCount == filter.BitCount && old.HashCount == filter.HashCount && bytes.Equal(old.Bits, filter.Bits) {
				version = old.Epoch
			}
		}
		if version == epoch {
			out.HPBFShardFilters = append(out.HPBFShardFilters, filter)
		}
		out.HPBFShards = append(out.HPBFShards, HPBFShardCommitment{Epoch: epoch, RegionID: rid, ShardID: sid,
			ShardIndex: int64(part.Index), FilterVersionEpoch: version, Commitment: part.Commitment})
	}
	for _, part := range regions {
		rid := part.TreeID.RegionID
		filter, err := bloomRecord(part.BloomFilter, rid, -1, epoch)
		if err != nil {
			return err
		}
		out.HPBFRegionFilters = append(out.HPBFRegionFilters, filter)
		out.HPBFRegions = append(out.HPBFRegions, HPBFRegionRoot{Epoch: epoch, RegionIndex: int64(part.Index), RegionID: rid, Root: part.RootHash})
		for _, nodes := range part.InternalNodes {
			for _, node := range nodes {
				out.HPBFRegionNodes = append(out.HPBFRegionNodes, RegionNode{RegionID: rid, Node: EpochNode{Epoch: epoch,
					MerkleNodeRecord: MerkleNodeRecord{Level: int32(node.Level), Index: node.Index, Hash: node.Hash}}})
			}
		}
	}
	for _, nodes := range global.InternalNodes {
		for _, node := range nodes {
			out.HPBFGlobalNodes = append(out.HPBFGlobalNodes, EpochNode{Epoch: epoch,
				MerkleNodeRecord: MerkleNodeRecord{Level: int32(node.Level), Index: node.Index, Hash: node.Hash}})
		}
	}
	return nil
}
