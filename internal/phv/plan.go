package phv

import (
	"context"
	"fmt"
	"slices"
	"sort"

	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

// Topology is the finalized HMF's configured order. HMF sorts Region IDs and
// numbers Shards from zero, so these fields are checkpoint configuration, not
// evidence inferred from untrusted storage.
type Topology struct {
	RegionIDs       []string
	ShardsPerRegion int
}

func (t Topology) orderedRegions() ([]string, error) {
	if len(t.RegionIDs) == 0 || t.ShardsPerRegion <= 0 {
		return nil, fmt.Errorf("PHV: invalid HMF topology")
	}
	ids := slices.Clone(t.RegionIDs)
	slices.Sort(ids)
	for i, id := range ids {
		if id == "" || i > 0 && ids[i-1] == id {
			return nil, fmt.Errorf("PHV: duplicate or empty Region ID")
		}
	}
	return ids, nil
}

func treeRank(kind merkle.TreeType) int {
	switch kind {
	case merkle.TreeSegment:
		return 0
	case merkle.TreeShard:
		return 1
	case merkle.TreeRegion:
		return 2
	case merkle.TreeGlobal:
		return 3
	}
	return 4
}

func lessTree(a, b merkle.TreeID) bool {
	if treeRank(a.Type) != treeRank(b.Type) {
		return treeRank(a.Type) < treeRank(b.Type)
	}
	if a.RegionID != b.RegionID {
		return a.RegionID < b.RegionID
	}
	if a.ShardID != b.ShardID {
		return a.ShardID < b.ShardID
	}
	return a.SegmentID < b.SegmentID
}

func lessRecord(a, b SelectedRecord) bool {
	x, y := a.Address, b.Address
	if x.RegionID != y.RegionID {
		return x.RegionID < y.RegionID
	}
	if x.ShardID != y.ShardID {
		return x.ShardID < y.ShardID
	}
	if x.SegmentID != y.SegmentID {
		return x.SegmentID < y.SegmentID
	}
	return x.LeafID < y.LeafID
}

// Frontier calculates the sibling subtrees adjacent to selected paths. Odd
// final nodes are carried upward, exactly as HMF does. It does not read nodes.
func Frontier(tree merkle.TreeID, leafCount int64, selected []int64) (TreePlan, int, error) {
	if leafCount <= 0 || len(selected) == 0 {
		return TreePlan{}, 0, fmt.Errorf("PHV: empty tree or selection")
	}
	indexes := slices.Clone(selected)
	slices.Sort(indexes)
	indexes = slices.Compact(indexes)
	for _, index := range indexes {
		if index < 0 || index >= leafCount {
			return TreePlan{}, 0, fmt.Errorf("PHV: selected index %d outside tree %v", index, tree)
		}
	}
	plan := TreePlan{Tree: tree, LeafCount: leafCount, Selected: indexes}
	width := leafCount
	level := 0
	naive := 0
	for width > 1 {
		selectedSet := make(map[int64]struct{}, len(indexes))
		for _, index := range indexes {
			selectedSet[index] = struct{}{}
			if sibling := index ^ 1; sibling < width {
				naive++
			}
		}
		next := make([]int64, 0, len(indexes))
		for _, index := range indexes {
			sibling := index ^ 1
			if sibling < width {
				if _, chosen := selectedSet[sibling]; !chosen {
					plan.Frontier = append(plan.Frontier, NodeKey{Tree: tree, Level: level, Index: sibling})
				}
			}
			next = append(next, index/2)
		}
		slices.Sort(next)
		indexes = slices.Compact(next)
		width = (width + 1) / 2
		level++
	}
	sort.Slice(plan.Frontier, func(i, j int) bool {
		a, b := plan.Frontier[i], plan.Frontier[j]
		if a.Level != b.Level {
			return a.Level < b.Level
		}
		return a.Index < b.Index
	})
	return plan, naive, nil
}

// BuildPlan groups authenticated MVA positions before requesting any proof
// nodes. Only small tree-size metadata is read during this stage.
func BuildPlan(ctx context.Context, repo Repository, epoch uint64, topology Topology, records []SelectedRecord) (Plan, error) {
	ids, err := topology.orderedRegions()
	if err != nil {
		return Plan{}, err
	}
	if repo == nil {
		return Plan{}, fmt.Errorf("PHV: nil repository")
	}
	canonical := Topology{RegionIDs: ids, ShardsPerRegion: topology.ShardsPerRegion}
	if len(records) == 0 {
		return Plan{Epoch: epoch, Topology: canonical}, nil
	}
	regionIndex := make(map[string]int64, len(ids))
	for i, id := range ids {
		regionIndex[id] = int64(i)
	}
	selected := make(map[merkle.TreeID][]int64)
	seen := make(map[[4]string]struct{}, len(records))
	copyRecords := slices.Clone(records)
	sort.Slice(copyRecords, func(i, j int) bool { return lessRecord(copyRecords[i], copyRecords[j]) })
	for _, record := range copyRecords {
		a := record.Address
		if record.Descriptor.RegionID != a.RegionID || a.ShardID < 0 || a.ShardID >= int64(topology.ShardsPerRegion) || a.SegmentID < 0 || a.LeafID < 0 {
			return Plan{}, fmt.Errorf("PHV: invalid authenticated physical address")
		}
		index, ok := regionIndex[a.RegionID]
		if !ok {
			return Plan{}, fmt.Errorf("PHV: unknown Region %q", a.RegionID)
		}
		key := [4]string{a.RegionID, fmt.Sprint(a.ShardID), fmt.Sprint(a.SegmentID), fmt.Sprint(a.LeafID)}
		if _, duplicate := seen[key]; duplicate {
			return Plan{}, fmt.Errorf("PHV: duplicate selected physical position")
		}
		seen[key] = struct{}{}
		seg := merkle.TreeID{Type: merkle.TreeSegment, RegionID: a.RegionID, ShardID: a.ShardID, SegmentID: a.SegmentID}
		shard := merkle.TreeID{Type: merkle.TreeShard, RegionID: a.RegionID, ShardID: a.ShardID}
		region := merkle.TreeID{Type: merkle.TreeRegion, RegionID: a.RegionID}
		global := merkle.TreeID{Type: merkle.TreeGlobal}
		selected[seg] = append(selected[seg], a.LeafID)
		selected[shard] = append(selected[shard], a.SegmentID)
		selected[region] = append(selected[region], a.ShardID)
		selected[global] = append(selected[global], index)
	}
	keys := make([]merkle.TreeID, 0, len(selected))
	for key := range selected {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return lessTree(keys[i], keys[j]) })
	plan := Plan{Epoch: epoch, Topology: canonical, Selected: copyRecords}
	partitionFor := func(key NodeKey) (string, error) {
		if mapper, ok := repo.(PartitionMapper); ok {
			return mapper.NodePartition(key)
		}
		return fmt.Sprintf("tree:%v", key.Tree), nil
	}
	for _, tree := range keys {
		var count int64
		switch tree.Type {
		case merkle.TreeGlobal:
			count = int64(len(ids))
		case merkle.TreeRegion:
			count = int64(topology.ShardsPerRegion)
		default:
			count, err = repo.LeafCount(ctx, epoch, tree)
			if err != nil {
				return Plan{}, fmt.Errorf("%w: tree size %v: %w", ErrEvidence, tree, err)
			}
		}
		part, _, err := Frontier(tree, count, selected[tree])
		if err != nil {
			return Plan{}, err
		}
		plan.Trees = append(plan.Trees, part)
		plan.UniqueNodes += len(part.Frontier)
		groups := make(map[string]*RetrievalGroup)
		for _, key := range part.Frontier {
			partition, err := partitionFor(key)
			if err != nil {
				return Plan{}, err
			}
			group := groups[partition]
			if group == nil {
				group = &RetrievalGroup{Tree: tree, Partition: partition}
				groups[partition] = group
			}
			group.Positions = append(group.Positions, key)
		}
		if tree.Type == merkle.TreeSegment {
			partition, err := partitionFor(NodeKey{Tree: tree, Level: 0, Index: 0})
			if err != nil {
				return Plan{}, err
			}
			group := groups[partition]
			if group == nil {
				group = &RetrievalGroup{Tree: tree, Partition: partition}
				groups[partition] = group
			}
			group.Leaves = slices.Clone(part.Selected)
			plan.SegmentGroups++
		}
		partitions := make([]string, 0, len(groups))
		for partition := range groups {
			partitions = append(partitions, partition)
		}
		slices.Sort(partitions)
		for _, partition := range partitions {
			group := groups[partition]
			if len(group.Positions) > 0 || len(group.Leaves) > 0 {
				plan.Groups = append(plan.Groups, *group)
			}
		}
	}
	// Baseline: one independent path through all four trees for each record.
	// Counting only one path per affected Shard/Region would understate sharing.
	counts := make(map[merkle.TreeID]int64, len(plan.Trees))
	for _, part := range plan.Trees {
		counts[part.Tree] = part.LeafCount
	}
	for _, record := range copyRecords {
		a := record.Address
		for _, position := range []struct {
			tree  merkle.TreeID
			index int64
		}{
			{merkle.TreeID{Type: merkle.TreeSegment, RegionID: a.RegionID, ShardID: a.ShardID, SegmentID: a.SegmentID}, a.LeafID},
			{merkle.TreeID{Type: merkle.TreeShard, RegionID: a.RegionID, ShardID: a.ShardID}, a.SegmentID},
			{merkle.TreeID{Type: merkle.TreeRegion, RegionID: a.RegionID}, a.ShardID},
			{merkle.TreeID{Type: merkle.TreeGlobal}, regionIndex[a.RegionID]},
		} {
			for width, index := counts[position.tree], position.index; width > 1; width, index = (width+1)/2, index/2 {
				if index^1 < width {
					plan.NaiveNodes++
				}
			}
		}
	}
	return plan, nil
}
