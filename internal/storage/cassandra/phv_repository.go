package cassandra

import (
	"context"
	"fmt"

	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
	"github.com/SirojWongpitakroj/mva-phv/internal/mpm"
	"github.com/SirojWongpitakroj/mva-phv/internal/phv"
)

var _ phv.Repository = (*Store)(nil)
var _ phv.RootEvidence = (*Store)(nil)
var _ phv.PartitionMapper = (*Store)(nil)

// NodePartition exposes the exact CQL partition without exposing its query
// syntax to PHV. Segment logs and nodes share (RID,SID,SegID); upper nodes
// share (kind,RID,SID,level,node bucket).
func (s *Store) NodePartition(key phv.NodeKey) (string, error) {
	id := key.Tree
	if key.Level < 0 || key.Index < 0 {
		return "", fmt.Errorf("cassandra PHV: negative node position")
	}
	switch id.Type {
	case merkle.TreeSegment:
		if id.RegionID == "" || id.ShardID < 0 || id.SegmentID < 0 {
			return "", fmt.Errorf("cassandra PHV: invalid Segment ID")
		}
		return fmt.Sprintf("segment:%q:%d:%d", id.RegionID, id.ShardID, id.SegmentID), nil
	case merkle.TreeShard, merkle.TreeRegion, merkle.TreeGlobal:
		kind, rid, sid := "SHARD", id.RegionID, id.ShardID
		if id.Type == merkle.TreeRegion {
			kind, sid = "REGION", -1
		}
		if id.Type == merkle.TreeGlobal {
			kind, rid, sid = "GLOBAL", "", -1
		}
		bucket, err := nodeBucket(key.Index)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("hierarchy:%s:%q:%d:%d:%d", kind, rid, sid, key.Level, bucket), nil
	default:
		return "", fmt.Errorf("cassandra PHV: unsupported tree type")
	}
}

func (s *Store) RootTuple(ctx context.Context, epoch uint64) (mpm.Roots, error) {
	var roots mpm.Roots
	var err error
	if roots.MVA, err = s.GetMVARoot(ctx, epoch); err != nil {
		return roots, err
	}
	global, err := s.GetGlobalState(ctx, "GLOBAL", epoch)
	if err != nil {
		return roots, err
	}
	roots.HMF = global.Root
	if roots.HPBF, err = s.GetHPBFRoot(ctx, epoch); err != nil {
		return roots, err
	}
	return roots, nil
}

// LeafCount supplies PHV only the small structural metadata needed to plan
// its frontier. These rows are evidence; the final root comparison authenticates
// their claimed shape.
func (s *Store) LeafCount(ctx context.Context, epoch uint64, tree merkle.TreeID) (int64, error) {
	switch tree.Type {
	case merkle.TreeSegment:
		meta, err := s.GetSealedSegment(ctx, SegmentKey{RegionID: tree.RegionID, ShardID: tree.ShardID, SegmentID: tree.SegmentID})
		if err != nil {
			return 0, err
		}
		return meta.LeafCount, nil
	case merkle.TreeShard:
		state, err := s.GetShardStateAt(ctx, tree.RegionID, tree.ShardID, epoch)
		if err != nil {
			return 0, err
		}
		return state.SegmentCount, nil
	default:
		return 0, fmt.Errorf("cassandra PHV: unsupported size request for %v", tree)
	}
}

// FetchNodes accepts one preplanned tree group. It never scans whole levels.
func (s *Store) FetchNodes(ctx context.Context, epoch uint64, tree merkle.TreeID, positions []phv.NodeKey) ([]phv.Node, error) {
	result := make([]phv.Node, 0, len(positions))
	for _, key := range positions {
		if key.Tree != tree || key.Level < 0 || key.Index < 0 {
			return nil, fmt.Errorf("cassandra PHV: node outside requested tree")
		}
		var node phv.Node
		node.Key = key
		switch tree.Type {
		case merkle.TreeSegment:
			row, err := s.GetSegmentNode(ctx, SegmentKey{RegionID: tree.RegionID, ShardID: tree.ShardID, SegmentID: tree.SegmentID}, int32(key.Level), key.Index)
			if err != nil {
				return nil, err
			}
			node.Hash = row.Hash
		case merkle.TreeShard, merkle.TreeRegion, merkle.TreeGlobal:
			kind, rid, sid := "", tree.RegionID, tree.ShardID
			switch tree.Type {
			case merkle.TreeShard:
				kind = "SHARD"
			case merkle.TreeRegion:
				kind, sid = "REGION", -1
			case merkle.TreeGlobal:
				kind, rid, sid = "GLOBAL", "", -1
			}
			row, err := s.GetHierarchyNodeAt(ctx, kind, rid, sid, int32(key.Level), key.Index, epoch)
			if err != nil {
				return nil, err
			}
			node.Hash, node.VersionEpoch = row.Hash, uint64(row.VersionEpoch)
		default:
			return nil, fmt.Errorf("cassandra PHV: unsupported tree type %q", tree.Type)
		}
		result = append(result, node)
	}
	return result, nil
}
