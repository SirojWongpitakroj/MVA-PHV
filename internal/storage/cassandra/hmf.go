package cassandra

import (
	"context"
	"fmt"
)

func (s *Store) PutLog(ctx context.Context, r LogRecord) error {
	if r.LeafID < 0 || r.ShardID < 0 || r.SegmentID < 0 {
		return fmt.Errorf("cassandra: invalid log address")
	}
	return s.exec(ctx, `INSERT INTO logs_by_segment
        (rid,sid,seg_id,leaf_id,log_id,site_id,device_id,event_type,event_ts_ns,
         ciphertext,nonce,tag,associated_data,digest,locator_commitment,
         hmf_leaf_commitment,ingested_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.RegionID, r.ShardID, r.SegmentID, r.LeafID, r.LogID,
		r.SiteID, r.DeviceID, r.EventType, r.EventTSNS,
		r.Ciphertext, r.Nonce, r.Tag, r.AssociatedData, r.Digest[:],
		r.LocatorCommitment[:], r.HMFLeafCommitment[:], r.IngestedAt)
}

func (s *Store) GetLog(ctx context.Context, key SegmentKey, leafID int64) (r LogRecord, err error) {
	r.SegmentKey, r.LeafID = key, leafID
	var digest, locator, commitment []byte
	err = s.one(ctx, `SELECT log_id,site_id,device_id,event_type,event_ts_ns,
        ciphertext,nonce,tag,associated_data,digest,locator_commitment,
        hmf_leaf_commitment,ingested_at FROM logs_by_segment
        WHERE rid=? AND sid=? AND seg_id=? AND leaf_id=?`,
		[]any{key.RegionID, key.ShardID, key.SegmentID, leafID}, func(rows Rows) error {
			return rows.Scan(&r.LogID, &r.SiteID, &r.DeviceID, &r.EventType, &r.EventTSNS,
				&r.Ciphertext, &r.Nonce, &r.Tag, &r.AssociatedData,
				&digest, &locator, &commitment, &r.IngestedAt)
		})
	if err != nil {
		return r, err
	}
	if r.Digest, err = parseHash(digest, "digest"); err != nil {
		return r, err
	}
	if r.LocatorCommitment, err = parseHash(locator, "locator commitment"); err != nil {
		return r, err
	}
	if r.HMFLeafCommitment, err = parseHash(commitment, "HMF leaf commitment"); err != nil {
		return r, err
	}
	r.Ciphertext, r.Nonce, r.Tag, r.AssociatedData = blob(r.Ciphertext), blob(r.Nonce), blob(r.Tag), blob(r.AssociatedData)
	return r, nil
}

func (s *Store) PutActiveSegment(ctx context.Context, r ActiveSegment) error {
	if r.ShardID < 0 || r.NextSegmentID < 0 || r.SegmentID == nil ||
		r.OpenedAtNS == nil || r.LeafCount == nil || *r.SegmentID < 0 ||
		*r.LeafCount < 0 || r.NextSegmentID <= *r.SegmentID {
		return fmt.Errorf("cassandra: invalid active Shard")
	}
	return s.exec(ctx, `INSERT INTO hmf_active_segments_by_shard
        (rid,sid,seg_id,opened_at_ns,leaf_count,next_seg_id) VALUES (?,?,?,?,?,?)`,
		r.RegionID, r.ShardID, *r.SegmentID, *r.OpenedAtNS, *r.LeafCount, r.NextSegmentID)
}

// ClearActiveSegment preserves the next ID while removing the sealed Segment's
// mutable recovery fields in one row mutation.
func (s *Store) ClearActiveSegment(ctx context.Context, rid string, sid, nextSegmentID int64) error {
	if sid < 0 || nextSegmentID < 0 {
		return fmt.Errorf("cassandra: invalid active Shard")
	}
	return s.exec(ctx, `UPDATE hmf_active_segments_by_shard
        SET seg_id=null,opened_at_ns=null,leaf_count=null,next_seg_id=?
        WHERE rid=? AND sid=?`, nextSegmentID, rid, sid)
}

func (s *Store) GetActiveSegment(ctx context.Context, rid string, sid int64) (r ActiveSegment, err error) {
	r.RegionID, r.ShardID = rid, sid
	err = s.one(ctx, `SELECT seg_id,opened_at_ns,leaf_count,next_seg_id
        FROM hmf_active_segments_by_shard WHERE rid=? AND sid=?`,
		[]any{rid, sid}, func(rows Rows) error {
			return rows.Scan(&r.SegmentID, &r.OpenedAtNS, &r.LeafCount, &r.NextSegmentID)
		})
	return r, err
}

func (s *Store) PutSealedSegment(ctx context.Context, r SealedSegment) error {
	if r.ShardID < 0 || r.SegmentID < 0 || r.LeafCount <= 0 || r.TreeHeight < 0 ||
		r.MaxLeaves <= 0 || r.FinalizedEpoch != nil {
		return fmt.Errorf("cassandra: invalid sealed Segment metadata")
	}
	return s.exec(ctx, `INSERT INTO hmf_segments_by_shard
        (rid,sid,seg_id,segment_root,leaf_count,tree_height,max_leaves,
         opened_at_ns,sealed_at_ns,persisted_at)
        VALUES (?,?,?,?,?,?,?,?,?,?)`,
		r.RegionID, r.ShardID, r.SegmentID, r.Root[:], r.LeafCount,
		r.TreeHeight, r.MaxLeaves, r.OpenedAtNS, r.SealedAtNS,
		r.PersistedAt)
}

// MarkSegmentFinalized is called only after trusted checkpoint publication.
// It records inclusion epoch as a lookup hint; PostgreSQL remains authoritative.
func (s *Store) MarkSegmentFinalized(ctx context.Context, key SegmentKey, epoch uint64) error {
	e, err := signedEpoch(epoch)
	if err != nil {
		return err
	}
	return s.exec(ctx, `UPDATE hmf_segments_by_shard SET finalized_epoch=?
        WHERE rid=? AND sid=? AND seg_id=?`,
		e, key.RegionID, key.ShardID, key.SegmentID)
}

func (s *Store) GetSealedSegment(ctx context.Context, key SegmentKey) (r SealedSegment, err error) {
	r.SegmentKey = key
	var root []byte
	err = s.one(ctx, `SELECT segment_root,leaf_count,tree_height,max_leaves,
        opened_at_ns,sealed_at_ns,finalized_epoch,persisted_at
        FROM hmf_segments_by_shard WHERE rid=? AND sid=? AND seg_id=?`,
		[]any{key.RegionID, key.ShardID, key.SegmentID}, func(rows Rows) error {
			return rows.Scan(&root, &r.LeafCount, &r.TreeHeight, &r.MaxLeaves,
				&r.OpenedAtNS, &r.SealedAtNS, &r.FinalizedEpoch, &r.PersistedAt)
		})
	if err != nil {
		return r, err
	}
	r.Root, err = parseHash(root, "Segment root")
	return r, err
}

func (s *Store) PutSegmentNode(ctx context.Context, key SegmentKey, n MerkleNodeRecord) error {
	if n.Level < 0 || n.Index < 0 {
		return fmt.Errorf("cassandra: invalid Segment node")
	}
	return s.exec(ctx, `INSERT INTO hmf_segment_nodes
        (rid,sid,seg_id,level,node_index,node_hash) VALUES (?,?,?,?,?,?)`,
		key.RegionID, key.ShardID, key.SegmentID, n.Level, n.Index, n.Hash[:])
}

func (s *Store) GetSegmentNodes(ctx context.Context, key SegmentKey) (nodes []MerkleNodeRecord, err error) {
	err = s.each(ctx, `SELECT level,node_index,node_hash FROM hmf_segment_nodes
        WHERE rid=? AND sid=? AND seg_id=?`,
		[]any{key.RegionID, key.ShardID, key.SegmentID}, func(rows Rows) error {
			var n MerkleNodeRecord
			var hash []byte
			if err := rows.Scan(&n.Level, &n.Index, &hash); err != nil {
				return err
			}
			var err error
			if n.Hash, err = parseHash(hash, "Segment node hash"); err != nil {
				return err
			}
			nodes = append(nodes, n)
			return nil
		})
	return nodes, err
}

func hierarchyID(kind, rid string, sid int64) (string, int64, error) {
	switch kind {
	case "SHARD":
		if rid == "" || sid < 0 {
			return "", 0, fmt.Errorf("cassandra: invalid Shard tree ID")
		}
		return rid, sid, nil
	case "REGION":
		if rid == "" {
			return "", 0, fmt.Errorf("cassandra: invalid Region tree ID")
		}
		return rid, -1, nil
	case "GLOBAL":
		return "", -1, nil
	default:
		return "", 0, fmt.Errorf("cassandra: unsupported tree kind %q", kind)
	}
}

func (s *Store) PutHierarchyNode(ctx context.Context, r HierarchyNode) error {
	rid, sid, err := hierarchyID(r.Kind, r.RegionID, r.ShardID)
	if err != nil {
		return err
	}
	bucket, err := nodeBucket(r.Index)
	if err != nil {
		return err
	}
	if r.Level < 0 || r.VersionEpoch < 0 {
		return fmt.Errorf("cassandra: invalid hierarchy node level or epoch")
	}
	return s.exec(ctx, `INSERT INTO hmf_hierarchy_nodes
        (tree_kind,rid,sid,level,node_bucket,node_index,version_epoch,node_hash)
        VALUES (?,?,?,?,?,?,?,?)`,
		r.Kind, rid, sid, r.Level, bucket, r.Index, r.VersionEpoch, r.Hash[:])
}

func (s *Store) GetHierarchyNodeAt(ctx context.Context, kind, rid string, sid int64, level int32, index int64, epoch uint64) (r HierarchyNode, err error) {
	if level < 0 {
		return r, fmt.Errorf("cassandra: negative hierarchy node level")
	}
	rid, sid, err = hierarchyID(kind, rid, sid)
	if err != nil {
		return r, err
	}
	bucket, err := nodeBucket(index)
	if err != nil {
		return r, err
	}
	e, err := signedEpoch(epoch)
	if err != nil {
		return r, err
	}
	r.Kind, r.RegionID, r.ShardID, r.Level, r.Index = kind, rid, sid, level, index
	var hash []byte
	err = s.one(ctx, `SELECT version_epoch,node_hash FROM hmf_hierarchy_nodes
        WHERE tree_kind=? AND rid=? AND sid=? AND level=? AND node_bucket=?
        AND node_index=? AND version_epoch<=? LIMIT 1`,
		[]any{kind, rid, sid, level, bucket, index, e}, func(rows Rows) error {
			return rows.Scan(&r.VersionEpoch, &hash)
		})
	if err != nil {
		return r, err
	}
	r.Hash, err = parseHash(hash, "hierarchy node hash")
	return r, err
}

func (s *Store) PutShardState(ctx context.Context, r ShardState) error {
	if r.Epoch < 0 || r.ShardID < 0 || r.SegmentCount < 0 || r.TreeHeight < 0 {
		return fmt.Errorf("cassandra: invalid Shard state")
	}
	if _, err := DecodeFrontier(r.FrontierData); err != nil {
		return err
	}
	return s.exec(ctx, `INSERT INTO hmf_shard_state_by_epoch
        (rid,sid,epoch,shard_root,segment_count,tree_height,frontier_data)
        VALUES (?,?,?,?,?,?,?)`,
		r.RegionID, r.ShardID, r.Epoch, r.Root[:], r.SegmentCount, r.TreeHeight, r.FrontierData)
}

func (s *Store) GetShardStateAt(ctx context.Context, rid string, sid int64, epoch uint64) (r ShardState, err error) {
	e, err := signedEpoch(epoch)
	if err != nil {
		return r, err
	}
	r.RegionID, r.ShardID = rid, sid
	var root []byte
	err = s.one(ctx, `SELECT epoch,shard_root,segment_count,tree_height,frontier_data
        FROM hmf_shard_state_by_epoch WHERE rid=? AND sid=? AND epoch<=? LIMIT 1`,
		[]any{rid, sid, e}, func(rows Rows) error {
			return rows.Scan(&r.Epoch, &root, &r.SegmentCount, &r.TreeHeight, &r.FrontierData)
		})
	if err != nil {
		return r, err
	}
	if r.Root, err = parseHash(root, "Shard root"); err != nil {
		return r, err
	}
	r.FrontierData = blob(r.FrontierData)
	if _, err := DecodeFrontier(r.FrontierData); err != nil {
		return r, err
	}
	return r, nil
}

func (s *Store) PutRegionState(ctx context.Context, r RegionState) error {
	if r.Epoch < 0 || r.ShardCount < 0 || r.TreeHeight < 0 {
		return fmt.Errorf("cassandra: invalid Region state")
	}
	return s.exec(ctx, `INSERT INTO hmf_region_state_by_epoch
        (rid,epoch,region_root,shard_count,tree_height) VALUES (?,?,?,?,?)`,
		r.RegionID, r.Epoch, r.Root[:], r.ShardCount, r.TreeHeight)
}

func (s *Store) GetRegionStateAt(ctx context.Context, rid string, epoch uint64) (r RegionState, err error) {
	e, err := signedEpoch(epoch)
	if err != nil {
		return r, err
	}
	r.RegionID = rid
	var root []byte
	err = s.one(ctx, `SELECT epoch,region_root,shard_count,tree_height
        FROM hmf_region_state_by_epoch WHERE rid=? AND epoch<=? LIMIT 1`,
		[]any{rid, e}, func(rows Rows) error {
			return rows.Scan(&r.Epoch, &root, &r.ShardCount, &r.TreeHeight)
		})
	if err != nil {
		return r, err
	}
	r.Root, err = parseHash(root, "Region root")
	return r, err
}

func (s *Store) PutGlobalState(ctx context.Context, r GlobalState) error {
	if r.Scope == "" || r.Epoch < 0 || r.RegionCount < 0 || r.TreeHeight < 0 {
		return fmt.Errorf("cassandra: invalid Global state")
	}
	return s.exec(ctx, `INSERT INTO hmf_global_state_by_epoch
        (scope,epoch,global_root,region_count,tree_height) VALUES (?,?,?,?,?)`,
		r.Scope, r.Epoch, r.Root[:], r.RegionCount, r.TreeHeight)
}

func (s *Store) GetGlobalState(ctx context.Context, scope string, epoch uint64) (r GlobalState, err error) {
	e, err := signedEpoch(epoch)
	if err != nil {
		return r, err
	}
	r.Scope, r.Epoch = scope, e
	var root []byte
	err = s.one(ctx, `SELECT global_root,region_count,tree_height
        FROM hmf_global_state_by_epoch WHERE scope=? AND epoch=?`,
		[]any{scope, e}, func(rows Rows) error {
			return rows.Scan(&root, &r.RegionCount, &r.TreeHeight)
		})
	if err != nil {
		return r, err
	}
	r.Root, err = parseHash(root, "Global root")
	return r, err
}
