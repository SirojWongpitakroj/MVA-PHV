package cassandra

import (
	"context"
	"fmt"
)

func validView(view string) error {
	if view != "id" && view != "attribute" {
		return fmt.Errorf("cassandra: invalid MVA view %q", view)
	}
	return nil
}

func (s *Store) PutPage(ctx context.Context, r PageVersion) error {
	if err := validView(r.View); err != nil {
		return err
	}
	bucket, err := pageBucket(r.PageID)
	if err != nil {
		return err
	}
	if r.VersionEpoch < 0 {
		return fmt.Errorf("cassandra: negative page epoch")
	}
	if _, err := r.DecodePageData(); err != nil {
		return err
	}
	return s.exec(ctx, `INSERT INTO mva_pages
        (rid,view,page_bucket,page_id,version_epoch,is_leaf,parent_page_id,
         prev_page_id,next_page_id,page_hash,page_data)
        VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		r.RegionID, r.View, bucket, r.PageID, r.VersionEpoch, r.IsLeaf,
		r.ParentPageID, r.PrevPageID, r.NextPageID, r.Hash[:], r.Data)
}

func (s *Store) GetPageAt(ctx context.Context, rid, view string, pageID int64, epoch uint64) (r PageVersion, err error) {
	if err := validView(view); err != nil {
		return r, err
	}
	bucket, err := pageBucket(pageID)
	if err != nil {
		return r, err
	}
	e, err := signedEpoch(epoch)
	if err != nil {
		return r, err
	}
	r.RegionID, r.View, r.PageID = rid, view, pageID
	var hash []byte
	err = s.one(ctx, `SELECT version_epoch,is_leaf,parent_page_id,prev_page_id,
        next_page_id,page_hash,page_data FROM mva_pages
        WHERE rid=? AND view=? AND page_bucket=? AND page_id=?
        AND version_epoch<=? LIMIT 1`,
		[]any{rid, view, bucket, pageID, e}, func(rows Rows) error {
			return rows.Scan(&r.VersionEpoch, &r.IsLeaf, &r.ParentPageID,
				&r.PrevPageID, &r.NextPageID, &hash, &r.Data)
		})
	if err != nil {
		return r, err
	}
	if r.Hash, err = parseHash(hash, "MVA page hash"); err != nil {
		return r, err
	}
	r.Data = blob(r.Data)
	if _, err := r.DecodePageData(); err != nil {
		return r, err
	}
	return r, nil
}

func (s *Store) PutWorkingViewState(ctx context.Context, r ViewState) error {
	if err := validView(r.View); err != nil {
		return err
	}
	if r.Epoch < 0 || r.RootPageID < 0 || r.NextPageID < 0 || r.RecordCount < 0 || r.TreeHeight < 0 || r.TreeOrder <= 0 {
		return fmt.Errorf("cassandra: invalid working MVA view state")
	}
	return s.exec(ctx, `INSERT INTO mva_working_view_state
        (rid,view,working_epoch,root_page_id,root_hash,tree_height,
         record_count,next_page_id,tree_order) VALUES (?,?,?,?,?,?,?,?,?)`,
		r.RegionID, r.View, r.Epoch, r.RootPageID, r.RootHash[:],
		r.TreeHeight, r.RecordCount, r.NextPageID, r.TreeOrder)
}

func (s *Store) GetWorkingViewState(ctx context.Context, rid, view string) (r ViewState, err error) {
	if err := validView(view); err != nil {
		return r, err
	}
	r.RegionID, r.View = rid, view
	var root []byte
	err = s.one(ctx, `SELECT working_epoch,root_page_id,root_hash,tree_height,
        record_count,next_page_id,tree_order FROM mva_working_view_state
        WHERE rid=? AND view=?`,
		[]any{rid, view}, func(rows Rows) error {
			return rows.Scan(&r.Epoch, &r.RootPageID, &root, &r.TreeHeight,
				&r.RecordCount, &r.NextPageID, &r.TreeOrder)
		})
	if err != nil {
		return r, err
	}
	r.RootHash, err = parseHash(root, "working MVA view root")
	return r, err
}

func (s *Store) PutViewState(ctx context.Context, r ViewState) error {
	if err := validView(r.View); err != nil {
		return err
	}
	if r.Epoch < 0 || r.RootPageID < 0 || r.NextPageID < 0 || r.RecordCount < 0 || r.TreeHeight < 0 || r.TreeOrder <= 0 {
		return fmt.Errorf("cassandra: invalid finalized MVA view state")
	}
	return s.exec(ctx, `INSERT INTO mva_region_view_state_by_epoch
        (rid,view,epoch,root_page_id,root_hash,tree_height,
         record_count,next_page_id,tree_order) VALUES (?,?,?,?,?,?,?,?,?)`,
		r.RegionID, r.View, r.Epoch, r.RootPageID, r.RootHash[:],
		r.TreeHeight, r.RecordCount, r.NextPageID, r.TreeOrder)
}

func (s *Store) GetViewStateAt(ctx context.Context, rid, view string, epoch uint64) (r ViewState, err error) {
	if err := validView(view); err != nil {
		return r, err
	}
	e, err := signedEpoch(epoch)
	if err != nil {
		return r, err
	}
	r.RegionID, r.View = rid, view
	var root []byte
	err = s.one(ctx, `SELECT epoch,root_page_id,root_hash,tree_height,
        record_count,next_page_id,tree_order FROM mva_region_view_state_by_epoch
        WHERE rid=? AND view=? AND epoch<=? LIMIT 1`,
		[]any{rid, view, e}, func(rows Rows) error {
			return rows.Scan(&r.Epoch, &r.RootPageID, &root, &r.TreeHeight,
				&r.RecordCount, &r.NextPageID, &r.TreeOrder)
		})
	if err != nil {
		return r, err
	}
	r.RootHash, err = parseHash(root, "MVA view root")
	return r, err
}

func (s *Store) PutMVARegionCommitment(ctx context.Context, r MVARegionCommitment) error {
	if r.Epoch < 0 || r.RegionIndex < 0 {
		return fmt.Errorf("cassandra: invalid MVA Region commitment")
	}
	return s.exec(ctx, `INSERT INTO mva_region_commitments_by_epoch
        (epoch,region_index,rid,id_root,attr_root,region_root)
        VALUES (?,?,?,?,?,?)`,
		r.Epoch, r.RegionIndex, r.RegionID, r.IDRoot[:], r.AttrRoot[:], r.RegionRoot[:])
}

func (s *Store) ListMVARegionCommitments(ctx context.Context, epoch uint64) (out []MVARegionCommitment, err error) {
	e, err := signedEpoch(epoch)
	if err != nil {
		return nil, err
	}
	err = s.each(ctx, `SELECT region_index,rid,id_root,attr_root,region_root
        FROM mva_region_commitments_by_epoch WHERE epoch=?`, []any{e}, func(rows Rows) error {
		var r MVARegionCommitment
		r.Epoch = e
		var id, attr, region []byte
		if err := rows.Scan(&r.RegionIndex, &r.RegionID, &id, &attr, &region); err != nil {
			return err
		}
		var err error
		if r.IDRoot, err = parseHash(id, "MVA ID root"); err != nil {
			return err
		}
		if r.AttrRoot, err = parseHash(attr, "MVA attribute root"); err != nil {
			return err
		}
		if r.RegionRoot, err = parseHash(region, "MVA Region root"); err != nil {
			return err
		}
		out = append(out, r)
		return nil
	})
	return out, err
}

func (s *Store) PutMVAGlobalNode(ctx context.Context, r EpochNode) error {
	if r.Epoch < 0 || r.Level < 0 || r.Index < 0 {
		return fmt.Errorf("cassandra: invalid MVA Global node")
	}
	return s.exec(ctx, `INSERT INTO mva_global_nodes_by_epoch
        (epoch,level,node_index,node_hash) VALUES (?,?,?,?)`,
		r.Epoch, r.Level, r.Index, r.Hash[:])
}

func (s *Store) ListMVAGlobalNodes(ctx context.Context, epoch uint64) (out []EpochNode, err error) {
	e, err := signedEpoch(epoch)
	if err != nil {
		return nil, err
	}
	err = s.each(ctx, `SELECT level,node_index,node_hash FROM mva_global_nodes_by_epoch
        WHERE epoch=?`, []any{e}, func(rows Rows) error {
		var r EpochNode
		r.Epoch = e
		var hash []byte
		if err := rows.Scan(&r.Level, &r.Index, &hash); err != nil {
			return err
		}
		var err error
		if r.Hash, err = parseHash(hash, "MVA Global node"); err != nil {
			return err
		}
		out = append(out, r)
		return nil
	})
	return out, err
}

func (s *Store) PutMVARoot(ctx context.Context, epoch uint64, root [32]byte) error {
	e, err := signedEpoch(epoch)
	if err != nil {
		return err
	}
	return s.exec(ctx, `INSERT INTO mva_epoch_roots (epoch,mva_root) VALUES (?,?)`, e, root[:])
}

func (s *Store) GetMVARoot(ctx context.Context, epoch uint64) (root [32]byte, err error) {
	e, err := signedEpoch(epoch)
	if err != nil {
		return root, err
	}
	var data []byte
	err = s.one(ctx, `SELECT mva_root FROM mva_epoch_roots WHERE epoch=?`, []any{e}, func(rows Rows) error {
		return rows.Scan(&data)
	})
	if err != nil {
		return root, err
	}
	return parseHash(data, "MVA root")
}
