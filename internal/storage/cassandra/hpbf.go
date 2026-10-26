package cassandra

import (
	"context"
	"fmt"
)

func (s *Store) PutWorkingShardFilter(ctx context.Context, f FilterRecord) error {
	if f.ShardID < 0 || f.Epoch < 0 {
		return fmt.Errorf("cassandra: invalid working HPBF key")
	}
	if err := f.Validate(); err != nil {
		return err
	}
	return s.exec(ctx, `INSERT INTO hpbf_working_shard_filters
        (rid,sid,working_epoch,bit_count,hash_count,filter_bits)
        VALUES (?,?,?,?,?,?)`,
		f.RegionID, f.ShardID, f.Epoch, f.BitCount, f.HashCount, f.Bits)
}

func (s *Store) GetWorkingShardFilter(ctx context.Context, rid string, sid int64) (f FilterRecord, err error) {
	f.RegionID, f.ShardID = rid, sid
	err = s.one(ctx, `SELECT working_epoch,bit_count,hash_count,filter_bits
        FROM hpbf_working_shard_filters WHERE rid=? AND sid=?`,
		[]any{rid, sid}, func(rows Rows) error {
			return rows.Scan(&f.Epoch, &f.BitCount, &f.HashCount, &f.Bits)
		})
	if err != nil {
		return f, err
	}
	f.Bits = blob(f.Bits)
	return f, f.Validate()
}

func (s *Store) PutShardFilterVersion(ctx context.Context, f FilterRecord) error {
	if f.ShardID < 0 || f.Epoch < 0 {
		return fmt.Errorf("cassandra: invalid HPBF filter version key")
	}
	if err := f.Validate(); err != nil {
		return err
	}
	return s.exec(ctx, `INSERT INTO hpbf_shard_filter_versions
        (rid,sid,version_epoch,bit_count,hash_count,filter_bits)
        VALUES (?,?,?,?,?,?)`,
		f.RegionID, f.ShardID, f.Epoch, f.BitCount, f.HashCount, f.Bits)
}

func (s *Store) GetShardFilterAt(ctx context.Context, rid string, sid int64, epoch uint64) (f FilterRecord, err error) {
	e, err := signedEpoch(epoch)
	if err != nil {
		return f, err
	}
	f.RegionID, f.ShardID = rid, sid
	err = s.one(ctx, `SELECT version_epoch,bit_count,hash_count,filter_bits
        FROM hpbf_shard_filter_versions
        WHERE rid=? AND sid=? AND version_epoch<=? LIMIT 1`,
		[]any{rid, sid, e}, func(rows Rows) error {
			return rows.Scan(&f.Epoch, &f.BitCount, &f.HashCount, &f.Bits)
		})
	if err != nil {
		return f, err
	}
	f.Bits = blob(f.Bits)
	return f, f.Validate()
}

// GetShardFilterVersion fetches exactly the version named by the epoch's
// Shard commitment manifest, rather than assuming the latest <= epoch.
func (s *Store) GetShardFilterVersion(ctx context.Context, rid string, sid, versionEpoch int64) (f FilterRecord, err error) {
	if versionEpoch < 0 {
		return f, fmt.Errorf("cassandra: negative HPBF filter version")
	}
	f.RegionID, f.ShardID, f.Epoch = rid, sid, versionEpoch
	err = s.one(ctx, `SELECT bit_count,hash_count,filter_bits
        FROM hpbf_shard_filter_versions
        WHERE rid=? AND sid=? AND version_epoch=?`,
		[]any{rid, sid, versionEpoch}, func(rows Rows) error {
			return rows.Scan(&f.BitCount, &f.HashCount, &f.Bits)
		})
	if err != nil {
		return f, err
	}
	f.Bits = blob(f.Bits)
	return f, f.Validate()
}

func (s *Store) PutHPBFShardCommitment(ctx context.Context, r HPBFShardCommitment) error {
	if r.Epoch < 0 || r.ShardID < 0 || r.ShardIndex < 0 ||
		r.FilterVersionEpoch < 0 || r.FilterVersionEpoch > r.Epoch {
		return fmt.Errorf("cassandra: invalid HPBF Shard commitment")
	}
	return s.exec(ctx, `INSERT INTO hpbf_shard_commitments_by_epoch
        (epoch,rid,sid,shard_index,filter_version_epoch,shard_commitment)
        VALUES (?,?,?,?,?,?)`,
		r.Epoch, r.RegionID, r.ShardID, r.ShardIndex,
		r.FilterVersionEpoch, r.Commitment[:])
}

func (s *Store) ListHPBFShardCommitments(ctx context.Context, epoch uint64, rid string) (out []HPBFShardCommitment, err error) {
	e, err := signedEpoch(epoch)
	if err != nil {
		return nil, err
	}
	err = s.each(ctx, `SELECT sid,shard_index,filter_version_epoch,shard_commitment
        FROM hpbf_shard_commitments_by_epoch WHERE epoch=? AND rid=?`,
		[]any{e, rid}, func(rows Rows) error {
			var r HPBFShardCommitment
			r.Epoch, r.RegionID = e, rid
			var hash []byte
			if err := rows.Scan(&r.ShardID, &r.ShardIndex, &r.FilterVersionEpoch, &hash); err != nil {
				return err
			}
			if r.FilterVersionEpoch < 0 || r.FilterVersionEpoch > e {
				return fmt.Errorf("cassandra: invalid HPBF filter version in manifest")
			}
			var err error
			if r.Commitment, err = parseHash(hash, "HPBF Shard commitment"); err != nil {
				return err
			}
			out = append(out, r)
			return nil
		})
	return out, err
}

func (s *Store) PutHPBFRegionFilter(ctx context.Context, f FilterRecord) error {
	if f.Epoch < 0 {
		return fmt.Errorf("cassandra: negative HPBF Region filter epoch")
	}
	if err := f.Validate(); err != nil {
		return err
	}
	return s.exec(ctx, `INSERT INTO hpbf_region_filters_by_epoch
        (rid,epoch,bit_count,hash_count,filter_bits) VALUES (?,?,?,?,?)`,
		f.RegionID, f.Epoch, f.BitCount, f.HashCount, f.Bits)
}

func (s *Store) GetHPBFRegionFilter(ctx context.Context, rid string, epoch uint64) (f FilterRecord, err error) {
	e, err := signedEpoch(epoch)
	if err != nil {
		return f, err
	}
	f.RegionID, f.Epoch = rid, e
	err = s.one(ctx, `SELECT bit_count,hash_count,filter_bits
        FROM hpbf_region_filters_by_epoch WHERE rid=? AND epoch=?`,
		[]any{rid, e}, func(rows Rows) error {
			return rows.Scan(&f.BitCount, &f.HashCount, &f.Bits)
		})
	if err != nil {
		return f, err
	}
	f.Bits = blob(f.Bits)
	return f, f.Validate()
}

// Region filters are derived caches. Audit code must verify that the filter is
// the OR of the authenticated Shard filters before using it to exclude a Region.
func (s *Store) PutHPBFRegionNode(ctx context.Context, rid string, r EpochNode) error {
	if r.Epoch < 0 || r.Level < 0 || r.Index < 0 {
		return fmt.Errorf("cassandra: invalid HPBF Region node")
	}
	return s.exec(ctx, `INSERT INTO hpbf_region_nodes_by_epoch
        (epoch,rid,level,node_index,node_hash) VALUES (?,?,?,?,?)`,
		r.Epoch, rid, r.Level, r.Index, r.Hash[:])
}

func (s *Store) ListHPBFRegionNodes(ctx context.Context, rid string, epoch uint64) (out []EpochNode, err error) {
	e, err := signedEpoch(epoch)
	if err != nil {
		return nil, err
	}
	err = s.each(ctx, `SELECT level,node_index,node_hash FROM hpbf_region_nodes_by_epoch
        WHERE epoch=? AND rid=?`, []any{e, rid}, func(rows Rows) error {
		var r EpochNode
		r.Epoch = e
		var hash []byte
		if err := rows.Scan(&r.Level, &r.Index, &hash); err != nil {
			return err
		}
		var err error
		if r.Hash, err = parseHash(hash, "HPBF Region node"); err != nil {
			return err
		}
		out = append(out, r)
		return nil
	})
	return out, err
}

func (s *Store) PutHPBFRegionRoot(ctx context.Context, r HPBFRegionRoot) error {
	if r.Epoch < 0 || r.RegionIndex < 0 {
		return fmt.Errorf("cassandra: invalid HPBF Region root")
	}
	return s.exec(ctx, `INSERT INTO hpbf_region_roots_by_epoch
        (epoch,region_index,rid,region_root) VALUES (?,?,?,?)`,
		r.Epoch, r.RegionIndex, r.RegionID, r.Root[:])
}

func (s *Store) ListHPBFRegionRoots(ctx context.Context, epoch uint64) (out []HPBFRegionRoot, err error) {
	e, err := signedEpoch(epoch)
	if err != nil {
		return nil, err
	}
	err = s.each(ctx, `SELECT region_index,rid,region_root FROM hpbf_region_roots_by_epoch
        WHERE epoch=?`, []any{e}, func(rows Rows) error {
		var r HPBFRegionRoot
		r.Epoch = e
		var hash []byte
		if err := rows.Scan(&r.RegionIndex, &r.RegionID, &hash); err != nil {
			return err
		}
		var err error
		if r.Root, err = parseHash(hash, "HPBF Region root"); err != nil {
			return err
		}
		out = append(out, r)
		return nil
	})
	return out, err
}

func (s *Store) PutHPBFGlobalNode(ctx context.Context, r EpochNode) error {
	if r.Epoch < 0 || r.Level < 0 || r.Index < 0 {
		return fmt.Errorf("cassandra: invalid HPBF Global node")
	}
	return s.exec(ctx, `INSERT INTO hpbf_global_nodes_by_epoch
        (epoch,level,node_index,node_hash) VALUES (?,?,?,?)`,
		r.Epoch, r.Level, r.Index, r.Hash[:])
}

func (s *Store) ListHPBFGlobalNodes(ctx context.Context, epoch uint64) (out []EpochNode, err error) {
	e, err := signedEpoch(epoch)
	if err != nil {
		return nil, err
	}
	err = s.each(ctx, `SELECT level,node_index,node_hash FROM hpbf_global_nodes_by_epoch
        WHERE epoch=?`, []any{e}, func(rows Rows) error {
		var r EpochNode
		r.Epoch = e
		var hash []byte
		if err := rows.Scan(&r.Level, &r.Index, &hash); err != nil {
			return err
		}
		var err error
		if r.Hash, err = parseHash(hash, "HPBF Global node"); err != nil {
			return err
		}
		out = append(out, r)
		return nil
	})
	return out, err
}

func (s *Store) PutHPBFRoot(ctx context.Context, epoch uint64, root [32]byte) error {
	e, err := signedEpoch(epoch)
	if err != nil {
		return err
	}
	return s.exec(ctx, `INSERT INTO hpbf_epoch_roots (epoch,hpbf_root) VALUES (?,?)`, e, root[:])
}

func (s *Store) GetHPBFRoot(ctx context.Context, epoch uint64) (root [32]byte, err error) {
	e, err := signedEpoch(epoch)
	if err != nil {
		return root, err
	}
	var data []byte
	err = s.one(ctx, `SELECT hpbf_root FROM hpbf_epoch_roots WHERE epoch=?`, []any{e}, func(rows Rows) error {
		return rows.Scan(&data)
	})
	if err != nil {
		return root, err
	}
	return parseHash(data, "HPBF root")
}
