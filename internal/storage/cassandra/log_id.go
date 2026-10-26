package cassandra

import (
	"context"
	"errors"
	"fmt"
	"uuid"
)

var ErrLogIDConflict = errors.New("cassandra: LogID already belongs to another physical address")

// ReserveLogID uses a Cassandra lightweight transaction. Identical retries
// are accepted, but the same LogID may never designate another HMF position.
func (s *Store) ReserveLogID(ctx context.Context, id uuid.UUID, key SegmentKey, leafID int64) error {
	if s == nil || s.client == nil {
		return fmt.Errorf("cassandra: nil store")
	}
	if id == (uuid.UUID{}) || key.RegionID == "" || key.ShardID < 0 || key.SegmentID < 0 || leafID < 0 {
		return fmt.Errorf("cassandra: invalid LogID reservation")
	}
	conditional, ok := s.client.(ConditionalClient)
	if !ok {
		return fmt.Errorf("cassandra: Client does not support conditional LogID writes")
	}
	applied, err := conditional.ExecIfNotExists(ctx, `INSERT INTO log_addresses_by_id
        (log_id,rid,sid,seg_id,leaf_id) VALUES (?,?,?,?,?) IF NOT EXISTS`,
		id, key.RegionID, key.ShardID, key.SegmentID, leafID)
	if err != nil {
		return fmt.Errorf("reserve LogID: %w", err)
	}
	if applied {
		return nil
	}
	var existing SegmentKey
	var existingLeaf int64
	err = s.one(ctx, `SELECT rid,sid,seg_id,leaf_id FROM log_addresses_by_id WHERE log_id=?`,
		[]any{id}, func(rows Rows) error {
			return rows.Scan(&existing.RegionID, &existing.ShardID, &existing.SegmentID, &existingLeaf)
		})
	if err != nil {
		return fmt.Errorf("read existing LogID reservation: %w", err)
	}
	if existing != key || existingLeaf != leafID {
		return ErrLogIDConflict
	}
	return nil
}
