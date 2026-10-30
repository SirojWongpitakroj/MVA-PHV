package postgresql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"

	"github.com/SirojWongpitakroj/mva-phv/internal/mpm"
)

var ErrCheckpointNotFound = errors.New("checkpoint not found")
var ErrCheckpointConflict = errors.New("checkpoint epoch already has a different commitment")

// MockCheckpointStore is the trusted append-only test checkpoint store.
// The application supplies a database/sql DB with a PostgreSQL driver.
type MockCheckpointStore struct{ db *sql.DB }

var _ mpm.CheckpointStore = (*MockCheckpointStore)(nil)

func NewMockCheckpointStore(db *sql.DB) (*MockCheckpointStore, error) {
	if db == nil {
		return nil, fmt.Errorf("PostgreSQL checkpoint store: DB is nil")
	}
	return &MockCheckpointStore{db: db}, nil
}

// Commit accepts an identical retry but rejects a different hash for an epoch.
func (s *MockCheckpointStore) Commit(ctx context.Context, epoch uint64, checkpoint [32]byte) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("PostgreSQL checkpoint store: not initialized")
	}
	if epoch > math.MaxInt64 {
		return fmt.Errorf("PostgreSQL checkpoint store: epoch exceeds bigint")
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO mock_checkpoints (epoch, checkpoint_hash)
		VALUES ($1, $2) ON CONFLICT (epoch) DO NOTHING`, int64(epoch), checkpoint[:])
	if err != nil {
		return fmt.Errorf("commit checkpoint: %w", err)
	}
	stored, err := s.GetCheckpoint(ctx, epoch)
	if err != nil {
		return fmt.Errorf("confirm checkpoint: %w", err)
	}
	if stored != checkpoint {
		return ErrCheckpointConflict
	}
	return nil
}

func (s *MockCheckpointStore) GetCheckpoint(ctx context.Context, epoch uint64) ([32]byte, error) {
	if s == nil || s.db == nil {
		return [32]byte{}, fmt.Errorf("PostgreSQL checkpoint store: not initialized")
	}
	if epoch > math.MaxInt64 {
		return [32]byte{}, fmt.Errorf("PostgreSQL checkpoint store: epoch exceeds bigint")
	}
	var raw []byte
	err := s.db.QueryRowContext(ctx, `SELECT checkpoint_hash FROM mock_checkpoints WHERE epoch = $1`, int64(epoch)).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return [32]byte{}, ErrCheckpointNotFound
	}
	if err != nil {
		return [32]byte{}, fmt.Errorf("get checkpoint: %w", err)
	}
	if len(raw) != 32 {
		return [32]byte{}, fmt.Errorf("get checkpoint: invalid hash length %d", len(raw))
	}
	var checkpoint [32]byte
	copy(checkpoint[:], raw)
	return checkpoint, nil
}
