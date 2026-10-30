package postgresql

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"sync"
	"testing"
)

type checkpointDriver struct{ state *checkpointState }
type checkpointState struct {
	mu     sync.Mutex
	values map[int64][]byte
}
type checkpointConn struct{ state *checkpointState }
type checkpointRows struct {
	value []byte
	read  bool
}

func (d checkpointDriver) Open(string) (driver.Conn, error) {
	return &checkpointConn{state: d.state}, nil
}
func (c *checkpointConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not used") }
func (c *checkpointConn) Close() error                        { return nil }
func (c *checkpointConn) Begin() (driver.Tx, error)           { return nil, errors.New("not used") }
func (c *checkpointConn) ExecContext(_ context.Context, _ string, args []driver.NamedValue) (driver.Result, error) {
	epoch := args[0].Value.(int64)
	hash := args[1].Value.([]byte)
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	if _, exists := c.state.values[epoch]; !exists {
		c.state.values[epoch] = append([]byte(nil), hash...)
	}
	return driver.RowsAffected(1), nil
}
func (c *checkpointConn) QueryContext(_ context.Context, _ string, args []driver.NamedValue) (driver.Rows, error) {
	epoch := args[0].Value.(int64)
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	return &checkpointRows{value: append([]byte(nil), c.state.values[epoch]...)}, nil
}
func (r *checkpointRows) Columns() []string { return []string{"checkpoint_hash"} }
func (r *checkpointRows) Close() error      { return nil }
func (r *checkpointRows) Next(dest []driver.Value) error {
	if r.read || r.value == nil {
		return io.EOF
	}
	r.read = true
	dest[0] = r.value
	return nil
}

func TestMockCheckpointStoreAppendOnly(t *testing.T) {
	state := &checkpointState{values: make(map[int64][]byte)}
	sql.Register("test-checkpoints", checkpointDriver{state: state})
	db, err := sql.Open("test-checkpoints", "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store, err := NewMockCheckpointStore(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := store.GetCheckpoint(ctx, 1); !errors.Is(err, ErrCheckpointNotFound) {
		t.Fatalf("missing epoch: %v", err)
	}
	first := [32]byte{1}
	if err := store.Commit(ctx, 1, first); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(ctx, 1, first); err != nil {
		t.Fatalf("same checkpoint retry: %v", err)
	}
	if err := store.Commit(ctx, 1, [32]byte{2}); !errors.Is(err, ErrCheckpointConflict) {
		t.Fatalf("conflict: %v", err)
	}
	if got, err := store.GetCheckpoint(ctx, 1); err != nil || got != first {
		t.Fatalf("historical checkpoint changed: %x, %v", got, err)
	}
}
