package placement

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type cursorValue struct {
	signature string
	next      int64
}
type placementData struct {
	cursors map[string]cursorValue
	sites   map[string]string
	devices map[string]int64
}

func newPlacementData() placementData {
	return placementData{make(map[string]cursorValue), make(map[string]string), make(map[string]int64)}
}
func (d placementData) clone() placementData {
	out := newPlacementData()
	for k, v := range d.cursors {
		out.cursors[k] = v
	}
	for k, v := range d.sites {
		out.sites[k] = v
	}
	for k, v := range d.devices {
		out.devices[k] = v
	}
	return out
}

type placementState struct {
	mu         sync.Mutex
	data       placementData
	failCommit bool
}
type placementDriver struct{ state *placementState }
type placementConn struct {
	state *placementState
	tx    *placementTx
}
type placementTx struct {
	conn *placementConn
	data placementData
	done bool
}
type placementRows struct {
	columns []string
	values  []driver.Value
	read    bool
}

func (d placementDriver) Open(string) (driver.Conn, error) {
	return &placementConn{state: d.state}, nil
}
func (c *placementConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not used") }
func (c *placementConn) Close() error {
	if c.tx != nil {
		return c.tx.Rollback()
	}
	return nil
}
func (c *placementConn) Begin() (driver.Tx, error) {
	return c.BeginTx(context.Background(), driver.TxOptions{})
}
func (c *placementConn) BeginTx(ctx context.Context, _ driver.TxOptions) (driver.Tx, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.state.mu.Lock()
	tx := &placementTx{conn: c, data: c.state.data.clone()}
	c.tx = tx
	return tx, nil
}
func (tx *placementTx) Commit() error {
	if tx.done {
		return errors.New("transaction completed")
	}
	tx.done = true
	tx.conn.tx = nil
	defer tx.conn.state.mu.Unlock()
	if tx.conn.state.failCommit {
		return errors.New("simulated commit failure")
	}
	tx.conn.state.data = tx.data
	return nil
}
func (tx *placementTx) Rollback() error {
	if tx.done {
		return nil
	}
	tx.done = true
	tx.conn.tx = nil
	tx.conn.state.mu.Unlock()
	return nil
}
func (c *placementConn) ExecContext(_ context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if c.tx == nil {
		if strings.Contains(query, "CREATE TABLE") {
			return driver.RowsAffected(0), nil
		}
		return nil, errors.New("write outside transaction")
	}
	d := &c.tx.data
	switch {
	case strings.Contains(query, "INSERT INTO placement_cursors"):
		key := scopeKey(args[0].Value.(string), args[1].Value.(string))
		if _, ok := d.cursors[key]; !ok {
			d.cursors[key] = cursorValue{signature: args[2].Value.(string)}
		}
	case strings.Contains(query, "INSERT INTO site_region_assignments"):
		key := args[0].Value.(string)
		if _, ok := d.sites[key]; ok {
			return nil, errors.New("duplicate Site")
		}
		d.sites[key] = args[1].Value.(string)
	case strings.Contains(query, "INSERT INTO device_shard_assignments"):
		key := deviceCacheKey(args[0].Value.(string), args[1].Value.(string))
		if _, ok := d.devices[key]; ok {
			return nil, errors.New("duplicate Device")
		}
		d.devices[key] = args[2].Value.(int64)
	case strings.Contains(query, "UPDATE placement_cursors"):
		kind, scope := "site", "global"
		if strings.Contains(query, "kind = 'device'") {
			kind, scope = "device", args[1].Value.(string)
		}
		key := scopeKey(kind, scope)
		cursor := d.cursors[key]
		cursor.next = args[0].Value.(int64)
		d.cursors[key] = cursor
	default:
		return nil, fmt.Errorf("unexpected SQL: %s", query)
	}
	return driver.RowsAffected(1), nil
}
func (c *placementConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if c.tx == nil {
		return nil, errors.New("query outside transaction")
	}
	d := c.tx.data
	switch {
	case strings.Contains(query, "FROM placement_cursors"):
		value, ok := d.cursors[scopeKey(args[0].Value.(string), args[1].Value.(string))]
		if !ok {
			return &placementRows{columns: []string{"config_signature", "next_index"}}, nil
		}
		return &placementRows{columns: []string{"config_signature", "next_index"}, values: []driver.Value{value.signature, value.next}}, nil
	case strings.Contains(query, "FROM site_region_assignments"):
		value, ok := d.sites[args[0].Value.(string)]
		if !ok {
			return &placementRows{columns: []string{"region_id"}}, nil
		}
		return &placementRows{columns: []string{"region_id"}, values: []driver.Value{value}}, nil
	case strings.Contains(query, "FROM device_shard_assignments"):
		value, ok := d.devices[deviceCacheKey(args[0].Value.(string), args[1].Value.(string))]
		if !ok {
			return &placementRows{columns: []string{"shard_id"}}, nil
		}
		return &placementRows{columns: []string{"shard_id"}, values: []driver.Value{value}}, nil
	}
	return nil, fmt.Errorf("unexpected SQL: %s", query)
}
func (r *placementRows) Columns() []string { return r.columns }
func (r *placementRows) Close() error      { return nil }
func (r *placementRows) Next(dest []driver.Value) error {
	if r.read || r.values == nil {
		return io.EOF
	}
	r.read = true
	copy(dest, r.values)
	return nil
}

var nextTestDriver atomic.Uint64

func fakePlacementDB(t *testing.T) (*sql.DB, *placementState) {
	t.Helper()
	state := &placementState{data: newPlacementData()}
	name := fmt.Sprintf("placement-test-%d", nextTestDriver.Add(1))
	sql.Register(name, placementDriver{state})
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(16)
	t.Cleanup(func() { db.Close() })
	return db, state
}

func TestPostgreSQLPlacementSurvivesNewStoreAndKeepsCursors(t *testing.T) {
	db, _ := fakePlacementDB(t)
	first, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := first.EnsureSchema(ctx); err != nil {
		t.Fatal(err)
	}
	regions := []string{"0", "1", "2", "3"}
	for i, key := range []string{"WADI:P1", "WADI:P2", "HAI:P1", "SWAT:P1", "WADI:P5"} {
		want := regions[i%4]
		if got, err := first.Assign(ctx, key, regions); err != nil || got != want {
			t.Fatalf("Site %s: got %s, want %s: %v", key, got, want, err)
		}
	}
	shards := ShardStore{first}
	for i, key := range []string{"WADI:P1:FIT", "WADI:P1:LT", "WADI:P1:MV"} {
		if got, err := shards.Assign(ctx, "0", key, 16); err != nil || got != int64(i) {
			t.Fatalf("Device %s: got %d: %v", key, got, err)
		}
	}
	restarted, err := New(db) // New cache, same persistent DB.
	if err != nil {
		t.Fatal(err)
	}
	if got, err := restarted.Assign(ctx, "WADI:P1", regions); err != nil || got != "0" {
		t.Fatalf("Site moved: %s, %v", got, err)
	}
	if got, err := (ShardStore{restarted}).Assign(ctx, "0", "WADI:P1:LT", 16); err != nil || got != 1 {
		t.Fatalf("Device moved: %d, %v", got, err)
	}
	if got, err := restarted.Assign(ctx, "HAI:P2", regions); err != nil || got != "1" {
		t.Fatalf("Site cursor restarted: %s, %v", got, err)
	}
	if got, err := (ShardStore{restarted}).Assign(ctx, "0", "WADI:P1:AIT", 16); err != nil || got != 3 {
		t.Fatalf("Shard cursor restarted: %d, %v", got, err)
	}
	if _, err := restarted.Assign(ctx, "new", []string{"1", "0", "2", "3"}); err == nil {
		t.Fatal("Region order changed")
	}
	if _, err := (ShardStore{restarted}).Assign(ctx, "0", "new", 8); err == nil {
		t.Fatal("Shard count changed")
	}
}

func TestPostgreSQLPlacementConcurrentFirstEncounterAndFailedCommit(t *testing.T) {
	db, state := fakePlacementDB(t)
	store, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	state.mu.Lock()
	state.failCommit = true
	state.mu.Unlock()
	if _, err := store.Assign(ctx, "WADI:P1", []string{"0", "1"}); err == nil {
		t.Fatal("failed transaction appeared successful")
	}
	state.mu.Lock()
	state.failCommit = false
	state.mu.Unlock()
	const workers = 32
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if region, err := store.Assign(ctx, "WADI:P1", []string{"0", "1"}); err != nil {
				errs <- err
			} else if region != "0" {
				errs <- fmt.Errorf("Site moved to %s", region)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if got, err := store.Assign(ctx, "HAI:P1", []string{"0", "1"}); err != nil || got != "1" {
		t.Fatalf("Site cursor advanced incorrectly: %s, %v", got, err)
	}
	shards := ShardStore{store}
	errs = make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if sid, err := shards.Assign(ctx, "0", "WADI:P1:FIT", 16); err != nil {
				errs <- err
			} else if sid != 0 {
				errs <- fmt.Errorf("Device moved to %d", sid)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if sid, err := shards.Assign(ctx, "0", "WADI:P1:LT", 16); err != nil || sid != 1 {
		t.Fatalf("Shard cursor advanced incorrectly: %d, %v", sid, err)
	}
}
