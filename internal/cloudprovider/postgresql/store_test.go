package postgresql

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"uuid"

	"github.com/SirojWongpitakroj/mva-phv/internal/cloudprovider"
)

type fakeState struct {
	mu                sync.Mutex
	values            map[string]cloudprovider.Ciphertext
	execErr, queryErr error
	batchSizes        []int
	statements        []string
}
type fakeDriver struct{ state *fakeState }
type fakeConn struct{ state *fakeState }
type fakeRows struct {
	values []cloudprovider.Ciphertext
	next   int
}

var driverSequence uint64

func (d fakeDriver) Open(string) (driver.Conn, error)   { return &fakeConn{state: d.state}, nil }
func (c *fakeConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not used") }
func (c *fakeConn) Close() error                        { return nil }
func (c *fakeConn) Begin() (driver.Tx, error)           { return nil, errors.New("not used") }
func (c *fakeConn) ExecContext(_ context.Context, statement string, args []driver.NamedValue) (driver.Result, error) {
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	c.state.statements = append(c.state.statements, statement)
	if c.state.execErr != nil {
		return nil, c.state.execErr
	}
	if !strings.Contains(statement, "INSERT INTO encrypted_logs") || len(args) != 6 {
		return nil, errors.New("wrong CP insert")
	}
	id := args[0].Value.(string)
	if _, exists := c.state.values[id]; !exists {
		parsed, err := uuid.Parse(id)
		if err != nil {
			return nil, err
		}
		c.state.values[id] = cloudprovider.Ciphertext{LogID: parsed,
			Ciphertext: slices.Clone(args[1].Value.([]byte)), Nonce: slices.Clone(args[2].Value.([]byte)),
			Tag: slices.Clone(args[3].Value.([]byte)), AD: slices.Clone(args[4].Value.([]byte)), Version: uint16(args[5].Value.(int64))}
	}
	return driver.RowsAffected(1), nil
}
func (c *fakeConn) QueryContext(_ context.Context, statement string, args []driver.NamedValue) (driver.Rows, error) {
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	c.state.statements = append(c.state.statements, statement)
	if c.state.queryErr != nil {
		return nil, c.state.queryErr
	}
	if !strings.Contains(statement, "FROM encrypted_logs WHERE log_id =") || len(args) != 1 {
		return nil, errors.New("CP queried by predicate other than LogID")
	}
	var ids []string
	if strings.Contains(statement, "ANY($1::uuid[])") {
		array := args[0].Value.(string)
		if len(array) < 2 || array[0] != '{' || array[len(array)-1] != '}' {
			return nil, errors.New("malformed UUID array")
		}
		if len(array) > 2 {
			ids = strings.Split(array[1:len(array)-1], ",")
		}
		c.state.batchSizes = append(c.state.batchSizes, len(ids))
	} else {
		ids = []string{args[0].Value.(string)}
	}
	var result []cloudprovider.Ciphertext
	for _, id := range ids {
		if value, ok := c.state.values[id]; ok {
			result = append(result, value)
		}
	}
	return &fakeRows{values: result}, nil
}
func (r *fakeRows) Columns() []string {
	return []string{"log_id", "ciphertext", "nonce", "tag", "associated_data", "encryption_version"}
}
func (r *fakeRows) Close() error { return nil }
func (r *fakeRows) Next(dest []driver.Value) error {
	if r.next >= len(r.values) {
		return io.EOF
	}
	v := r.values[r.next]
	r.next++
	dest[0] = v.LogID.String()
	dest[1] = slices.Clone(v.Ciphertext)
	dest[2] = slices.Clone(v.Nonce)
	dest[3] = slices.Clone(v.Tag)
	dest[4] = slices.Clone(v.AD)
	dest[5] = int64(v.Version)
	return nil
}
func openFake(t *testing.T) (*Store, *fakeState) {
	t.Helper()
	state := &fakeState{values: make(map[string]cloudprovider.Ciphertext)}
	name := fmt.Sprintf("fake-external-cp-%d", atomic.AddUint64(&driverSequence, 1))
	sql.Register(name, fakeDriver{state: state})
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store, err := New(db)
	if err != nil {
		t.Fatal(err)
	}
	return store, state
}
func record(n byte) cloudprovider.Ciphertext {
	return cloudprovider.Ciphertext{LogID: uuid.UUID{n}, Ciphertext: []byte{n + 10}, Nonce: make([]byte, 12), Tag: make([]byte, 16), AD: []byte{1}, Version: cloudprovider.EncryptionVersionAESGCM}
}

func TestExternalPostgreSQLCPStoresByUUIDOnly(t *testing.T) {
	if _, err := New(nil); err == nil {
		t.Fatal("nil DB accepted")
	}
	store, state := openFake(t)
	ctx := context.Background()
	for _, n := range []byte{1, 2, 3} {
		if err := store.StoreCiphertext(ctx, "R", record(n)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.StoreCiphertext(ctx, "R", record(1)); err != nil {
		t.Fatalf("idempotent retry: %v", err)
	}
	changed := record(1)
	changed.Ciphertext[0]++
	if err := store.StoreCiphertext(ctx, "R", changed); !errors.Is(err, cloudprovider.ErrConflict) {
		t.Fatalf("conflicting retry: %v", err)
	}
	got, err := store.GetCiphertexts(ctx, "R", []uuid.UUID{record(3).LogID, record(1).LogID, uuid.UUID{9}})
	if err != nil || len(got) != 2 || got[0].LogID != record(3).LogID || got[1].LogID != record(1).LogID {
		t.Fatalf("exact LogID batch: %+v, %v", got, err)
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	for _, statement := range state.statements {
		if strings.Contains(statement, "site") || strings.Contains(statement, "device") || strings.Contains(statement, "seg_id") || strings.Contains(statement, "mock_checkpoints") {
			t.Fatalf("CP crossed storage boundary: %s", statement)
		}
	}
}

func TestExternalPostgreSQLCPRejectsMalformedVersionAndPropagatesOutages(t *testing.T) {
	store, state := openFake(t)
	ctx := context.Background()
	if err := store.StoreCiphertext(ctx, "R", record(1)); err != nil {
		t.Fatal(err)
	}
	state.mu.Lock()
	changed := state.values[record(1).LogID.String()]
	changed.Version = 2
	state.values[record(1).LogID.String()] = changed
	state.mu.Unlock()
	if _, err := store.GetCiphertexts(ctx, "R", []uuid.UUID{record(1).LogID}); !errors.Is(err, cloudprovider.ErrUnsupportedVersion) {
		t.Fatalf("unsupported version: %v", err)
	}
	state.mu.Lock()
	state.queryErr = errors.New("CP unavailable")
	state.mu.Unlock()
	if _, err := store.GetCiphertexts(ctx, "R", []uuid.UUID{record(1).LogID}); err == nil || !strings.Contains(err.Error(), "CP unavailable") {
		t.Fatalf("query outage: %v", err)
	}
	state.mu.Lock()
	state.queryErr = nil
	state.execErr = errors.New("CP write unavailable")
	state.mu.Unlock()
	if err := store.StoreCiphertext(ctx, "R", record(2)); err == nil || !strings.Contains(err.Error(), "CP write unavailable") {
		t.Fatalf("write outage: %v", err)
	}
}

func TestExternalPostgreSQLCPChunksLargeExactLogIDSet(t *testing.T) {
	store, state := openFake(t)
	ids := make([]uuid.UUID, 260)
	for i := range ids {
		ids[i] = uuid.UUID{byte(i >> 8), byte(i), 1}
	}
	got, err := store.GetCiphertexts(context.Background(), "R", ids)
	if err != nil || len(got) != 0 {
		t.Fatalf("missing CP objects should be returned as gaps: %+v, %v", got, err)
	}
	state.mu.Lock()
	sizes := slices.Clone(state.batchSizes)
	state.mu.Unlock()
	if !slices.Equal(sizes, []int{128, 128, 4}) {
		t.Fatalf("wrong bounded batches: %v", sizes)
	}
}

func TestPostgreSQLCPCiphertextRemainsUntrusted(t *testing.T) {
	provider, state := openFake(t)
	ctx := context.Background()
	original := record(1)
	if err := provider.StoreCiphertext(ctx, "0", original); err != nil {
		t.Fatal(err)
	}
	stored, err := provider.GetCiphertexts(ctx, "0", []uuid.UUID{original.LogID})
	if err != nil || len(stored) != 1 || !slices.Equal(stored[0].Ciphertext, original.Ciphertext) {
		t.Fatalf("CP PostgreSQL record missing or plaintext: %+v, %v", stored, err)
	}
	state.mu.Lock()
	changed := state.values[original.LogID.String()]
	changed.Ciphertext = slices.Clone(changed.Ciphertext)
	changed.Ciphertext[0] ^= 1
	state.values[original.LogID.String()] = changed
	state.mu.Unlock()
	tampered, err := provider.GetCiphertexts(ctx, "0", []uuid.UUID{original.LogID})
	if err != nil || len(tampered) != 1 || slices.Equal(tampered[0].Ciphertext, original.Ciphertext) {
		t.Fatalf("CP failed to return untrusted modified ciphertext: %+v, %v", tampered, err)
	}
	state.mu.Lock()
	delete(state.values, original.LogID.String())
	state.mu.Unlock()
	missing, err := provider.GetCiphertexts(ctx, "0", []uuid.UUID{original.LogID})
	if err != nil || len(missing) != 0 {
		t.Fatalf("missing CP object was not reported as unavailable: %+v, %v", missing, err)
	}
}
