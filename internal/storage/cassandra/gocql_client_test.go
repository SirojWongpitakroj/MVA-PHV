package cassandra

import (
	"context"
	"errors"
	"os"
	"strconv"
	"testing"
	"uuid"
)

type reuseScanner struct {
	data []byte
	used bool
}

func (s *reuseScanner) Next() bool {
	if s.used {
		return false
	}
	s.used = true
	return true
}
func (s *reuseScanner) Scan(dest ...any) error {
	if len(dest) != 1 {
		return errors.New("unexpected destination count")
	}
	*dest[0].(*[]byte) = s.data
	return nil
}
func (s *reuseScanner) Err() error { return nil }

func TestGocqlRowsCopiesBlobAndClosesIdempotently(t *testing.T) {
	scanner := &reuseScanner{data: []byte{1, 2}}
	rows := &gocqlRows{scanner: scanner}
	if !rows.Next() {
		t.Fatal("missing row")
	}
	var value []byte
	if err := rows.Scan(&value); err != nil {
		t.Fatal(err)
	}
	scanner.data[0] = 9
	if value[0] != 1 || rows.Err() != nil || rows.Close() != nil {
		t.Fatal("blob was reused or cursor failed to close")
	}
}

func TestCQLArgsConvertStandardUUID(t *testing.T) {
	// A standard-library UUID has its own named type. gocql accepts [16]byte.
	input := []any{uuid.UUID{1}, "region", int64(2)}
	converted := cqlArgs(input)
	id, ok := converted[0].([16]byte)
	if !ok || id[0] != 1 || len(converted) != len(input) || converted[1] != input[1] || converted[2] != input[2] {
		t.Fatalf("unexpected CQL arguments: %v", converted)
	}
}

// Opt-in connectivity test; normal unit tests require no live Cassandra.
func TestLiveGocqlConnection(t *testing.T) {
	if os.Getenv("MVA_CASSANDRA_LIVE") != "1" {
		t.Skip("set MVA_CASSANDRA_LIVE=1 for a live connection check")
	}
	port, err := strconv.Atoi(os.Getenv("MVA_CASSANDRA_PORT"))
	if err != nil {
		t.Fatal(err)
	}
	client, err := Dial([]string{os.Getenv("MVA_CASSANDRA_HOSTS")}, port, os.Getenv("MVA_CASSANDRA_KEYSPACE"))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	rows, err := client.Query(context.Background(), "SELECT release_version FROM system.local")
	if err != nil {
		t.Fatal(err)
	}
	if !rows.Next() {
		t.Fatalf("system.local has no row: %v", rows.Close())
	}
	var version string
	if err := rows.Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil || version == "" {
		t.Fatalf("Cassandra query: version present=%v err=%v", version != "", err)
	}
	store, err := NewStore(client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetPageAt(context.Background(), "__connection_probe__", "id", 0, 0); !errors.Is(err, ErrNotFound) {
		t.Fatalf("prepared MVA page query: want not found, got %v", err)
	}
}
