package cassandra

import (
	"context"
	"errors"
	"fmt"
	"math"
)

// Client is the small part of a Cassandra driver needed by this package.
// A connection adapter can implement it later; statements always use bind args.
type Client interface {
	Exec(ctx context.Context, statement string, args ...any) error
	Query(ctx context.Context, statement string, args ...any) (Rows, error)
}

// ConditionalClient performs a Cassandra lightweight transaction at SERIAL
// consistency and reports whether its IF NOT EXISTS condition was applied.
// MPMRepository requires this for durable LogID uniqueness.
type ConditionalClient interface {
	ExecIfNotExists(ctx context.Context, statement string, args ...any) (bool, error)
}

// Rows follows the usual forward-only driver cursor contract. Nullable bigint
// columns scan into **int64 (nil for CQL null). Scan must copy blob values into
// destinations, since the cursor may reuse its buffers.
type Rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
	Close() error
}

var ErrNotFound = errors.New("cassandra: row not found")

// Store contains query and parsing logic, but does not create a connection.
type Store struct{ client Client }

func NewStore(client Client) (*Store, error) {
	if client == nil {
		return nil, errors.New("cassandra: nil client")
	}
	return &Store{client: client}, nil
}

func (s *Store) exec(ctx context.Context, statement string, args ...any) error {
	if s == nil || s.client == nil {
		return errors.New("cassandra: nil store")
	}
	return s.client.Exec(ctx, statement, args...)
}

func (s *Store) query(ctx context.Context, statement string, args ...any) (Rows, error) {
	if s == nil || s.client == nil {
		return nil, errors.New("cassandra: nil store")
	}
	return s.client.Query(ctx, statement, args...)
}

// one closes the cursor and reports both scan and close errors. All callers
// issue a primary-key query with LIMIT 1 or an exact primary-key lookup.
func (s *Store) one(ctx context.Context, statement string, args []any, scan func(Rows) error) (err error) {
	rows, err := s.query(ctx, statement, args...)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return err
		}
		return ErrNotFound
	}
	if err := scan(rows); err != nil {
		return err
	}
	return rows.Err()
}

func (s *Store) each(ctx context.Context, statement string, args []any, scan func(Rows) error) (err error) {
	rows, err := s.query(ctx, statement, args...)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, rows.Close()) }()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

func signedEpoch(epoch uint64) (int64, error) {
	if epoch > math.MaxInt64 {
		return 0, fmt.Errorf("cassandra: epoch %d exceeds CQL bigint", epoch)
	}
	return int64(epoch), nil
}

func nodeBucket(index int64) (int64, error) {
	if index < 0 {
		return 0, fmt.Errorf("cassandra: negative node index %d", index)
	}
	return index / 4096, nil
}

func pageBucket(id int64) (int64, error) {
	if id < 0 {
		return 0, fmt.Errorf("cassandra: negative page id %d", id)
	}
	return id / 256, nil
}

func parseHash(data []byte, name string) ([32]byte, error) {
	var hash [32]byte
	if len(data) != len(hash) {
		return hash, fmt.Errorf("cassandra: %s has %d bytes, want 32", name, len(data))
	}
	copy(hash[:], data)
	return hash, nil
}

func blob(data []byte) []byte { return append([]byte(nil), data...) }
