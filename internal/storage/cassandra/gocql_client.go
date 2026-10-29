package cassandra

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
	"uuid"

	"github.com/gocql/gocql"
)

// GocqlClient connects the storage-neutral CQL Store to a Cassandra session.
// The caller owns the lifetime of the client and its SSH tunnel, if any.
type GocqlClient struct{ session *gocql.Session }

var _ Client = (*GocqlClient)(nil)
var _ ConditionalClient = (*GocqlClient)(nil)

func Dial(hosts []string, port int, keyspace string) (*GocqlClient, error) {
	if len(hosts) == 0 || port < 1 || port > 65535 || keyspace == "" {
		return nil, fmt.Errorf("cassandra: hosts, port, and keyspace are required")
	}
	for _, host := range hosts {
		if strings.TrimSpace(host) == "" {
			return nil, fmt.Errorf("cassandra: empty host")
		}
	}
	cluster := gocql.NewCluster(hosts...)
	cluster.Port = port
	cluster.Keyspace = keyspace
	cluster.Consistency = gocql.LocalQuorum
	cluster.SerialConsistency = gocql.LocalSerial
	cluster.ConnectTimeout = 5 * time.Second
	cluster.Timeout = 10 * time.Second
	session, err := cluster.CreateSession()
	if err != nil {
		return nil, fmt.Errorf("cassandra: connect: %w", err)
	}
	return &GocqlClient{session: session}, nil
}

func (c *GocqlClient) Close() {
	if c != nil && c.session != nil {
		c.session.Close()
	}
}

func cqlArgs(args []any) []any {
	converted := make([]any, len(args))
	for i, arg := range args {
		if id, ok := arg.(uuid.UUID); ok {
			converted[i] = [16]byte(id)
		} else {
			converted[i] = arg
		}
	}
	return converted
}

func (c *GocqlClient) Exec(ctx context.Context, statement string, args ...any) error {
	if c == nil || c.session == nil {
		return fmt.Errorf("cassandra: client not connected")
	}
	return c.session.Query(statement, cqlArgs(args)...).WithContext(ctx).Exec()
}

func (c *GocqlClient) ExecIfNotExists(ctx context.Context, statement string, args ...any) (bool, error) {
	if c == nil || c.session == nil {
		return false, fmt.Errorf("cassandra: client not connected")
	}
	return c.session.Query(statement, cqlArgs(args)...).WithContext(ctx).
		Consistency(gocql.LocalQuorum).SerialConsistency(gocql.LocalSerial).
		MapScanCAS(make(map[string]any))
}

func (c *GocqlClient) Query(ctx context.Context, statement string, args ...any) (Rows, error) {
	if c == nil || c.session == nil {
		return nil, fmt.Errorf("cassandra: client not connected")
	}
	return &gocqlRows{scanner: c.session.Query(statement, cqlArgs(args)...).WithContext(ctx).Iter().Scanner()}, nil
}

// gocql's Scanner.Err closes its iterator. Keep Close idempotent because the
// Store calls Err after iteration and also defers Close.
type gocqlRows struct {
	scanner gocql.Scanner
	once    sync.Once
	err     error
}

func (r *gocqlRows) Next() bool { return r.scanner.Next() }

func (r *gocqlRows) Scan(dest ...any) error {
	values := make([]any, len(dest))
	blobs := make(map[int]*[]byte)
	for i, value := range dest {
		if target, ok := value.(*[]byte); ok {
			var raw []byte
			values[i] = &raw
			blobs[i] = target
		} else {
			values[i] = value
		}
	}
	if err := r.scanner.Scan(values...); err != nil {
		return err
	}
	for i, target := range blobs {
		*target = append([]byte(nil), *values[i].(*[]byte)...)
	}
	return nil
}

func (r *gocqlRows) Err() error { return r.Close() }

func (r *gocqlRows) Close() error {
	r.once.Do(func() { r.err = r.scanner.Err() })
	return r.err
}
