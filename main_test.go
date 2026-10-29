package main

import (
	"context"
	"database/sql"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLivePostgreSQLSchemas(t *testing.T) {
	if os.Getenv("MVA_POSTGRES_LIVE") != "1" {
		t.Skip("set MVA_POSTGRES_LIVE=1 for live PostgreSQL schema checks")
	}
	if err := loadEnvLocal(".env.local"); err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct{ prefix, table string }{
		{"MVA_CP", "encrypted_logs"},
		{"MVA_CHECKPOINT", "mock_checkpoints"},
	} {
		t.Run(target.prefix, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			db, err := openPostgreSQL(ctx, target.prefix)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var table sql.NullString
			if err := db.QueryRowContext(ctx, "SELECT to_regclass($1)::text", "public."+target.table).Scan(&table); err != nil {
				t.Fatal(err)
			}
			if !table.Valid {
				t.Fatalf("%s is missing", target.table)
			}
		})
	}
}

func TestLiveCassandraSSHTunnel(t *testing.T) {
	if os.Getenv("MVA_CASSANDRA_TUNNEL_LIVE") != "1" {
		t.Skip("set MVA_CASSANDRA_TUNNEL_LIVE=1 for the configured SSH tunnel test")
	}
	client, closeTunnel, err := openCassandra()
	if err != nil {
		t.Fatal(err)
	}
	defer closeTunnel()
	defer client.Close()
	rows, err := client.Query(context.Background(), "SELECT release_version FROM system.local")
	if err != nil {
		t.Fatal(err)
	}
	if !rows.Next() {
		t.Fatalf("missing Cassandra system.local: %v", rows.Close())
	}
	var version string
	if err := rows.Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil || version == "" {
		t.Fatalf("Cassandra tunnel query: version present=%v err=%v", version != "", err)
	}
}

func TestLoadEnvLocalKeepsExistingProcessSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".env.local")
	if err := os.WriteFile(path, []byte("# local settings\nTEST_MVA_MODE=aws\nTEST_MVA_PASSWORD=quoted=value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TEST_MVA_MODE", "memory")
	if err := loadEnvLocal(path); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("TEST_MVA_MODE"); got != "memory" {
		t.Fatalf("process setting replaced: %q", got)
	}
	if got := os.Getenv("TEST_MVA_PASSWORD"); got != "quoted=value" {
		t.Fatalf("local value incorrectly parsed: %q", got)
	}
}

// A deployable application needs an entry point before its initialization can
// be tested through the executable.
func TestMainHasEntryPoint(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatalf("parse main.go: %v", err)
	}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if ok && function.Recv == nil && function.Name.Name == "main" &&
			function.Type.Params.NumFields() == 0 && function.Type.Results == nil {
			return
		}
	}
	t.Fatal("main.go has no func main; application initialization is not wired yet")
}
