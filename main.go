package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	checkpointpostgresql "github.com/SirojWongpitakroj/mva-phv/internal/checkpoint"
	cppostgresql "github.com/SirojWongpitakroj/mva-phv/internal/cloudprovider/postgresql"
	"github.com/SirojWongpitakroj/mva-phv/internal/storage/cassandra"
	"github.com/SirojWongpitakroj/mva-phv/internal/storage/postgresql/placement"
	"github.com/SirojWongpitakroj/mva-phv/internal/system"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	if err := loadEnvLocal(".env.local"); err != nil {
		return err
	}
	regions := flag.Int("regions", 4, "number of regions")
	shards := flag.Int("shards-per-region", 16, "shards in each region")
	segmentSize := flag.Int("max-segment-size", 1024, "maximum leaves per segment")
	sealInterval := flag.Duration("seal-interval", time.Minute, "maximum age of an active segment")
	mvaOrder := flag.Int("mva-order", 32, "MVA tree order")
	filterItems := flag.Int("filter-items", 10000, "expected Bloom filter items")
	falsePositive := flag.Float64("false-positive", 0.01, "Bloom filter false-positive probability")
	auditWorkers := flag.Int("audit-workers", 4, "maximum concurrent audit retrievals")
	smokeFile := flag.String("smoke-workload", "", "private canonical JSONL smoke workload to ingest")
	smokeEpoch := flag.Uint64("smoke-epoch", 1, "finalized epoch for the smoke workload")
	ingestWorkers := flag.Int("ingest-workers", 32, "maximum concurrent smoke ingestion calls")
	bootstrap := flag.Bool("bootstrap", false, "create missing PostgreSQL experiment tables and placement database")
	flag.Parse()

	key, err := hex.DecodeString(os.Getenv("MVA_PHV_ENCRYPTION_KEY_HEX"))
	if err != nil || len(key) != 32 {
		return fmt.Errorf("MVA_PHV_ENCRYPTION_KEY_HEX must contain a 32-byte key encoded as 64 hex characters")
	}

	config := system.Config{
		NumRegions:      *regions,
		ShardsPerRegion: *shards,
		MaxSegmentSize:  *segmentSize,
		SealInterval:    *sealInterval,
		MVAOrder:        *mvaOrder,
		FilterItems:     *filterItems,
		FalsePositive:   *falsePositive,
		EncryptionKey:   key,
		AuditWorkers:    *auditWorkers,
	}
	mode := os.Getenv("MVA_MODE")
	if mode == "" || mode == "aws" {
		err = runPersistent(config, *smokeFile, *smokeEpoch, *ingestWorkers, *bootstrap)
	} else {
		return fmt.Errorf("unsupported MVA_MODE %q", mode)
	}
	if err != nil {
		return fmt.Errorf("initialize MVA-PHV: %w", err)
	}
	return nil
}

func loadEnvLocal(path string) error {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("open local environment: %w", err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, ok := strings.Cut(line, "=")
		if !ok || name == "" {
			return fmt.Errorf("invalid local environment line")
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '"' && value[len(value)-1] == '"' ||
			value[0] == '\'' && value[len(value)-1] == '\'') {
			value = value[1 : len(value)-1]
		}
		if _, set := os.LookupEnv(name); !set {
			if err := os.Setenv(name, value); err != nil {
				return fmt.Errorf("set local environment %s: %w", name, err)
			}
		}
	}
	return scanner.Err()
}

func openPostgreSQL(ctx context.Context, prefix string) (*sql.DB, error) {
	host, port := os.Getenv(prefix+"_HOST"), os.Getenv(prefix+"_PORT")
	database, user := os.Getenv(prefix+"_DATABASE"), os.Getenv(prefix+"_USER")
	password, sslmode := os.Getenv(prefix+"_PASSWORD"), os.Getenv(prefix+"_SSLMODE")
	if host == "" || port == "" || database == "" || user == "" || password == "" || sslmode == "" {
		return nil, fmt.Errorf("%s: incomplete PostgreSQL settings", prefix)
	}
	if _, err := strconv.Atoi(port); err != nil {
		return nil, fmt.Errorf("%s: invalid PostgreSQL port", prefix)
	}
	dsn := &url.URL{Scheme: "postgres", User: url.UserPassword(user, password),
		Host: net.JoinHostPort(host, port), Path: "/" + database}
	query := dsn.Query()
	query.Set("sslmode", sslmode)
	dsn.RawQuery = query.Encode()
	db, err := sql.Open("pgx", dsn.String())
	if err != nil {
		return nil, fmt.Errorf("%s: open PostgreSQL: %w", prefix, err)
	}
	db.SetMaxOpenConns(10)
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("%s: connect PostgreSQL: %w", prefix, err)
	}
	return db, nil
}

func setPlacementDefaults() {
	if os.Getenv("MVA_PLACEMENT_HOST") != "" || os.Getenv("MVA_PLACEMENT_DATABASE") != "" {
		return
	}
	for _, suffix := range []string{"HOST", "PORT", "USER", "PASSWORD", "SSLMODE"} {
		_ = os.Setenv("MVA_PLACEMENT_"+suffix, os.Getenv("MVA_CHECKPOINT_"+suffix))
	}
	_ = os.Setenv("MVA_PLACEMENT_DATABASE", "mva_phv_placement")
}

func ensurePlacementDatabase(ctx context.Context, checkpointDB *sql.DB) error {
	if os.Getenv("MVA_PLACEMENT_DATABASE") != "mva_phv_placement" ||
		os.Getenv("MVA_PLACEMENT_HOST") != os.Getenv("MVA_CHECKPOINT_HOST") ||
		os.Getenv("MVA_PLACEMENT_PORT") != os.Getenv("MVA_CHECKPOINT_PORT") {
		return nil // An explicitly configured placement database is managed externally.
	}
	var exists bool
	if err := checkpointDB.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = 'mva_phv_placement')`).Scan(&exists); err != nil {
		return fmt.Errorf("check placement database: %w", err)
	}
	if exists {
		return nil
	}
	if _, err := checkpointDB.ExecContext(ctx, `CREATE DATABASE mva_phv_placement`); err != nil {
		return fmt.Errorf("create separate placement database: %w", err)
	}
	return nil
}

func runPersistent(config system.Config, smokeFile string, smokeEpoch uint64, ingestWorkers int, bootstrap bool) error {
	setPlacementDefaults()
	for _, other := range []string{"MVA_CP", "MVA_CHECKPOINT"} {
		if os.Getenv("MVA_PLACEMENT_HOST") == os.Getenv(other+"_HOST") &&
			os.Getenv("MVA_PLACEMENT_PORT") == os.Getenv(other+"_PORT") &&
			os.Getenv("MVA_PLACEMENT_DATABASE") == os.Getenv(other+"_DATABASE") {
			return fmt.Errorf("MVA_PLACEMENT must use a database separate from %s", other)
		}
	}
	openDB := func(prefix string) (*sql.DB, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		return openPostgreSQL(ctx, prefix)
	}
	cpDB, err := openDB("MVA_CP")
	if err != nil {
		return err
	}
	defer cpDB.Close()
	if ingestWorkers < 1 || ingestWorkers > 64 {
		return fmt.Errorf("ingest workers must be between 1 and 64")
	}
	cpDB.SetMaxOpenConns(ingestWorkers)
	checkpointDB, err := openDB("MVA_CHECKPOINT")
	if err != nil {
		return err
	}
	defer checkpointDB.Close()
	if bootstrap {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		if err := ensurePlacementDatabase(ctx, checkpointDB); err != nil {
			cancel()
			return err
		}
		cancel()
	}
	placementDB, err := openDB("MVA_PLACEMENT")
	if err != nil {
		return err
	}
	defer placementDB.Close()
	placements, err := placement.New(placementDB)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := placements.EnsureSchema(ctx); err != nil {
		return err
	}
	config.SiteRegions = placements
	config.DeviceShards = placement.ShardStore{Store: placements}
	client, closeTunnel, err := openCassandra()
	if err != nil {
		return err
	}
	defer closeTunnel()
	defer client.Close()
	cls, err := cassandra.NewStore(client)
	if err != nil {
		return err
	}
	cp, err := cppostgresql.New(cpDB)
	if err != nil {
		return err
	}
	checkpoints, err := checkpointpostgresql.NewMockCheckpointStore(checkpointDB)
	if err != nil {
		return err
	}
	if bootstrap {
		schemaCtx, schemaCancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer schemaCancel()
		if err := cp.EnsureSchema(schemaCtx); err != nil {
			return fmt.Errorf("prepare CP schema: %w", err)
		}
		if err := checkpoints.EnsureSchema(schemaCtx); err != nil {
			return fmt.Errorf("prepare checkpoint schema: %w", err)
		}
	}
	app, err := system.NewWithStorage(config, cp, cls, checkpoints)
	if err != nil {
		return err
	}
	if smokeFile != "" {
		if err := runSmokeWorkload(app, cpDB, checkpointDB, placementDB, client, cls, checkpoints, smokeFile, smokeEpoch, config.SealInterval, ingestWorkers); err != nil {
			return err
		}
	}
	fmt.Println("MVA-PHV initialized with Cassandra CLS, PostgreSQL CP, PostgreSQL placement control plane, and PostgreSQL checkpoint store")
	return nil
}

// Local development can use the configured SSH host to reach Cassandra. An
// application running inside the VPC can omit MVA_CASSANDRA_SSH_HOST and use
// its direct Cassandra hosts instead.
func openCassandra() (*cassandra.GocqlClient, func(), error) {
	port, err := strconv.Atoi(os.Getenv("MVA_CASSANDRA_PORT"))
	if err != nil || port < 1 || port > 65535 {
		return nil, nil, fmt.Errorf("invalid MVA_CASSANDRA_PORT")
	}
	stop := func() {}
	if host := os.Getenv("MVA_CASSANDRA_SSH_HOST"); host != "" {
		localPort, err := strconv.Atoi(os.Getenv("MVA_CASSANDRA_SSH_LOCAL_PORT"))
		if err != nil || localPort < 1 || localPort > 65535 {
			return nil, nil, fmt.Errorf("invalid MVA_CASSANDRA_SSH_LOCAL_PORT")
		}
		key, user := os.Getenv("MVA_CASSANDRA_SSH_KEY"), os.Getenv("MVA_CASSANDRA_SSH_USER")
		if user == "" || key == "" {
			return nil, nil, fmt.Errorf("Cassandra SSH user and key are required")
		}
		if _, err := os.Stat(key); err != nil {
			return nil, nil, fmt.Errorf("Cassandra SSH key: %w", err)
		}
		address := net.JoinHostPort("127.0.0.1", strconv.Itoa(localPort))
		listener, err := net.Listen("tcp", address)
		if err != nil {
			return nil, nil, fmt.Errorf("Cassandra SSH local port unavailable: %w", err)
		}
		listener.Close()
		forward := address + ":127.0.0.1:" + strconv.Itoa(port)
		sshArgs := []string{"-N", "-L", forward, "-i", key,
			"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
			"-o", "ExitOnForwardFailure=yes", "-o", "ConnectTimeout=7"}
		if knownHosts := os.Getenv("MVA_CASSANDRA_SSH_KNOWN_HOSTS"); knownHosts != "" {
			sshArgs = append(sshArgs, "-o", "UserKnownHostsFile="+knownHosts)
		}
		cmd := exec.Command("ssh", append(sshArgs, user+"@"+host)...)
		if err := cmd.Start(); err != nil {
			return nil, nil, fmt.Errorf("start Cassandra SSH tunnel: %w", err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		stop = func() {
			_ = cmd.Process.Kill()
			<-done
		}
		deadline := time.NewTimer(8 * time.Second)
		defer deadline.Stop()
		ready := false
		for !ready {
			select {
			case err := <-done:
				return nil, nil, fmt.Errorf("Cassandra SSH tunnel exited: %v", err)
			case <-deadline.C:
				stop()
				return nil, nil, fmt.Errorf("Cassandra SSH tunnel did not open local port")
			case <-time.After(100 * time.Millisecond):
				conn, err := net.DialTimeout("tcp", address, time.Second)
				if err == nil {
					conn.Close()
					ready = true
				}
			}
		}
		port = localPort
	}
	hosts := strings.Split(os.Getenv("MVA_CASSANDRA_HOSTS"), ",")
	client, err := cassandra.Dial(hosts, port, os.Getenv("MVA_CASSANDRA_KEYSPACE"))
	if err != nil {
		stop()
		return nil, nil, err
	}
	return client, stop, nil
}
