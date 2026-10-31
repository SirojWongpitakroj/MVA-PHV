package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SirojWongpitakroj/mva-phv/internal/canonicalize"
	checkpointpostgresql "github.com/SirojWongpitakroj/mva-phv/internal/checkpoint"
	"github.com/SirojWongpitakroj/mva-phv/internal/storage/cassandra"
	"github.com/SirojWongpitakroj/mva-phv/internal/system"
	"github.com/gocql/gocql"
)

type smokeManifest struct {
	SHA256        string         `json:"sha256"`
	TotalRecords  int            `json:"total_records"`
	DatasetCounts map[string]int `json:"dataset_counts"`
}

func eachSmokeRecord(path string, visit func(int, canonicalize.CanonicalRecord) error) (map[string]int, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1<<20)
	counts := map[string]int{"WADI": 0, "HAI": 0, "SWAT": 0}
	order := [...]string{"WADI", "HAI", "SWAT"}
	line := 0
	for scanner.Scan() {
		var record canonicalize.CanonicalRecord
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			return nil, fmt.Errorf("smoke line %d: %w", line+1, err)
		}
		expected := order[line%len(order)]
		if record.Dataset != expected || !strings.HasPrefix(record.Site, expected+":") ||
			record.Device == "" || record.Type == "" || record.Timestamp.IsZero() || record.Value == "" ||
			(record.Label != "normal" && record.Label != "attack") {
			return nil, fmt.Errorf("smoke line %d: invalid canonical record", line+1)
		}
		if visit != nil {
			if err := visit(line, record); err != nil {
				return nil, err
			}
		}
		counts[expected]++
		line++
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if line != 100000 || counts["WADI"] != 33334 || counts["HAI"] != 33333 || counts["SWAT"] != 33333 {
		return nil, fmt.Errorf("smoke workload: got %d records (%v), expected 100000 with 33334/33333/33333 split", line, counts)
	}
	return counts, nil
}

func validateSmokeWorkload(path string) error {
	manifestPath := strings.TrimSuffix(path, filepath.Ext(path)) + "_manifest.json"
	rawManifest, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read smoke manifest: %w", err)
	}
	var manifest smokeManifest
	if err := json.Unmarshal(rawManifest, &manifest); err != nil {
		return fmt.Errorf("parse smoke manifest: %w", err)
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	digest := sha256.New()
	_, copyErr := io.Copy(digest, file)
	closeErr := file.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		return err
	}
	if manifest.SHA256 != hex.EncodeToString(digest.Sum(nil)) || manifest.TotalRecords != 100000 ||
		manifest.DatasetCounts["WADI"] != 33334 || manifest.DatasetCounts["HAI"] != 33333 ||
		manifest.DatasetCounts["SWAT"] != 33333 {
		return fmt.Errorf("smoke workload: manifest count or SHA-256 mismatch")
	}
	_, err = eachSmokeRecord(path, nil)
	return err
}

func requireEmptyPostgreSQL(ctx context.Context, db *sql.DB, table string) error {
	var populated bool
	// Table names are fixed literals supplied by this program, never user input.
	if err := db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM "+table+")").Scan(&populated); err != nil {
		return fmt.Errorf("check %s: %w", table, err)
	}
	if populated {
		return fmt.Errorf("smoke workload: %s already contains data; this fresh-only runner cannot recover it", table)
	}
	return nil
}

func requireFreshCLS(ctx context.Context, client *cassandra.GocqlClient) error {
	required := []string{
		"log_addresses_by_id", "hmf_active_segments_by_shard", "hmf_segments_by_shard", "hmf_segment_nodes",
		"hmf_hierarchy_nodes", "hmf_shard_state_by_epoch", "hmf_region_state_by_epoch", "hmf_global_state_by_epoch",
		"mva_pages", "mva_working_view_state", "mva_region_view_state_by_epoch", "mva_region_commitments_by_epoch",
		"mva_global_nodes_by_epoch", "mva_epoch_roots", "hpbf_working_shard_filters", "hpbf_shard_filter_versions",
		"hpbf_shard_commitments_by_epoch", "hpbf_region_filters_by_epoch", "hpbf_region_nodes_by_epoch",
		"hpbf_region_roots_by_epoch", "hpbf_global_nodes_by_epoch", "hpbf_epoch_roots",
	}
	rows, err := client.Query(ctx, `SELECT table_name FROM system_schema.tables WHERE keyspace_name=?`, os.Getenv("MVA_CASSANDRA_KEYSPACE"))
	if err != nil {
		return err
	}
	found := make(map[string]bool)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			rows.Close()
			return err
		}
		found[name] = true
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, name := range required {
		if !found[name] {
			return fmt.Errorf("smoke workload: Cassandra CLS table %s is missing", name)
		}
	}
	rows, err = client.Query(ctx, `SELECT log_id FROM log_addresses_by_id LIMIT 1`)
	if err != nil {
		return err
	}
	if rows.Next() {
		var id gocql.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		return fmt.Errorf("smoke workload: Cassandra CLS already contains accepted LogIDs; this fresh-only runner cannot recover them")
	}
	return rows.Close()
}

func runSmokeWorkload(app *system.System, cpDB, checkpointDB, placementDB *sql.DB,
	client *cassandra.GocqlClient, cls *cassandra.Store, checkpoints *checkpointpostgresql.MockCheckpointStore,
	path string, epoch uint64, sealInterval time.Duration, workers int) error {
	if epoch != 1 {
		return fmt.Errorf("smoke workload: fresh deployment requires epoch 1")
	}
	if err := validateSmokeWorkload(path); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	for _, check := range []struct {
		db    *sql.DB
		table string
	}{
		{cpDB, "encrypted_logs"}, {checkpointDB, "mock_checkpoints"},
		{placementDB, "site_region_assignments"}, {placementDB, "device_shard_assignments"},
	} {
		if err := requireEmptyPostgreSQL(ctx, check.db, check.table); err != nil {
			return err
		}
	}
	if err := requireFreshCLS(ctx, client); err != nil {
		return err
	}
	// First encounters are admitted in source order. This fixes the sticky
	// Site/Device placement before parallel ingestion can reorder requests.
	type identity struct{ dataset, site, device string }
	type firstRecord struct {
		index  int
		record canonicalize.CanonicalRecord
	}
	first := make([]firstRecord, 0, 256)
	firstPositions := make(map[int]struct{})
	seen := make(map[identity]struct{})
	if _, err := eachSmokeRecord(path, func(index int, record canonicalize.CanonicalRecord) error {
		key := identity{record.Dataset, record.Site, record.Device}
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			first = append(first, firstRecord{index, record})
			firstPositions[index] = struct{}{}
		}
		return nil
	}); err != nil {
		return err
	}
	start := time.Now()
	var accepted atomic.Int64
	progress := func() {
		count := accepted.Add(1)
		if count == 1 || count == 10 || count == 100 || count%1000 == 0 {
			fmt.Printf("ingested %d/100000 records in %s\n", count, time.Since(start).Round(time.Second))
		}
	}
	for _, item := range first {
		if _, err := app.IngestCanonical(ctx, item.record, time.Now().UTC()); err != nil {
			return fmt.Errorf("smoke first-placement record %d failed after %d accepted records: %w", item.index+1, accepted.Load(), err)
		}
		progress()
	}
	workCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type job struct {
		index  int
		record canonicalize.CanonicalRecord
	}
	jobs := make(chan job, workers*2)
	var group sync.WaitGroup
	var failOnce sync.Once
	var workerErr error
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			for item := range jobs {
				if workCtx.Err() != nil {
					return
				}
				if _, err := app.IngestCanonical(workCtx, item.record, time.Now().UTC()); err != nil {
					failOnce.Do(func() {
						workerErr = fmt.Errorf("smoke record %d failed after at least %d accepted records: %w", item.index+1, accepted.Load(), err)
						cancel()
					})
					return
				}
				progress()
			}
		}()
	}
	_, readErr := eachSmokeRecord(path, func(index int, record canonicalize.CanonicalRecord) error {
		if _, first := firstPositions[index]; first {
			return nil
		}
		select {
		case jobs <- job{index, record}:
			return nil
		case <-workCtx.Done():
			return workCtx.Err()
		}
	})
	close(jobs)
	group.Wait()
	if workerErr != nil {
		return workerErr
	}
	if readErr != nil {
		return readErr
	}
	if accepted.Load() != 100000 {
		return fmt.Errorf("smoke ingestion accepted %d records, expected 100000", accepted.Load())
	}
	// A finalization boundary advances the test clock past the sealing interval.
	if err := app.SealExpired(ctx, time.Now().UTC().Add(sealInterval+time.Second)); err != nil {
		return fmt.Errorf("seal final active Segments: %w", err)
	}
	candidate, err := app.PrepareFinalization(ctx, epoch)
	if err != nil {
		return fmt.Errorf("prepare smoke epoch: %w", err)
	}
	if len(candidate.Records) != 100000 {
		return fmt.Errorf("smoke candidate contains %d records, expected 100000", len(candidate.Records))
	}
	checkpoint, err := app.CommitFinalization(ctx, epoch)
	if err != nil {
		return fmt.Errorf("commit smoke epoch: %w", err)
	}
	anchored, err := checkpoints.GetCheckpoint(ctx, epoch)
	if err != nil || anchored != checkpoint {
		return fmt.Errorf("smoke checkpoint confirmation: %w", err)
	}
	hmfState, err := cls.GetGlobalState(ctx, "GLOBAL", epoch)
	if err != nil || hmfState.Root != candidate.Roots.HMF {
		return fmt.Errorf("smoke CLS HMF root confirmation: %w", err)
	}
	mvaRoot, err := cls.GetMVARoot(ctx, epoch)
	if err != nil || mvaRoot != candidate.Roots.MVA {
		return fmt.Errorf("smoke CLS MVA root confirmation: %w", err)
	}
	hpbfRoot, err := cls.GetHPBFRoot(ctx, epoch)
	if err != nil || hpbfRoot != candidate.Roots.HPBF {
		return fmt.Errorf("smoke CLS HPBF root confirmation: %w", err)
	}
	fmt.Printf("smoke ingestion finalized: epoch=%d records=100000 segments=%d checkpoint=%x elapsed=%s\n",
		epoch, len(candidate.Segments), checkpoint, time.Since(start).Round(time.Second))
	return nil
}
