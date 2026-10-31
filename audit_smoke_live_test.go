package main

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
	"uuid"

	checkpoint "github.com/SirojWongpitakroj/mva-phv/internal/checkpoint"
	"github.com/SirojWongpitakroj/mva-phv/internal/cloudprovider/postgresql"
	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
	"github.com/SirojWongpitakroj/mva-phv/internal/mva"
	"github.com/SirojWongpitakroj/mva-phv/internal/phv"
	"github.com/SirojWongpitakroj/mva-phv/internal/storage/cassandra"
	"github.com/SirojWongpitakroj/mva-phv/internal/storage/postgresql/placement"
	"github.com/SirojWongpitakroj/mva-phv/internal/system"
)

// Run explicitly with MVA_LIVE_AUDIT=1 against the isolated 100k smoke stores.
func TestLiveSmokeAudit(t *testing.T) {
	if os.Getenv("MVA_LIVE_AUDIT") != "1" {
		t.Skip("live smoke audit is opt-in")
	}
	if err := loadEnvLocal(".env.local"); err != nil {
		t.Fatal(err)
	}
	base, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	os.Setenv("MVA_CASSANDRA_SSH_KNOWN_HOSTS", filepath.Join(filepath.Dir(base), ".cassandra_known_hosts"))
	deployment := os.Getenv("MVA_LIVE_DEPLOYMENT")
	if deployment == "" {
		deployment = "v2"
	}
	if deployment != "v2" && deployment != "v3" {
		t.Fatal("unsupported live smoke deployment")
	}
	os.Setenv("MVA_CP_DATABASE", "mva_phv_cp_smoke_100k_"+deployment)
	os.Setenv("MVA_CHECKPOINT_DATABASE", "mva_phv_checkpoint_smoke_100k_"+deployment)
	for _, suffix := range []string{"HOST", "PORT", "USER", "PASSWORD", "SSLMODE"} {
		os.Setenv("MVA_PLACEMENT_"+suffix, os.Getenv("MVA_CHECKPOINT_"+suffix))
	}
	os.Setenv("MVA_PLACEMENT_DATABASE", "mva_phv_placement_smoke_100k_"+deployment)
	os.Setenv("MVA_CASSANDRA_KEYSPACE", "mva_phv_smoke_100k_"+deployment)
	limit := 20 * time.Minute
	if os.Getenv("MVA_LIVE_AUDIT_MATRIX") == "1" {
		limit = 5 * time.Hour
	}
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	cpDB, err := openPostgreSQL(ctx, "MVA_CP")
	if err != nil {
		t.Fatal(err)
	}
	defer cpDB.Close()
	ckDB, err := openPostgreSQL(ctx, "MVA_CHECKPOINT")
	if err != nil {
		t.Fatal(err)
	}
	defer ckDB.Close()
	plDB, err := openPostgreSQL(ctx, "MVA_PLACEMENT")
	if err != nil {
		t.Fatal(err)
	}
	defer plDB.Close()
	client, stop, err := openCassandra()
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	defer client.Close()
	cls, err := cassandra.NewStore(client)
	if err != nil {
		t.Fatal(err)
	}
	cp, err := postgresql.New(cpDB)
	if err != nil {
		t.Fatal(err)
	}
	ck, err := checkpoint.NewMockCheckpointStore(ckDB)
	if err != nil {
		t.Fatal(err)
	}
	pl, err := placement.New(plDB)
	if err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(os.Getenv("MVA_PHV_ENCRYPTION_KEY_HEX"))
	if err != nil {
		t.Fatal(err)
	}
	app, err := system.NewWithStorage(system.Config{NumRegions: 4, ShardsPerRegion: 16, MaxSegmentSize: 1024, SealInterval: time.Minute, MVAOrder: 32, FilterItems: 10000, FalsePositive: 0.01, EncryptionKey: key, AuditWorkers: 8, SiteRegions: pl, DeviceShards: placement.ShardStore{Store: pl}}, cp, cls, ck)
	if err != nil {
		t.Fatal(err)
	}
	roots, err := (phv.CheckpointRoots{Evidence: cls, Checkpoints: ck}).Roots(ctx, 1)
	if err != nil {
		t.Fatalf("trusted roots: %v", err)
	}
	regions := []merkle.TreeID{{Type: merkle.TreeRegion, RegionID: "0"}, {Type: merkle.TreeRegion, RegionID: "1"}, {Type: merkle.TreeRegion, RegionID: "2"}, {Type: merkle.TreeRegion, RegionID: "3"}}
	var rawID string
	if err := cpDB.QueryRowContext(ctx, "SELECT log_id::text FROM encrypted_logs ORDER BY log_id LIMIT 1").Scan(&rawID); err != nil {
		t.Fatal(err)
	}
	id, err := uuid.Parse(rawID)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2017, 9, 25, 18, 0, 0, 0, time.UTC)
	if os.Getenv("MVA_LIVE_AUDIT_MATRIX") == "1" {
		runLiveLocalityBenchmark(t, ctx, cls, client, cp, ck, roots)
		return
	}
	if os.Getenv("MVA_LIVE_AUDIT_BATCH") == "1" {
		values, _, err := mva.ResolveHistorical(ctx, cls, 1, mva.SiteQuery{SiteID: "WADI:P1"}, regions, roots.MVA)
		if err != nil {
			t.Fatal(err)
		}
		bySegment := map[string][]mva.LogIDBatchTarget{}
		maxCount := 0
		var chosen []mva.LogIDBatchTarget
		for _, value := range values {
			key := value.RegionID + ":" + value.ShardID + ":" + value.SegmentID
			bySegment[key] = append(bySegment[key], mva.LogIDBatchTarget{ID: value.LocatorKey.LogID(), RegionID: value.RegionID})
			if len(bySegment[key]) > maxCount {
				maxCount = len(bySegment[key])
			}
			if len(bySegment[key]) >= 16 && len(chosen) == 0 {
				chosen = append([]mva.LogIDBatchTarget(nil), bySegment[key][:16]...)
			}
		}
		t.Logf("WADI:P1 maximum selected leaves in one Segment=%d", maxCount)
		maxSegmentLeaves := int64(0)
		for region := 0; region < 4; region++ {
			for shard := int64(0); shard < 16; shard++ {
				rows, err := client.Query(ctx, "SELECT seg_id,leaf_count FROM hmf_segments_by_shard WHERE rid=? AND sid=?", strconv.Itoa(region), shard)
				if err != nil {
					t.Fatal(err)
				}
				for rows.Next() {
					var seg, count int64
					if err := rows.Scan(&seg, &count); err != nil {
						rows.Close()
						t.Fatal(err)
					}
					if count > maxSegmentLeaves {
						maxSegmentLeaves = count
					}
				}
				if err := rows.Close(); err != nil {
					t.Fatal(err)
				}
			}
		}
		t.Logf("global maximum sealed Segment leaves=%d", maxSegmentLeaves)
		if len(chosen) != 16 {
			t.Fatal("no Segment has 16 selected records")
		}
		q, err := mva.NewLogIDBatchQuery(chosen)
		if err != nil {
			t.Fatal(err)
		}
		result, err := app.Audit(ctx, phv.Request{Epoch: 1, Query: q})
		if err != nil || !result.Verified || len(result.Proof.Selected) != 16 {
			t.Fatalf("batch audit: selected=%d valid=%v err=%v", len(result.Proof.Selected), result.Verified, err)
		}
		encoded, err := phv.EncodeProof(result.Proof)
		if err != nil {
			t.Fatal(err)
		}
		detached, err := phv.DecodeProof(encoded)
		if err != nil {
			t.Fatal(err)
		}
		checked, err := app.VerifyProof(ctx, detached)
		if err != nil || !checked.Valid {
			t.Fatalf("detached batch: valid=%v err=%v", checked.Valid, err)
		}
		m := result.Metrics
		t.Logf("exact_logid_batch: selected=%d MVA=%s MVA_proof=%d bytes HMF_plan=%s CLS=%s CP=%s verify=%s total=%s nodes=%d/%d proof=%d bytes", m.SelectedRecords, m.MVAResolutionTime, m.MVAProofBytes, m.PlanningTime, m.CLSRetrievalTime, m.CiphertextRetrievalTime, m.VerificationTime, m.TotalTime, m.UniqueNodes, m.NaiveNodes, m.ProofBytes)
		return
	}
	if os.Getenv("MVA_LIVE_AUDIT_TIME_ONLY") == "1" {
		result, err := app.Audit(ctx, phv.Request{Epoch: 1, Query: mva.TimeRangeQuery{StartTS: start, EndTS: start.Add(2 * time.Second)}})
		if err != nil || !result.Verified {
			t.Fatalf("cross-region timestamp audit: valid=%v err=%v", result.Verified, err)
		}
		checked, err := app.VerifyProof(ctx, result.Proof)
		if err != nil || !checked.Valid {
			t.Fatalf("cross-region detached proof: valid=%v err=%v", checked.Valid, err)
		}
		regionsSeen, shardsSeen, segmentsSeen := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
		for _, record := range result.Proof.Selected {
			a := record.Address
			regionsSeen[a.RegionID] = struct{}{}
			shard := a.RegionID + ":" + strconv.FormatInt(a.ShardID, 10)
			shardsSeen[shard] = struct{}{}
			segmentsSeen[shard+":"+strconv.FormatInt(a.SegmentID, 10)] = struct{}{}
		}
		m := result.Metrics
		if len(regionsSeen) < 2 || m.UniqueNodes >= m.NaiveNodes {
			t.Errorf("cross-region sharing: regions=%d nodes=%d/%d", len(regionsSeen), m.UniqueNodes, m.NaiveNodes)
		}
		t.Logf("cross_region_time: selected=%d regions=%d shards=%d segments=%d nodes=%d/%d MVA=%s MVA_proof=%d bytes HPBF=%s proof=%d bytes groups=%d requests=%d plan=%s CLS=%s CP=%s verify=%s total=%s", m.SelectedRecords, len(regionsSeen), len(shardsSeen), len(segmentsSeen), m.UniqueNodes, m.NaiveNodes, m.MVAResolutionTime, m.MVAProofBytes, m.HPBFPruningTime, m.ProofBytes, m.RetrievalGroups, m.RepositoryCalls, m.PlanningTime, m.CLSRetrievalTime, m.CiphertextRetrievalTime, m.VerificationTime, m.TotalTime)
		return
	}
	queries := []struct {
		name  string
		query mva.LocatorQuery
	}{
		{"log_id", mva.LogIDQuery{ID: id}},
		{"site", mva.SiteQuery{SiteID: "WADI:P1"}},
		{"site_device", mva.SiteDeviceQuery{SiteID: "WADI:P1", DevID: "FIT_001"}},
		{"site_device_type", mva.AttrRangeQuery{SiteID: "WADI:P1", DevID: "FIT_001", Type: "FIT_PV", StartTS: start.Add(-24 * time.Hour), EndTS: start.Add(365 * 24 * time.Hour)}},
		{"timestamp_range", mva.TimeRangeQuery{StartTS: start, EndTS: start.Add(2 * time.Second)}},
	}
	for _, q := range queries {
		if q.name == "timestamp_range" && os.Getenv("MVA_LIVE_AUDIT_FULL_TIME_SCAN") != "1" {
			t.Log("MVA timestamp_range: skipped broad full-index scan; set MVA_LIVE_AUDIT_FULL_TIME_SCAN=1 to run")
			continue
		}
		began := time.Now()
		values, proof, err := mva.ResolveHistorical(ctx, cls, 1, q.query, regions, roots.MVA)
		if err != nil {
			t.Errorf("%s MVA: %v", q.name, err)
			continue
		}
		if err := mva.VerifyResolution(q.query, regions, values, proof, roots.MVA); err != nil {
			t.Errorf("%s proof: %v", q.name, err)
			continue
		}
		for _, value := range values {
			if value == nil || value.LocatorKey == nil || value.RegionID == "" || value.ShardID == "" || value.SegmentID == "" || value.LeafID == "" {
				t.Errorf("%s invalid locator", q.name)
				break
			}
			for _, v := range []string{value.ShardID, value.SegmentID, value.LeafID} {
				if n, e := strconv.ParseInt(v, 10, 64); e != nil || n < 0 {
					t.Errorf("%s invalid address %q", q.name, v)
				}
			}
		}
		t.Logf("MVA %s: records=%d duration=%s", q.name, len(values), time.Since(began))
	}
	for _, tc := range []struct {
		name  string
		parts []string
		query mva.LocatorQuery
	}{
		{"site", []string{"WADI:P1"}, mva.SiteQuery{SiteID: "WADI:P1"}},
		{"site_device", []string{"WADI:P1", "FIT_001"}, mva.SiteDeviceQuery{SiteID: "WADI:P1", DevID: "FIT_001"}},
		{"site_device_type", []string{"WADI:P1", "FIT_001", "FIT_PV"}, mva.AttrRangeQuery{SiteID: "WADI:P1", DevID: "FIT_001", Type: "FIT_PV", StartTS: start.Add(-24 * time.Hour), EndTS: start.Add(365 * 24 * time.Hour)}},
	} {
		var tokens [3][]byte
		for i := range tokens {
			n := i + 1
			if n > len(tc.parts) {
				n = len(tc.parts)
			}
			tokens[i], err = domain.Serialize(anyStrings(tc.parts[:n])...)
			if err != nil {
				t.Fatal(err)
			}
		}
		pruned, err := (phv.HistoricalHPBFPruner{Source: cls}).Prune(ctx, 1, tokens, roots.HPBF)
		if err != nil {
			t.Errorf("%s HPBF: %v", tc.name, err)
			continue
		}
		t.Logf("HPBF %s: regions=%d/4 (%.1f%% pruned), shards=%d/64 (%.1f%% pruned)", tc.name, len(pruned.Regions), 100*(1-float64(len(pruned.Regions))/4), len(pruned.Shards), 100*(1-float64(len(pruned.Shards))/64))
	}
	for _, tc := range []struct {
		name  string
		query mva.LocatorQuery
		prune bool
	}{{"log_id", mva.LogIDQuery{ID: id}, false}, {"one_type", mva.AttrRangeQuery{SiteID: "WADI:P1", DevID: "FIT_001", Type: "FIT_PV", StartTS: start, EndTS: start}, true}} {
		began := time.Now()
		result, err := app.Audit(ctx, phv.Request{Epoch: 1, Query: tc.query, UsePruning: tc.prune})
		if err != nil {
			t.Errorf("PHV %s: %v", tc.name, err)
			continue
		}
		if !result.Verified {
			t.Errorf("PHV %s: invalid result: %v", tc.name, result.IntegrityError)
			continue
		}
		verification, err := app.VerifyProof(ctx, result.Proof)
		if err != nil || !verification.Valid {
			t.Errorf("PHV %s detached: valid=%v error=%v", tc.name, verification.Valid, err)
			continue
		}
		m := result.Metrics
		t.Logf("PHV %s: selected=%d nodes=%d/%d MVA=%s MVA_proof=%d bytes HPBF=%s proof=%d bytes requests=%d plan=%s CLS=%s CP=%s verify=%s total=%s wall=%s", tc.name, m.SelectedRecords, m.UniqueNodes, m.NaiveNodes, m.MVAResolutionTime, m.MVAProofBytes, m.HPBFPruningTime, m.ProofBytes, m.RepositoryCalls, m.PlanningTime, m.CLSRetrievalTime, m.CiphertextRetrievalTime, m.VerificationTime, m.TotalTime, time.Since(began))
		if tc.name == "one_type" {
			encoded, err := phv.EncodeProof(result.Proof)
			if err != nil {
				t.Fatal(err)
			}
			altered, err := phv.DecodeProof(encoded)
			if err != nil {
				t.Fatal(err)
			}
			altered.Logs[0].Ciphertext[0] ^= 1
			bad, err := phv.VerifyAuditProof(ctx, altered, ck)
			if err != nil || bad.Valid || bad.GlobalRoot == roots.HMF {
				t.Errorf("tampered ciphertext accepted or unclassified: valid=%v err=%v", bad.Valid, err)
				continue
			}
			localized := phv.Localize(ctx, cls, altered, roots.HMF, bad)
			found := map[merkle.TreeType]bool{}
			for _, f := range localized.Failures {
				if !f.Unresolved {
					found[f.Tree.Type] = true
				}
			}
			t.Logf("tamper localization: failures=%d examined=%d pruned=%d expanded=%d", len(localized.Failures), localized.Examined, localized.Pruned, localized.Expanded)
			for _, kind := range []merkle.TreeType{merkle.TreeRegion, merkle.TreeShard, merkle.TreeSegment} {
				if !found[kind] {
					t.Errorf("tamper localization missing %s", kind)
				}
			}
			if !found[merkle.TreeSegment] {
				t.Errorf("tamper localization did not reach record")
			}
			alteredNode, err := phv.DecodeProof(encoded)
			if err != nil {
				t.Fatal(err)
			}
			if len(alteredNode.Nodes) == 0 {
				t.Fatal("no HMF frontier node to alter")
			}
			alteredNode.Nodes[0].Hash[0] ^= 1
			badNode, err := phv.VerifyAuditProof(ctx, alteredNode, ck)
			if err != nil || badNode.Valid {
				t.Errorf("altered HMF evidence accepted: valid=%v err=%v", badNode.Valid, err)
			} else {
				where := phv.Localize(ctx, cls, alteredNode, roots.HMF, badNode)
				if len(where.Failures) == 0 {
					t.Error("altered HMF frontier produced no localization outcome")
				}
				for _, failure := range where.Failures {
					if failure.LogID != (uuid.UUID{}) && !failure.Unresolved {
						t.Errorf("frontier corruption falsely confirmed record tampering: %+v", failure)
					}
				}
				t.Logf("altered HMF frontier: invalid, localization failures=%d (a frontier mismatch must not be called record tampering)", len(where.Failures))
			}
		}
	}
	if os.Getenv("MVA_LIVE_AUDIT_BENCH") == "1" {
		for _, n := range []int{1, 16, 64, 256} {
			query := mva.AttrRangeQuery{SiteID: "WADI:P1", DevID: "FIT_001", Type: "FIT_PV", StartTS: start, EndTS: start.Add(time.Duration(n-1) * time.Second)}
			result, err := app.Audit(ctx, phv.Request{Epoch: 1, Query: query, UsePruning: true})
			if err != nil || !result.Verified {
				t.Errorf("clustered %d: valid=%v err=%v", n, result.Verified, err)
				continue
			}
			if result.Metrics.SelectedRecords != n {
				t.Errorf("clustered %d selected %d", n, result.Metrics.SelectedRecords)
			}
			m := result.Metrics
			if n > 1 && m.UniqueNodes >= m.NaiveNodes {
				t.Errorf("clustered %d did not share nodes: %d/%d", n, m.UniqueNodes, m.NaiveNodes)
			}
			t.Logf("clustered %d: selected=%d nodes=%d/%d proof=%d bytes groups=%d requests=%d plan=%s CLS=%s CP=%s verify=%s total=%s", n, m.SelectedRecords, m.UniqueNodes, m.NaiveNodes, m.ProofBytes, m.RetrievalGroups, m.RepositoryCalls, m.PlanningTime, m.CLSRetrievalTime, m.CiphertextRetrievalTime, m.VerificationTime, m.TotalTime)
		}
		result, err := app.Audit(ctx, phv.Request{Epoch: 1, Query: mva.SiteQuery{SiteID: "WADI:P2A"}, UsePruning: true})
		if err != nil || !result.Verified {
			t.Errorf("spread_shards: valid=%v err=%v", result.Verified, err)
		} else {
			shards := map[string]struct{}{}
			segments := map[string]struct{}{}
			for _, record := range result.Proof.Selected {
				a := record.Address
				shard := a.RegionID + ":" + strconv.FormatInt(a.ShardID, 10)
				shards[shard] = struct{}{}
				segments[shard+":"+strconv.FormatInt(a.SegmentID, 10)] = struct{}{}
			}
			m := result.Metrics
			t.Logf("spread_shards: selected=%d shards=%d segments=%d nodes=%d/%d proof=%d bytes groups=%d requests=%d plan=%s CLS=%s CP=%s verify=%s total=%s", m.SelectedRecords, len(shards), len(segments), m.UniqueNodes, m.NaiveNodes, m.ProofBytes, m.RetrievalGroups, m.RepositoryCalls, m.PlanningTime, m.CLSRetrievalTime, m.CiphertextRetrievalTime, m.VerificationTime, m.TotalTime)
		}
	}
}

func anyStrings(values []string) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}
