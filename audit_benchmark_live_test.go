package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"testing"
	"time"
	"uuid"

	"github.com/SirojWongpitakroj/mva-phv/internal/cloudprovider"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
	"github.com/SirojWongpitakroj/mva-phv/internal/mpm"
	"github.com/SirojWongpitakroj/mva-phv/internal/mva"
	"github.com/SirojWongpitakroj/mva-phv/internal/phv"
	"github.com/SirojWongpitakroj/mva-phv/internal/storage/cassandra"
	"github.com/gocql/gocql"
)

type benchPosition struct {
	ID                 uuid.UUID
	RID                string
	SID, SegID, LeafID int64
}
type benchStats struct{ Median, Mean, StdDev, P95 float64 }
type benchCaseReport struct {
	Locality             string     `json:"locality"`
	Requested            int        `json:"requested"`
	Available            bool       `json:"available"`
	Reason               string     `json:"reason,omitempty"`
	Regions              int        `json:"regions,omitempty"`
	Shards               int        `json:"shards,omitempty"`
	Segments             int        `json:"segments,omitempty"`
	Warmups              int        `json:"warmups,omitempty"`
	Measured             int        `json:"measured,omitempty"`
	MVAResolutionMs      float64    `json:"mva_resolution_ms,omitempty"`
	MVAResolutionStatsMs benchStats `json:"mva_resolution_stats_ms"`
	MVAProofBytes        int64      `json:"mva_proof_bytes,omitempty"`
	HPBFPruningMs        benchStats `json:"hpbf_pruning_ms"`
	HMFPlanningMs        benchStats `json:"hmf_planning_ms"`
	CLSRetrievalMs       benchStats `json:"cassandra_proof_retrieval_ms"`
	CPRetrievalMs        benchStats `json:"cp_ciphertext_retrieval_ms"`
	PHVVerificationMs    benchStats `json:"phv_verification_ms"`
	PHVTotalMs           benchStats `json:"phv_total_ms"`
	EndToEndMs           benchStats `json:"end_to_end_total_ms"`
	ProofBytes           benchStats `json:"complete_proof_bytes"`
	StorageCalls         benchStats `json:"repository_calls"`
	UniqueNodes          int        `json:"unique_nodes,omitempty"`
	NaiveNodes           int        `json:"naive_nodes,omitempty"`
}
type benchReport struct {
	Epoch            uint64            `json:"epoch"`
	Source           string            `json:"source"`
	MaxSegmentLeaves int64             `json:"max_segment_leaves"`
	Cases            []benchCaseReport `json:"cases"`
	Notes            []string          `json:"notes"`
}

func stats(values []float64) benchStats {
	if len(values) == 0 {
		return benchStats{}
	}
	v := slices.Clone(values)
	sort.Float64s(v)
	var sum float64
	for _, x := range v {
		sum += x
	}
	mean := sum / float64(len(v))
	var variance float64
	for _, x := range v {
		d := x - mean
		variance += d * d
	}
	variance /= float64(len(v))
	median := v[len(v)/2]
	if len(v)%2 == 0 {
		median = (v[len(v)/2-1] + v[len(v)/2]) / 2
	}
	return benchStats{Median: median, Mean: mean, StdDev: math.Sqrt(variance), P95: v[int(math.Ceil(0.95*float64(len(v))))-1]}
}

func TestBenchmarkStatsAndLocalitySelection(t *testing.T) {
	values := make([]float64, 20)
	for i := range values {
		values[i] = float64(i + 1)
	}
	s := stats(values)
	if s.Median != 10.5 || s.Mean != 10.5 || s.P95 != 19 || s.StdDev <= 0 {
		t.Fatalf("wrong summary statistics: %+v", s)
	}
	var all []benchPosition
	for r := 0; r < 4; r++ {
		for shard := 0; shard < 4; shard++ {
			for segment := 0; segment < 2; segment++ {
				for leaf := 0; leaf < 1024; leaf++ {
					all = append(all, benchPosition{RID: strconv.Itoa(r), SID: int64(shard), SegID: int64(segment), LeafID: int64(leaf)})
				}
			}
		}
	}
	for _, tc := range []struct {
		kind                                  string
		wantRegions, wantShards, wantSegments int
	}{
		{"same_segment", 1, 1, 1}, {"same_shard_multiple_segments", 1, 1, 2}, {"multiple_shards_one_region", 1, 4, 4}, {"multiple_regions", 4, 16, 16},
	} {
		selected := selectBenchCase(all, tc.kind, 1024)
		regions, shards, segments := map[string]bool{}, map[string]bool{}, map[string]bool{}
		for _, p := range selected {
			regions[p.RID] = true
			k := fmt.Sprintf("%s/%d", p.RID, p.SID)
			shards[k] = true
			segments[fmt.Sprintf("%s/%d", k, p.SegID)] = true
		}
		if len(selected) != 1024 || len(regions) != tc.wantRegions || len(shards) != tc.wantShards || len(segments) != tc.wantSegments {
			t.Fatalf("%s: selected=%d regions=%d shards=%d segments=%d", tc.kind, len(selected), len(regions), len(shards), len(segments))
		}
	}
}
func benchCountEnv(name string, fallback int) int {
	n, e := strconv.Atoi(os.Getenv(name))
	if e != nil || n < 0 {
		return fallback
	}
	return n
}

type cachedBenchResolver struct {
	query      mva.LocatorQuery
	regions    []merkle.TreeID
	root       [32]byte
	resolution phv.Resolution
}

func (r cachedBenchResolver) Resolve(ctx context.Context, epoch uint64, q mva.LocatorQuery, regions []merkle.TreeID, root [32]byte) (phv.Resolution, error) {
	if err := ctx.Err(); err != nil {
		return phv.Resolution{}, err
	}
	if epoch != r.resolution.Epoch || root != r.root || !reflect.DeepEqual(q, r.query) || !reflect.DeepEqual(regions, r.regions) {
		return phv.Resolution{}, fmt.Errorf("benchmark: cached MVA scope differs")
	}
	return r.resolution, nil
}

func scanBenchmarkPositions(ctx context.Context, client *cassandra.GocqlClient) ([]benchPosition, error) {
	// One-time experiment selection scan, outside every timed PHV audit.
	rows, err := client.Query(ctx, "SELECT log_id,rid,sid,seg_id,leaf_id FROM log_addresses_by_id")
	if err != nil {
		return nil, err
	}
	var out []benchPosition
	for rows.Next() {
		var id gocql.UUID
		var p benchPosition
		if err := rows.Scan(&id, &p.RID, &p.SID, &p.SegID, &p.LeafID); err != nil {
			rows.Close()
			return nil, err
		}
		p.ID = uuid.UUID(id)
		out = append(out, p)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.RID != b.RID {
			return a.RID < b.RID
		}
		if a.SID != b.SID {
			return a.SID < b.SID
		}
		if a.SegID != b.SegID {
			return a.SegID < b.SegID
		}
		return a.LeafID < b.LeafID
	})
	return out, nil
}
func groupBench(positions []benchPosition, key func(benchPosition) string) map[string][]benchPosition {
	out := map[string][]benchPosition{}
	for _, p := range positions {
		out[key(p)] = append(out[key(p)], p)
	}
	return out
}
func sortedBenchKeys(groups map[string][]benchPosition) []string {
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
func roundRobinBench(groups map[string][]benchPosition, n int) []benchPosition {
	keys := sortedBenchKeys(groups)
	indices := make(map[string]int, len(keys))
	out := make([]benchPosition, 0, n)
	for len(out) < n {
		advanced := false
		for _, key := range keys {
			index := indices[key]
			if index < len(groups[key]) {
				out = append(out, groups[key][index])
				indices[key]++
				advanced = true
				if len(out) == n {
					break
				}
			}
		}
		if !advanced {
			break
		}
	}
	return out
}
func selectBenchCase(all []benchPosition, locality string, n int) []benchPosition {
	segments := groupBench(all, func(p benchPosition) string { return fmt.Sprintf("%s/%d/%d", p.RID, p.SID, p.SegID) })
	shards := groupBench(all, func(p benchPosition) string { return fmt.Sprintf("%s/%d", p.RID, p.SID) })
	regions := groupBench(all, func(p benchPosition) string { return p.RID })
	switch locality {
	case "same_segment":
		for _, key := range sortedBenchKeys(segments) {
			if len(segments[key]) >= n {
				return slices.Clone(segments[key][:n])
			}
		}
	case "same_shard_multiple_segments":
		for _, key := range sortedBenchKeys(shards) {
			if len(shards[key]) < n {
				continue
			}
			parts := groupBench(shards[key], func(p benchPosition) string { return strconv.FormatInt(p.SegID, 10) })
			if len(parts) >= 2 {
				return roundRobinBench(parts, n)
			}
		}
	case "multiple_shards_one_region":
		for _, key := range sortedBenchKeys(regions) {
			if len(regions[key]) < n {
				continue
			}
			parts := groupBench(regions[key], func(p benchPosition) string { return strconv.FormatInt(p.SID, 10) })
			if len(parts) >= 2 {
				return roundRobinBench(parts, n)
			}
		}
	case "multiple_regions":
		if len(regions) >= 2 {
			spread := make(map[string][]benchPosition, len(regions))
			for rid, records := range regions {
				byShard := groupBench(records, func(p benchPosition) string { return strconv.FormatInt(p.SID, 10) })
				spread[rid] = roundRobinBench(byShard, len(records))
			}
			return roundRobinBench(spread, n)
		}
	}
	return nil
}

// runLiveLocalityBenchmark runs when MVA_LIVE_AUDIT_MATRIX=1. Counts default to
// five warmups and 20 measured runs; the result stays outside the public repo.
func runLiveLocalityBenchmark(t *testing.T, ctx context.Context, cls *cassandra.Store, client *cassandra.GocqlClient, cp cloudprovider.Reader, ck mpm.CheckpointStore, roots mpm.Roots) {
	t.Helper()
	all, err := scanBenchmarkPositions(ctx, client)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 100000 {
		t.Fatalf("benchmark selection index has %d LogIDs, want 100000", len(all))
	}
	maxSegment := int64(0)
	for _, g := range groupBench(all, func(p benchPosition) string { return fmt.Sprintf("%s/%d/%d", p.RID, p.SID, p.SegID) }) {
		if int64(len(g)) > maxSegment {
			maxSegment = int64(len(g))
		}
	}
	deployment := os.Getenv("MVA_LIVE_DEPLOYMENT")
	if deployment == "" {
		deployment = "v2"
	}
	report := benchReport{Epoch: 1, Source: "isolated 100k smoke " + deployment, MaxSegmentLeaves: maxSegment, Notes: []string{
		"Selection scans the LogID-address index once before timing; PHV audits request exact LogIDs and never scan it.",
		"Every run resolves and authenticates its MVA batch, then runs PHV against a verified cached scope so the two costs remain separate.",
		"LogID batch queries have no HPBF token, so HPBF pruning time is zero.",
		"Timestamp-only predicates lack an attribute prefix and require broad authenticated MVA resolution; this matrix intentionally selects exact LogIDs instead.",
		"CP and CLS retrieval overlap; their durations must not be summed to derive total latency.",
	}}
	regions := []merkle.TreeID{{Type: merkle.TreeRegion, RegionID: "0"}, {Type: merkle.TreeRegion, RegionID: "1"}, {Type: merkle.TreeRegion, RegionID: "2"}, {Type: merkle.TreeRegion, RegionID: "3"}}
	warmups, measured := benchCountEnv("MVA_BENCH_WARMUPS", 5), benchCountEnv("MVA_BENCH_RUNS", 20)
	if measured < 1 {
		t.Fatal("MVA_BENCH_RUNS must be positive")
	}
	for _, locality := range []string{"same_segment", "same_shard_multiple_segments", "multiple_shards_one_region", "multiple_regions"} {
		if only := os.Getenv("MVA_BENCH_LOCALITY"); only != "" && only != locality {
			continue
		}
		for _, n := range []int{16, 64, 256, 1024} {
			entry := benchCaseReport{Locality: locality, Requested: n}
			selected := selectBenchCase(all, locality, n)
			if len(selected) != n {
				entry.Reason = fmt.Sprintf("only %d leaves in largest sealed Segment or insufficient locality pool", maxSegment)
				report.Cases = append(report.Cases, entry)
				t.Logf("%s/%d unavailable: %s", locality, n, entry.Reason)
				continue
			}
			regionSet, shardSet, segmentSet := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
			targets := make([]mva.LogIDBatchTarget, 0, n)
			for _, p := range selected {
				regionSet[p.RID] = struct{}{}
				shard := fmt.Sprintf("%s/%d", p.RID, p.SID)
				shardSet[shard] = struct{}{}
				segmentSet[fmt.Sprintf("%s/%d", shard, p.SegID)] = struct{}{}
				targets = append(targets, mva.LogIDBatchTarget{ID: p.ID, RegionID: p.RID})
			}
			q, err := mva.NewLogIDBatchQuery(targets)
			if err != nil {
				t.Fatal(err)
			}
			mvaStarted := time.Now()
			resolved, err := (phv.HistoricalMVAResolver{Reader: cls}).Resolve(ctx, 1, q, regions, roots.MVA)
			entry.MVAResolutionMs = float64(time.Since(mvaStarted)) / float64(time.Millisecond)
			if err != nil {
				t.Fatalf("%s/%d MVA resolution: %v", locality, n, err)
			}
			entry.MVAProofBytes, err = phv.MVAProofSize(resolved.Proof)
			if err != nil {
				t.Fatal(err)
			}
			auditor := &phv.Auditor{Roots: phv.CheckpointRoots{Evidence: cls, Checkpoints: ck}, Resolver: cachedBenchResolver{query: q, regions: regions, root: roots.MVA, resolution: resolved}, Repository: cls, Ciphertexts: cp, Topology: phv.Topology{RegionIDs: []string{"0", "1", "2", "3"}, ShardsPerRegion: 16}, Workers: 8}
			entry.Available = true
			entry.Regions = len(regionSet)
			entry.Shards = len(shardSet)
			entry.Segments = len(segmentSet)
			entry.Warmups = warmups
			entry.Measured = measured
			var mvaTimes, plan, clsTimes, cpTimes, verify, total, endToEnd, proofSizes, calls []float64
			for run := 0; run < warmups+measured; run++ {
				mvaDuration := entry.MVAResolutionMs
				if run > 0 {
					began := time.Now()
					again, resolveErr := (phv.HistoricalMVAResolver{Reader: cls}).Resolve(ctx, 1, q, regions, roots.MVA)
					mvaDuration = float64(time.Since(began)) / float64(time.Millisecond)
					if resolveErr != nil || len(again.Records) != n {
						t.Fatalf("%s/%d MVA run %d: selected=%d err=%v", locality, n, run, len(again.Records), resolveErr)
					}
				}
				result, err := auditor.Audit(ctx, phv.Request{Epoch: 1, Query: q})
				if err != nil || !result.Verified || result.Metrics.SelectedRecords != n {
					t.Fatalf("%s/%d run %d: verified=%v selected=%d err=%v", locality, n, run, result.Verified, result.Metrics.SelectedRecords, err)
				}
				if run == 0 {
					checked, e := phv.VerifyAuditProof(ctx, result.Proof, ck)
					if e != nil || !checked.Valid {
						t.Fatalf("%s/%d detached proof: valid=%v err=%v", locality, n, checked.Valid, e)
					}
				}
				if run < warmups {
					continue
				}
				m := result.Metrics
				entry.UniqueNodes, entry.NaiveNodes = m.UniqueNodes, m.NaiveNodes
				mvaTimes = append(mvaTimes, mvaDuration)
				plan = append(plan, float64(m.PlanningTime)/1e6)
				clsTimes = append(clsTimes, float64(m.CLSRetrievalTime)/1e6)
				cpTimes = append(cpTimes, float64(m.CiphertextRetrievalTime)/1e6)
				verify = append(verify, float64(m.VerificationTime)/1e6)
				total = append(total, float64(m.TotalTime)/1e6)
				endToEnd = append(endToEnd, float64(m.TotalTime)/1e6+mvaDuration)
				proofSizes = append(proofSizes, float64(m.ProofBytes))
				calls = append(calls, float64(m.RepositoryCalls))
			}
			entry.MVAResolutionStatsMs = stats(mvaTimes)
			entry.HMFPlanningMs, entry.CLSRetrievalMs, entry.CPRetrievalMs = stats(plan), stats(clsTimes), stats(cpTimes)
			entry.PHVVerificationMs, entry.PHVTotalMs, entry.EndToEndMs = stats(verify), stats(total), stats(endToEnd)
			entry.ProofBytes, entry.StorageCalls = stats(proofSizes), stats(calls)
			report.Cases = append(report.Cases, entry)
			t.Logf("%s/%d: MVA %.1f ms, MVA proof %d B, PHV median %.1f ms, nodes %d/%d", locality, n, entry.MVAResolutionMs, entry.MVAProofBytes, entry.PHVTotalMs.Median, entry.UniqueNodes, entry.NaiveNodes)
		}
	}
	root := filepath.Join("..", "results", "phv")
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "smoke_100k_"+deployment+"_"+time.Now().UTC().Format("20060102T150405Z")+".json")
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Logf("private benchmark report: %s", path)
}
