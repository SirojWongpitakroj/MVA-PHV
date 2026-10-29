package system

import (
	"context"
	"errors"
	"testing"
	"time"
	"uuid"

	"github.com/SirojWongpitakroj/mva-phv/internal/cloudprovider"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
	"github.com/SirojWongpitakroj/mva-phv/internal/mpm"
	"github.com/SirojWongpitakroj/mva-phv/internal/mva"
	"github.com/SirojWongpitakroj/mva-phv/internal/phv"
	"github.com/SirojWongpitakroj/mva-phv/internal/storage/cassandra"
)

type connectTestCQL struct{}

func (connectTestCQL) Exec(context.Context, string, ...any) error { return nil }
func (connectTestCQL) Query(context.Context, string, ...any) (cassandra.Rows, error) {
	return nil, nil
}
func (connectTestCQL) ExecIfNotExists(context.Context, string, ...any) (bool, error) {
	return true, nil
}

func TestNewWithStorageUsesDistinctPersistenceBoundaries(t *testing.T) {
	cls, err := cassandra.NewStore(connectTestCQL{})
	if err != nil {
		t.Fatal(err)
	}
	cp := cloudprovider.NewMemory()
	checkpoints := NewMemoryCheckpoints()
	s, err := NewWithStorage(testConfig(), cp, cls, checkpoints)
	if err != nil {
		t.Fatal(err)
	}
	if s.ciphertexts != cp || s.auditor.Repository != cls || s.trusted != checkpoints || s.evidence != nil {
		t.Fatal("persistent system reused a memory evidence store or changed an injected dependency")
	}
	if _, ok := s.auditor.Roots.(phv.CheckpointRoots); !ok {
		t.Fatal("persistent audits did not authenticate CLS roots against the checkpoint store")
	}
	if _, ok := s.auditor.Pruner.(phv.HistoricalHPBFPruner); !ok {
		t.Fatal("persistent audits did not read finalized HPBF evidence")
	}
	if _, ok := s.auditor.Resolver.(phv.HistoricalMVAResolver); !ok {
		t.Fatal("persistent audits did not read finalized MVA evidence")
	}
}

func testConfig() Config {
	return Config{NumRegions: 2, ShardsPerRegion: 2, MaxSegmentSize: 2,
		SealInterval: time.Hour, MVAOrder: 3, FilterItems: 100,
		FalsePositive: 0.01, EncryptionKey: make([]byte, 32), AuditWorkers: 4}
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	for _, change := range []func(*Config){
		func(c *Config) { c.NumRegions = 0 },
		func(c *Config) { c.ShardsPerRegion = 0 },
		func(c *Config) { c.MaxSegmentSize = 0 },
		func(c *Config) { c.SealInterval = 0 },
		func(c *Config) { c.MVAOrder = 2 },
		func(c *Config) { c.FilterItems = 0 },
		func(c *Config) { c.FalsePositive = 1 },
		func(c *Config) { c.EncryptionKey = nil },
		func(c *Config) { c.AuditWorkers = -1 },
	} {
		config := testConfig()
		change(&config)
		if _, err := New(config); err == nil {
			t.Fatalf("accepted invalid config %+v", config)
		}
	}
}

func TestNewWithProviderSharesExternalCPAcrossIngestionAndAudit(t *testing.T) {
	if _, err := NewWithProvider(testConfig(), nil); err == nil {
		t.Fatal("nil CP accepted")
	}
	provider := cloudprovider.NewMemory()
	config := testConfig()
	config.MaxSegmentSize = 1
	s, err := NewWithProvider(config, provider)
	if err != nil {
		t.Fatal(err)
	}
	if s.ciphertexts != provider {
		t.Fatal("injected CP was replaced")
	}
	ctx := context.Background()
	input := mpm.Input{RegionID: "0", SiteID: "P3", DeviceID: "P3_LIT01", Type: "LevelReading", TS: time.Unix(500, 0), Plaintext: []byte("sensor event")}
	receipt, err := s.Ingest(ctx, input, input.TS)
	if err != nil {
		t.Fatal(err)
	}
	values, err := provider.GetCiphertexts(ctx, "0", []uuid.UUID{receipt.LogID})
	if err != nil || len(values) != 1 {
		t.Fatalf("injected CP did not receive log: %+v, %v", values, err)
	}
	if _, err := s.PrepareFinalization(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitFinalization(ctx, 1); err != nil {
		t.Fatal(err)
	}
	result, err := s.Audit(ctx, phv.Request{Epoch: 1, Query: mva.LogIDQuery{ID: receipt.LogID}})
	if err != nil || !result.Verified {
		t.Fatalf("audit did not use injected CP: verified=%v err=%v", result.Verified, err)
	}
}

type countingCiphertextReader struct {
	cloudprovider.Reader
	calls int
}

func (r *countingCiphertextReader) GetCiphertexts(ctx context.Context, region string, ids []uuid.UUID) ([]cloudprovider.Ciphertext, error) {
	r.calls++
	return r.Reader.GetCiphertexts(ctx, region, ids)
}

func TestCheckpointOutageStopsAuditBeforeCPRead(t *testing.T) {
	config := testConfig()
	config.MaxSegmentSize = 1
	s, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	input := mpm.Input{RegionID: "0", SiteID: "P3", DeviceID: "P3_LIT01", Type: "LevelReading", TS: time.Unix(700, 0), Plaintext: []byte("event")}
	receipt, err := s.Ingest(ctx, input, input.TS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareFinalization(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitFinalization(ctx, 1); err != nil {
		t.Fatal(err)
	}
	spy := &countingCiphertextReader{Reader: s.ciphertexts}
	s.auditor.Ciphertexts = spy
	s.checkpoints.mu.Lock()
	delete(s.checkpoints.values, 1)
	s.checkpoints.mu.Unlock()
	if _, err := s.Audit(ctx, phv.Request{Epoch: 1, Query: mva.LogIDQuery{ID: receipt.LogID}}); err == nil || spy.calls != 0 {
		t.Fatalf("CP queried without trusted checkpoint: calls=%d err=%v", spy.calls, err)
	}
}

func TestCLSEvidenceOutageIsNotCiphertextTampering(t *testing.T) {
	s, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	input := mpm.Input{RegionID: "0", SiteID: "P3", DeviceID: "P3_LIT01", Type: "LevelReading", TS: time.Unix(800, 0), Plaintext: []byte("event")}
	first, err := s.Ingest(ctx, input, input.TS)
	if err != nil {
		t.Fatal(err)
	}
	input.TS = input.TS.Add(time.Second)
	if _, err := s.Ingest(ctx, input, input.TS); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareFinalization(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitFinalization(ctx, 1); err != nil {
		t.Fatal(err)
	}
	segment := merkle.TreeID{Type: merkle.TreeSegment, RegionID: first.Address.RegionID, ShardID: first.Address.ShardID, SegmentID: first.Address.SegmentID}
	// The second leaf is the first leaf's required frontier sibling.
	s.evidence.mu.Lock()
	delete(s.evidence.segmentNode, phv.NodeKey{Tree: segment, Level: 0, Index: 1})
	s.evidence.mu.Unlock()
	result, err := s.Audit(ctx, phv.Request{Epoch: 1, Query: mva.LogIDQuery{ID: first.LogID}})
	if !errors.Is(err, phv.ErrRepositoryFailure) || !result.Unresolved || result.Verified {
		t.Fatalf("missing CLS frontier classified as tampering: verified=%v unresolved=%v err=%v", result.Verified, result.Unresolved, err)
	}
	values, err := s.ciphertexts.GetCiphertexts(ctx, "0", []uuid.UUID{first.LogID})
	if err != nil || len(values) != 1 {
		t.Fatalf("CP was incorrectly tied to CLS outage: %+v, %v", values, err)
	}
}

func TestFirstIngestionFinalizationAndAuditThroughSystem(t *testing.T) {
	s, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Unix(1000, 0).UTC()
	input := func(region string, i int) mpm.Input {
		return mpm.Input{RegionID: region, SiteID: "site", DeviceID: "device",
			Type: "alarm", TS: now.Add(time.Duration(i) * time.Second), Plaintext: []byte{byte(i)}}
	}
	first, err := s.Ingest(ctx, input("0", 1), now)
	if err != nil || first.Address.RegionID != "0" || first.Address.SegmentID != 0 || first.Address.LeafID != 0 {
		t.Fatalf("first ingest=%+v err=%v", first, err)
	}
	if len(s.manager.PendingSegments()) != 0 {
		t.Fatal("active Segment became pending before sealing")
	}
	second, err := s.Ingest(ctx, input("0", 2), now.Add(time.Second))
	if err != nil || second.Address.ShardID != first.Address.ShardID || second.Address.SegmentID != 0 || second.Address.LeafID != 1 {
		t.Fatalf("second ingest=%+v err=%v", second, err)
	}
	if len(s.manager.PendingSegments()) != 1 || len(s.evidence.segments) != 1 || len(s.evidence.segmentNode) < 2 {
		t.Fatal("sealed Segment proof nodes were not retained in memory")
	}
	query := mva.AttrRangeQuery{SiteID: "site", DevID: "device", Type: "alarm",
		StartTS: now.Add(time.Second), EndTS: now.Add(2 * time.Second)}
	request := phv.Request{Epoch: 1, Query: query, UsePruning: true}
	if _, err := s.Audit(ctx, request); err == nil {
		t.Fatal("candidate epoch was auditable before checkpoint commitment")
	}
	candidate, err := s.PrepareFinalization(ctx, 1)
	if err != nil || len(candidate.Records) != 2 || len(candidate.Segments) != 1 {
		t.Fatalf("candidate=%+v err=%v", candidate, err)
	}
	if _, err := s.Audit(ctx, request); err == nil {
		t.Fatal("prepared but uncommitted epoch was auditable")
	}
	checkpoint, err := s.CommitFinalization(ctx, 1)
	if err != nil || checkpoint != candidate.Checkpoint {
		t.Fatalf("commit checkpoint=%x err=%v", checkpoint, err)
	}
	epoch, roots := s.Finalized()
	if epoch != 1 || roots != candidate.Roots {
		t.Fatalf("finalized epoch/root=%d/%+v", epoch, roots)
	}
	result, err := s.Audit(ctx, request)
	if err != nil || !result.Verified || len(result.Proof.Selected) != 2 || result.Proof.HPBF == nil {
		t.Fatalf("first audit=%+v err=%v", result.Metrics, err)
	}
	verified, err := s.VerifyProof(ctx, result.Proof)
	if err != nil || !verified.Valid || verified.GlobalRoot != roots.HMF {
		t.Fatalf("detached proof=%+v err=%v", verified, err)
	}
	if err := s.checkpoints.Commit(ctx, 1, checkpoint); err != nil {
		t.Fatalf("identical checkpoint retry: %v", err)
	}
	if err := s.checkpoints.Commit(ctx, 1, [32]byte{9}); err == nil {
		t.Fatal("conflicting checkpoint replaced the finalized checkpoint")
	}

	// A later Region starts a new pending generation. The first audit remains
	// tied to epoch 1 until the next checkpoint has been committed.
	for i := 3; i <= 4; i++ {
		if _, err := s.Ingest(ctx, input("1", i), now.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatalf("second Region ingest %d: %v", i, err)
		}
	}
	before, err := s.Audit(ctx, request)
	if err != nil || !before.Verified || len(before.Proof.Selected) != 2 {
		t.Fatalf("working records leaked into epoch 1 audit: %+v, %v", before.Metrics, err)
	}
	candidate, err = s.PrepareFinalization(ctx, 2)
	if err != nil || len(candidate.Records) != 2 {
		t.Fatalf("second candidate=%+v err=%v", candidate, err)
	}
	if _, err := s.CommitFinalization(ctx, 2); err != nil {
		t.Fatal(err)
	}
	all, err := s.Audit(ctx, phv.Request{Epoch: 2, Query: mva.SiteQuery{SiteID: "site"}, UsePruning: true})
	if err != nil || !all.Verified || len(all.Proof.Selected) != 4 {
		t.Fatalf("cross-Region audit=%+v err=%v", all.Metrics, err)
	}
	if _, err := s.Audit(ctx, request); err == nil {
		t.Fatal("current-only in-memory auditor accepted an older epoch")
	}
}

func TestTimedSealBecomesAuditableOnlyAfterFinalization(t *testing.T) {
	config := testConfig()
	config.MaxSegmentSize = 10
	config.SealInterval = time.Minute
	s, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Unix(2000, 0).UTC()
	receipt, err := s.Ingest(ctx, mpm.Input{RegionID: "0", SiteID: "site", DeviceID: "device",
		Type: "alarm", TS: now, Plaintext: []byte("one")}, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SealExpired(ctx, now.Add(30*time.Second)); err != nil || len(s.manager.PendingSegments()) != 0 {
		t.Fatalf("early seal: pending=%d err=%v", len(s.manager.PendingSegments()), err)
	}
	if err := s.SealExpired(ctx, now.Add(2*time.Minute)); err != nil || len(s.manager.PendingSegments()) != 1 {
		t.Fatalf("expired seal: pending=%d err=%v", len(s.manager.PendingSegments()), err)
	}
	if _, err := s.PrepareFinalization(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitFinalization(ctx, 1); err != nil {
		t.Fatal(err)
	}
	result, err := s.Audit(ctx, phv.Request{Epoch: 1, Query: mva.LogIDQuery{ID: receipt.LogID}})
	if err != nil || !result.Verified || len(result.Proof.Selected) != 1 ||
		result.Proof.Selected[0].Address != receipt.Address {
		t.Fatalf("timed Segment audit=%+v err=%v", result.Metrics, err)
	}
}
