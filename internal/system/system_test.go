package system

import (
	"context"
	"testing"
	"time"

	"github.com/SirojWongpitakroj/mva-phv/internal/mpm"
	"github.com/SirojWongpitakroj/mva-phv/internal/mva"
	"github.com/SirojWongpitakroj/mva-phv/internal/phv"
)

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
