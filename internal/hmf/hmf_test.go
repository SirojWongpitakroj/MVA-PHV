package hmf

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

func hmfDeviceForShard(t *testing.T, h *HMF, rid string, want int64) string {
	t.Helper()
	for i := 0; i < 100; i++ {
		device := fmt.Sprintf("device-%d", i)
		got, err := h.SelectShard(rid, "site", device)
		if err != nil {
			t.Fatal(err)
		}
		if got == want {
			return device
		}
	}
	t.Fatalf("no device selected Shard %d in Region %s", want, rid)
	return ""
}

func hmfCommitLeaf(t *testing.T, h *HMF, rid, device string, leaf [32]byte, now time.Time) Address {
	t.Helper()
	r, err := h.ReserveAddress(rid, "site", device, now)
	if err != nil {
		t.Fatal(err)
	}
	a := r.Address()
	if err := h.CommitReservation(r, leaf, now); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestHMFReservationSealingEvidenceAndPromotion(t *testing.T) {
	h, err := NewHMFWithConfig(HMFConfig{RegionIDs: []string{"r1", "r0"},
		NumShardsPerRegion: 2, MaxSegmentLeaves: 2}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := h.FinalizedRoot()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Commitment(); err != ErrNoCandidateState {
		t.Fatalf("unexpected candidate root: %v", err)
	}
	device := hmfDeviceForShard(t, h, "r0", 0)
	now := time.Unix(100, 0).UTC()
	first := hmfCommitLeaf(t, h, "r0", device, [32]byte{1}, now)
	if first != (Address{RegionID: "r0", ShardID: 0, SegmentID: 0, LeafID: 0}) {
		t.Fatalf("first address = %+v", first)
	}
	if len(h.PendingSegments()) != 0 || h.Working.Regions["r0"].Shards[0].Active.LeafCount != 1 {
		t.Fatal("unsealed Segment entered pending or lost its leaf")
	}
	if root, _ := h.FinalizedRoot(); root != initial {
		t.Fatal("active leaf changed authoritative root")
	}
	second := hmfCommitLeaf(t, h, "r0", device, [32]byte{2}, now)
	if second.SegmentID != 0 || second.LeafID != 1 {
		t.Fatalf("second address = %+v", second)
	}
	pending := h.PendingSegments()
	if len(pending) != 1 || !pending[0].Sealed || pending[0].LeafCount != 2 ||
		pending[0].OpenedAt != now || pending[0].SealedAt != now || pending[0].Root == ([32]byte{}) {
		t.Fatal("full Segment did not seal with immutable metadata")
	}
	segment := pending[0]
	sealedRoot := segment.Root
	if err := segment.AppendCommitment([32]byte{3}); err == nil {
		t.Fatal("sealed Segment accepted another leaf")
	}
	nodes, err := h.PendingSegmentNodes(segment.TreeID)
	if err != nil || len(nodes) < 2 {
		t.Fatalf("sealed proof nodes missing: %v", err)
	}
	if err := h.PrepareFinalization(1); err != nil {
		t.Fatal(err)
	}
	candidateRoot, err := h.Commitment()
	if err != nil || candidateRoot == initial {
		t.Fatalf("candidate root = %x, %v", candidateRoot, err)
	}
	if root, _ := h.FinalizedRoot(); root != initial {
		t.Fatal("prepare changed authoritative root")
	}
	evidence, err := h.CandidateEvidence(1)
	if err != nil {
		t.Fatal(err)
	}
	if evidence.GlobalRoot != candidateRoot || len(evidence.Shards) != 1 || len(evidence.Regions) != 1 ||
		len(evidence.Nodes) == 0 || evidence.Shards[0].TreeID.ShardID != 0 ||
		evidence.Regions[0].TreeID.RegionID != "r0" {
		t.Fatal("candidate exported unrelated or incomplete HMF evidence")
	}
	if h.Candidate.Regions["r1"] != h.Finalized.Regions["r1"] ||
		h.Candidate.Regions["r0"].Shards[1] != h.Finalized.Regions["r0"].Shards[1] {
		t.Fatal("candidate rebuilt an unchanged branch")
	}
	if err := h.ValidateFinalization(1); err == nil {
		t.Fatal("unpersisted Segment validated")
	}
	if err := h.CommitFinalization(1); err == nil {
		t.Fatal("unpersisted Segment promoted")
	}
	if err := h.AcknowledgeSegmentPersisted(segment.TreeID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.PendingSegmentNodes(segment.TreeID); err == nil {
		t.Fatal("persisted proof builder was retained")
	}
	if segment.Root != sealedRoot {
		t.Fatal("persistence acknowledgement changed Segment root")
	}
	if err := h.ValidateFinalization(2); err == nil {
		t.Fatal("wrong epoch validated")
	}
	if err := h.ValidateFinalization(1); err != nil {
		t.Fatal(err)
	}
	if err := h.CommitFinalization(2); err == nil {
		t.Fatal("wrong epoch promoted")
	}
	if err := h.CommitFinalization(1); err != nil {
		t.Fatal(err)
	}
	if root, _ := h.FinalizedRoot(); root != candidateRoot || len(h.PendingSegments()) != 0 {
		t.Fatal("promotion lost candidate root or left captured Segment pending")
	}
	if _, err := h.Commitment(); err != ErrNoCandidateState {
		t.Fatal("promoted candidate remained prepared")
	}
}

func TestHMFCandidateKeepsLaterSealedSegmentsPending(t *testing.T) {
	h, err := NewHMF(1, 1, 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	hmfCommitLeaf(t, h, "0", "device", [32]byte{1}, now)
	first := h.PendingSegments()[0]
	if err := h.AcknowledgeSegmentPersisted(first.TreeID); err != nil {
		t.Fatal(err)
	}
	if err := h.PrepareFinalization(1); err != nil {
		t.Fatal(err)
	}
	root1, _ := h.Commitment()
	hmfCommitLeaf(t, h, "0", "device", [32]byte{2}, now.Add(time.Second))
	if len(h.PendingSegments()) != 2 {
		t.Fatal("later sealed Segment missing")
	}
	if err := h.AcknowledgeSegmentPersisted(h.PendingSegments()[1].TreeID); err != nil {
		t.Fatal(err)
	}
	if err := h.PrepareFinalization(1); err != nil {
		t.Fatal(err)
	}
	if root, _ := h.Commitment(); root != root1 {
		t.Fatal("retry included a later Segment")
	}
	if err := h.PrepareFinalization(2); err == nil {
		t.Fatal("conflicting candidate epoch accepted")
	}
	if err := h.CommitFinalization(1); err != nil {
		t.Fatal(err)
	}
	if pending := h.PendingSegments(); len(pending) != 1 || pending[0].TreeID.SegmentID != 1 {
		t.Fatal("promotion cleared a later Segment")
	}
	if err := h.PrepareFinalization(2); err != nil {
		t.Fatal(err)
	}
	root2, _ := h.Commitment()
	if root2 == root1 || h.Finalized.Global.Root != root1 || first.Root == ([32]byte{}) {
		t.Fatal("second candidate did not extend the finalized hierarchy")
	}
	evidence, err := h.CandidateEvidence(2)
	if err != nil || len(evidence.Shards) != 1 || evidence.Shards[0].SegmentCount != 2 {
		t.Fatalf("second candidate evidence: %+v, %v", evidence.Shards, err)
	}
	if err := h.CommitFinalization(2); err != nil {
		t.Fatal(err)
	}
	if root, _ := h.FinalizedRoot(); root != root2 {
		t.Fatal("second root not promoted")
	}
}

func TestHMFReservationExpiryAbortAndOwnership(t *testing.T) {
	h, err := NewHMF(1, 1, 3, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Unix(100, 0)
	if _, err := h.ReserveAddress("0", "site", "device", time.Time{}); err == nil {
		t.Fatal("zero reservation time accepted")
	}
	if _, err := h.ReserveAddress("missing", "site", "device", start); err == nil {
		t.Fatal("unknown Region accepted")
	}
	r, err := h.ReserveAddress("0", "site", "device", start)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := h.Insert("0", "site", "device", [32]byte{1}, start); err == nil {
		t.Fatal("legacy insertion bypassed outstanding reservation")
	}
	other, err := NewHMF(1, 1, 3, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := other.AbortReservation(r); err == nil {
		t.Fatal("foreign HMF aborted reservation")
	}
	if err := other.CommitReservation(r, [32]byte{1}, start); err == nil {
		t.Fatal("foreign HMF committed reservation")
	}
	if sealed, err := h.SealExpired(start.Add(2 * time.Hour)); err != nil || len(sealed) != 0 {
		t.Fatalf("reserved Segment sealed: %v", err)
	}
	if err := h.AbortReservation(r); err != nil {
		t.Fatal(err)
	}
	if len(h.PendingSegments()) != 0 {
		t.Fatal("empty aborted Segment entered pending")
	}
	opened := start.Add(3 * time.Hour)
	a := hmfCommitLeaf(t, h, "0", "device", [32]byte{2}, opened)
	if a.SegmentID != 0 || a.LeafID != 0 {
		t.Fatalf("aborted position not reused: %+v", a)
	}
	if sealed, err := h.SealExpired(opened.Add(time.Hour - time.Nanosecond)); err != nil || len(sealed) != 0 {
		t.Fatalf("Segment sealed too early: %v", err)
	}
	sealed, err := h.SealExpired(opened.Add(time.Hour))
	if err != nil || len(sealed) != 1 || sealed[0].OpenedAt != opened {
		t.Fatalf("expiry seal: %v", err)
	}
	if again, err := h.SealExpired(opened.Add(2 * time.Hour)); err != nil || len(again) != 0 {
		t.Fatal("Segment sealed twice")
	}
	if _, err := h.PendingSegmentNodes(merkle.TreeID{Type: merkle.TreeSegment, RegionID: "0", ShardID: 0, SegmentID: 9}); err == nil {
		t.Fatal("unknown Segment returned proof nodes")
	}
}

func TestHMFReservationsAreIndependentAcrossShards(t *testing.T) {
	h, err := NewHMF(1, 2, 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	devices := []string{hmfDeviceForShard(t, h, "0", 0), hmfDeviceForShard(t, h, "0", 1)}
	var wg sync.WaitGroup
	errors := make(chan error, 2)
	for shard, device := range devices {
		wg.Add(1)
		go func(shard int, device string) {
			defer wg.Done()
			r, err := h.ReserveAddress("0", "site", device, time.Unix(100, 0))
			if err != nil {
				errors <- err
				return
			}
			if r.Address().ShardID != int64(shard) {
				errors <- fmt.Errorf("Shard %d got address %+v", shard, r.Address())
				return
			}
			if err := h.CommitReservation(r, [32]byte{byte(shard + 1)}, time.Unix(100, 0)); err != nil {
				errors <- err
			}
		}(shard, device)
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Fatal(err)
	}
	if len(h.PendingSegments()) != 2 {
		t.Fatal("one Shard lost a concurrent sealed Segment")
	}
}

func TestHMFActiveOnlyEpochReusesFinalizedRoot(t *testing.T) {
	h, err := NewHMF(1, 1, 4, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	initial, _ := h.FinalizedRoot()
	hmfCommitLeaf(t, h, "0", "device", [32]byte{1}, time.Unix(100, 0))
	if len(h.PendingSegments()) != 0 {
		t.Fatal("active Segment entered pending")
	}
	if err := h.PrepareFinalization(1); err != nil {
		t.Fatal(err)
	}
	root1, err := h.Commitment()
	if err != nil || root1 != initial {
		t.Fatal("active Segment changed candidate root")
	}
	evidence, err := h.CandidateEvidence(1)
	if err != nil || len(evidence.Nodes) != 0 || len(evidence.Shards) != 0 || len(evidence.Regions) != 0 {
		t.Fatalf("empty pending set produced changed nodes: %v", err)
	}
	if err := h.ValidateFinalization(1); err != nil {
		t.Fatal(err)
	}
	if err := h.CommitFinalization(1); err != nil {
		t.Fatal(err)
	}
	if err := h.PrepareFinalization(2); err != nil {
		t.Fatal(err)
	}
	root2, _ := h.Commitment()
	if root2 != initial {
		t.Fatal("epoch was hashed into an unchanged HMF root")
	}
}

func TestHMFRejectsInvalidConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name     string
		config   HMFConfig
		interval time.Duration
	}{
		{"no regions", HMFConfig{NumShardsPerRegion: 1, MaxSegmentLeaves: 1}, time.Hour},
		{"no shards", HMFConfig{RegionIDs: []string{"0"}, MaxSegmentLeaves: 1}, time.Hour},
		{"no capacity", HMFConfig{RegionIDs: []string{"0"}, NumShardsPerRegion: 1}, time.Hour},
		{"no interval", HMFConfig{RegionIDs: []string{"0"}, NumShardsPerRegion: 1, MaxSegmentLeaves: 1}, 0},
		{"duplicate regions", HMFConfig{RegionIDs: []string{"r", "r"}, NumShardsPerRegion: 1, MaxSegmentLeaves: 1}, time.Hour},
		{"empty region", HMFConfig{RegionIDs: []string{""}, NumShardsPerRegion: 1, MaxSegmentLeaves: 1}, time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewHMFWithConfig(tc.config, tc.interval); err == nil {
				t.Fatal("invalid HMF configuration accepted")
			}
		})
	}
}
