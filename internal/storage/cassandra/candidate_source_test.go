package cassandra

import (
	"bytes"
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/SirojWongpitakroj/mva-phv/internal/canonicalize"
	"github.com/SirojWongpitakroj/mva-phv/internal/cloudprovider"
	"github.com/SirojWongpitakroj/mva-phv/internal/hmf"
	"github.com/SirojWongpitakroj/mva-phv/internal/hpbf"
	"github.com/SirojWongpitakroj/mva-phv/internal/mpm"
	"github.com/SirojWongpitakroj/mva-phv/internal/mva"
)

type memoryCheckpoints struct {
	values map[uint64][32]byte
	fail   bool
}

func (c *memoryCheckpoints) Commit(_ context.Context, epoch uint64, hash [32]byte) error {
	if c.fail {
		return errors.New("anchor unavailable")
	}
	if old, ok := c.values[epoch]; ok && old != hash {
		return errors.New("conflicting checkpoint")
	}
	c.values[epoch] = hash
	return nil
}
func (c *memoryCheckpoints) GetCheckpoint(_ context.Context, epoch uint64) ([32]byte, error) {
	if hash, ok := c.values[epoch]; ok {
		return hash, nil
	}
	return [32]byte{}, errors.New("checkpoint missing")
}

func TestComponentEvidenceSourcePreparedCandidate(t *testing.T) {
	h, err := hmf.NewHMF(1, 2, 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	v, err := mva.NewMVA(1, 3)
	if err != nil {
		t.Fatal(err)
	}
	p, err := hpbf.NewHPBF(1, 2, 100, 0.00001)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0).UTC()
	reservation, err := h.ReserveAddress("0", "site", "device", now)
	if err != nil {
		t.Fatal(err)
	}
	address := reservation.Address()
	if err := h.CommitReservation(reservation, [32]byte{9}, now); err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	id[15] = 1
	mvaRoot, err := v.PrepareCandidate(1, []mva.PendingRecord{{LogID: id, RegionID: "0", SiteID: "site", DeviceID: "device", Type: "type", TS: now,
		Address: mva.PhysicalAddress{RegionID: "0", ShardID: strconv.FormatInt(address.ShardID, 10), SegmentID: "0", LeafID: "0"}, Locator: [32]byte{2}}})
	if err != nil {
		t.Fatal(err)
	}
	hpbfRoot, err := p.PrepareCandidate(1, []hpbf.TokenRecord{{RegionID: "0", ShardID: address.ShardID, SiteID: "site", DeviceID: "device", Type: "type"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.PrepareFinalization(1); err != nil {
		t.Fatal(err)
	}
	hmfRoot, err := h.Commitment()
	if err != nil {
		t.Fatal(err)
	}
	client := &repositoryClient{}
	store, err := NewStore(client)
	if err != nil {
		t.Fatal(err)
	}
	source := &ComponentEvidenceSource{Store: store, HMF: h, MVA: v, HPBF: p}
	segment := h.PendingSegments()[0]
	candidate := mpm.Candidate{Epoch: 1, Roots: mpm.Roots{MVA: mvaRoot, HMF: hmfRoot, HPBF: hpbfRoot},
		Segments: []mpm.Segment{{ID: segment.TreeID, Root: segment.Root, LeafCount: segment.LeafCount}}}
	evidence, err := source.CandidateEvidence(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCandidateEvidence(candidate, evidence); err != nil {
		t.Fatal(err)
	}
	for _, node := range evidence.HPBFRegionNodes {
		if node.Node.Level < 1 {
			t.Fatalf("HPBF internal node was stored as leaf level: %+v", node)
		}
	}
	if len(evidence.HMFShards) != 1 || len(evidence.HMFNodes) == 0 || len(evidence.MVAPages) == 0 || len(evidence.HPBFShardFilters) != 2 {
		t.Fatalf("missing changed evidence: HMF Shards %d, nodes %d, MVA pages %d, HPBF filters %d",
			len(evidence.HMFShards), len(evidence.HMFNodes), len(evidence.MVAPages), len(evidence.HPBFShardFilters))
	}
}

func TestConcreteMPMAdaptersIngestPrepareAndCommit(t *testing.T) {
	h, err := hmf.NewHMF(1, 2, 1, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	v, err := mva.NewMVA(1, 3)
	if err != nil {
		t.Fatal(err)
	}
	p, err := hpbf.NewHPBF(1, 2, 100, 0.00001)
	if err != nil {
		t.Fatal(err)
	}
	client := &repositoryClient{}
	store, err := NewStore(client)
	if err != nil {
		t.Fatal(err)
	}
	source := &ComponentEvidenceSource{Store: store, HMF: h, MVA: v, HPBF: p}
	repo, err := NewMPMRepository(store, source)
	if err != nil {
		t.Fatal(err)
	}
	encryptor, err := canonicalize.NewAEADService(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	checkpoints := &memoryCheckpoints{values: make(map[uint64][32]byte), fail: true}
	provider := cloudprovider.NewMemory()
	manager, err := mpm.NewMPM(mpm.Options{Regions: []string{"0"}, ShardsPerRegion: 2, HMF: &mpm.HMFAdapter{Tree: h}, MVA: &mpm.MVAAdapter{Tree: v},
		HPBF: &mpm.HPBFAdapter{Tree: p}, Encryptor: encryptor, Locator: mpm.CanonicalLocator{},
		Evidence: repo, Ciphertexts: provider, Checkpoints: checkpoints})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0).UTC()
	receipt, err := manager.Ingest(context.Background(), mpm.Input{RegionID: "0", SiteID: "site", DeviceID: "device", Type: "type", TS: now, Plaintext: []byte("log")}, now)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Address.LeafID != 0 || len(manager.PendingSegments()) != 1 {
		t.Fatal("accepted log did not seal its Segment")
	}
	ciphertexts, err := provider.GetCiphertexts(context.Background(), "0", []uuid.UUID{receipt.LogID})
	if err != nil || len(ciphertexts) != 1 || bytes.Equal(ciphertexts[0].Ciphertext, []byte("log")) {
		t.Fatalf("external CP did not receive encrypted log by LogID: %+v, %v", ciphertexts, err)
	}
	if countWrites(client.writes, "logs_by_segment") != 0 || countWrites(client.writes, "hmf_segment_nodes") == 0 {
		t.Fatal("CLS stored ciphertext or missed sealed HMF evidence")
	}
	candidate, err := manager.PrepareFinalization(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidate.Records) != 1 || candidate.Records[0].Address != receipt.Address {
		t.Fatal("candidate has wrong bound record")
	}
	later, err := manager.Ingest(context.Background(), mpm.Input{RegionID: "0", SiteID: "site", DeviceID: "device",
		Type: "type", TS: now.Add(time.Second), Plaintext: []byte("later")}, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if later.Address.SegmentID != receipt.Address.SegmentID+1 {
		t.Fatal("next log did not use a new Segment")
	}
	if countWrites(client.writes, "hmf_global_state_by_epoch") == 0 || countWrites(client.writes, "mva_epoch_roots") == 0 || countWrites(client.writes, "hpbf_epoch_roots") == 0 {
		t.Fatal("candidate roots were not persisted")
	}
	if _, err := manager.CommitFinalization(context.Background(), 1); err == nil || !strings.Contains(err.Error(), "checkpoint") {
		t.Fatalf("expected anchor failure, got %v", err)
	}
	if epoch, _ := manager.Finalized(); epoch != 0 || v.Finalized != nil || p.Finalized.Epoch != 0 {
		t.Fatal("failed anchor advanced a component")
	}
	checkpoints.fail = false
	if _, err := manager.CommitFinalization(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if epoch, roots := manager.Finalized(); epoch != 1 || roots != candidate.Roots || v.Finalized.Epoch != 1 || p.Finalized.Epoch != 1 {
		t.Fatal("successful anchor did not promote all components")
	}
	if len(manager.PendingSegments()) != 1 {
		t.Fatal("promoting candidate cleared later pending Segment")
	}
	next, err := manager.PrepareFinalization(context.Background(), 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(next.Records) != 1 || next.Records[0].Address != later.Address {
		t.Fatal("next candidate did not capture only later Segment")
	}
	nextEvidence, err := source.CandidateEvidence(context.Background(), next)
	if err != nil {
		t.Fatal(err)
	}
	if len(nextEvidence.HMFShards) != 1 || len(nextEvidence.HMFRegions) != 1 || len(nextEvidence.HMFNodes) == 0 {
		t.Fatal("second candidate did not export only the affected HMF branch")
	}
}
