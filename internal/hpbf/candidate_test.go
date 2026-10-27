package hpbf

import (
	"testing"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
)

func TestCandidateUsesOnlySealedTokens(t *testing.T) {
	h, err := NewHPBF(1, 2, 100, 0.00001)
	if err != nil {
		t.Fatal(err)
	}
	sealed := TokenRecord{RegionID: "0", ShardID: 0, SiteID: "site-one", DeviceID: "device-one", Type: "type-one"}
	active := TokenRecord{RegionID: "0", ShardID: 1, SiteID: "site-two", DeviceID: "device-two", Type: "type-two"}
	for _, record := range []TokenRecord{sealed, active} {
		if err := h.AddToken(record.RegionID, record.ShardID, record.SiteID, record.DeviceID, record.Type); err != nil {
			t.Fatal(err)
		}
	}
	root, err := h.PrepareCandidate(1, []TokenRecord{sealed})
	if err != nil {
		t.Fatal(err)
	}
	if h.Finalized.Epoch != 0 || h.Candidate.Epoch != 1 {
		t.Fatal("preparation published candidate")
	}
	shards, _, global, err := h.CandidatePartitions(1)
	if err != nil {
		t.Fatal(err)
	}
	if root != global.RootHash || len(shards) != 2 {
		t.Fatal("invalid candidate evidence")
	}
	for _, shard := range shards {
		if shard.TreeID.ShardID == 1 {
			token, _ := domain.Serialize(active.SiteID)
			if shard.BloomFilter.Contains(token) {
				t.Fatal("active token entered candidate")
			}
		}
	}
	if retry, err := h.PrepareCandidate(1, []TokenRecord{active}); err != nil || retry != root {
		t.Fatalf("retry changed candidate: %x, %v", retry, err)
	}
	if err := h.CommitCandidate(2); err == nil {
		t.Fatal("wrong epoch promoted")
	}
	if err := h.CommitCandidate(1); err != nil {
		t.Fatal(err)
	}
	if h.Finalized.Epoch != 1 || h.Finalized.Global.RootHash != root {
		t.Fatal("wrong finalized candidate")
	}
	if _, err := h.PrepareCandidate(2, []TokenRecord{active}); err != nil {
		t.Fatal(err)
	}
	if h.Candidate.Epoch != 2 {
		t.Fatal("next candidate not prepared")
	}
}
