package mva

import (
	"testing"
	"time"
	"uuid"
)

func candidateRecord(id byte) PendingRecord {
	var logID uuid.UUID
	logID[15] = id
	return PendingRecord{LogID: logID, RegionID: "0", SiteID: "site", DeviceID: "device",
		Type: "type", TS: time.Unix(int64(id), 0).UTC(),
		Address: PhysicalAddress{RegionID: "0", ShardID: "0", SegmentID: "0", LeafID: string(rune('0' + id))},
		Locator: [32]byte{id}}
}

func TestCandidateUsesOnlySealedRecords(t *testing.T) {
	tree, err := NewMVA(1, 3)
	if err != nil {
		t.Fatal(err)
	}
	sealed, active := candidateRecord(1), candidateRecord(2)
	for _, record := range []PendingRecord{sealed, active} {
		if _, _, err := tree.IngestRecord(record); err != nil {
			t.Fatal(err)
		}
	}
	root, err := tree.PrepareCandidate(1, []PendingRecord{sealed})
	if err != nil {
		t.Fatal(err)
	}
	if tree.Finalized != nil {
		t.Fatal("preparation published a finalized snapshot")
	}
	snapshot, err := tree.CandidateSnapshot(1)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Root != root || snapshot.Regions["0"].IDView.LeafCount != 1 || tree.Regions[0].IDView.LeafCount != 2 {
		t.Fatal("candidate included an active record or changed Working")
	}
	if retry, err := tree.PrepareCandidate(1, []PendingRecord{active}); err != nil || retry != root {
		t.Fatalf("candidate retry changed root: %x, %v", retry, err)
	}
	if err := tree.CommitCandidate(2); err == nil {
		t.Fatal("wrong epoch promoted")
	}
	if err := tree.CommitCandidate(1); err != nil {
		t.Fatal(err)
	}
	if tree.Finalized.Root != root || tree.Finalized.Regions["0"].IDView.LeafCount != 1 {
		t.Fatal("promoted snapshot differs from sealed candidate")
	}
	if _, err := tree.PrepareCandidate(2, []PendingRecord{active}); err != nil {
		t.Fatal(err)
	}
	if tree.Candidate.Regions["0"].IDView.LeafCount != 2 {
		t.Fatal("next candidate failed to inherit earlier sealed record")
	}
}
