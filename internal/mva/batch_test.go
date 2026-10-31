package mva

import (
	"context"
	"testing"

	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

func TestHistoricalLogIDBatchAuthenticatesExactCrossRegionSet(t *testing.T) {
	tree, err := NewMVA(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	var pending []PendingRecord
	var targets []LogIDBatchTarget
	for i := byte(1); i <= 6; i++ {
		rid := "0"
		if i%2 == 0 {
			rid = "1"
		}
		key, address, locator := testMVALog(i, rid)
		pending = append(pending, PendingRecord{LogID: key.ID, RegionID: rid, SiteID: key.SiteID, DeviceID: key.DevID, Type: key.Type, TS: key.TS, Address: address, Locator: locator})
		if i <= 4 {
			targets = append(targets, LogIDBatchTarget{ID: key.ID, RegionID: rid})
		}
	}
	root, err := tree.PrepareCandidate(1, pending)
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.CommitCandidate(1); err != nil {
		t.Fatal(err)
	}
	q, err := NewLogIDBatchQuery(targets)
	if err != nil {
		t.Fatal(err)
	}
	regions := []merkle.TreeID{{Type: merkle.TreeRegion, RegionID: "0"}, {Type: merkle.TreeRegion, RegionID: "1"}}
	history := &snapshotHistory{epochs: map[uint64]*MVASnapshot{1: tree.Finalized}}
	values, proof, err := ResolveHistorical(context.Background(), history, 1, q, regions, root)
	if err != nil || len(values) != 4 || len(proof.Batch) != 4 {
		t.Fatalf("batch: values=%d proof=%d err=%v", len(values), len(proof.Batch), err)
	}
	for i, v := range values {
		if v.LocatorKey.LogID() != q.Targets[i].ID || v.RegionID != q.Targets[i].RegionID {
			t.Fatalf("wrong batch locator %d: %+v", i, v)
		}
	}
	withoutHints := append([]LogIDBatchTarget(nil), targets...)
	for i := range withoutHints {
		withoutHints[i].RegionID = ""
	}
	unhinted, err := NewLogIDBatchQuery(withoutHints)
	if err != nil {
		t.Fatal(err)
	}
	allRegions, unhintedProof, err := ResolveHistorical(context.Background(), history, 1, unhinted, regions, root)
	if err != nil || len(allRegions) != len(targets) || VerifyResolution(unhinted, regions, allRegions, unhintedProof, root) != nil {
		t.Fatalf("unhinted cross-Region batch: records=%d err=%v", len(allRegions), err)
	}
	if err := VerifyResolution(q, regions, values[:3], proof, root); err == nil {
		t.Fatal("accepted omitted requested LogID")
	}
	wrong := *proof
	wrong.Batch = append([]MVABatchItem(nil), proof.Batch...)
	wrong.Batch[1].Target.ID = targets[0].ID
	if err := VerifyResolution(q, regions, values, &wrong, root); err == nil {
		t.Fatal("accepted altered batch target")
	}
	bad := append([]LogIDBatchTarget(nil), targets...)
	bad = append(bad, bad[0])
	if _, err := NewLogIDBatchQuery(bad); err == nil {
		t.Fatal("accepted duplicate LogID")
	}
	if _, err := NewLogIDBatchQuery(nil); err == nil {
		t.Fatal("accepted empty LogID batch")
	}
	missingKey, _, _ := testMVALog(99, "0")
	missing, err := NewLogIDBatchQuery(append(targets, LogIDBatchTarget{ID: missingKey.ID, RegionID: "0"}))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveHistorical(context.Background(), history, 1, missing, regions, root); err == nil {
		t.Fatal("accepted batch with a missing LogID")
	}
	badHint := append([]LogIDBatchTarget(nil), targets...)
	if badHint[0].RegionID == "0" {
		badHint[0].RegionID = "1"
	} else {
		badHint[0].RegionID = "0"
	}
	q, err = NewLogIDBatchQuery(badHint)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ResolveHistorical(context.Background(), history, 1, q, regions, root); err == nil {
		t.Fatal("accepted wrong Region hint")
	}
}
