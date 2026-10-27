package mpm

import (
	"testing"
	"time"
	"uuid"
)

func TestCanonicalLocatorBindsPhysicalAddress(t *testing.T) {
	var id uuid.UUID
	id[15] = 1
	d := Descriptor{RegionID: "0", SiteID: "site", DeviceID: "device", Type: "type", TS: time.Unix(100, 0)}
	a := Address{RegionID: "0", ShardID: 1, SegmentID: 2, LeafID: 3}
	commitment, err := (CanonicalLocator{}).CommitLocator(id, d, a)
	if err != nil {
		t.Fatal(err)
	}
	again, err := (CanonicalLocator{}).CommitLocator(id, d, a)
	if err != nil || again != commitment {
		t.Fatal("locator commitment is not deterministic")
	}
	a.LeafID++
	changed, err := (CanonicalLocator{}).CommitLocator(id, d, a)
	if err != nil || changed == commitment {
		t.Fatal("locator commitment did not bind LeafID")
	}
	a.RegionID = "other"
	if _, err := (CanonicalLocator{}).CommitLocator(id, d, a); err == nil {
		t.Fatal("mismatched Region accepted")
	}
}
