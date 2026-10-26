package hmf

import (
	"fmt"
	"testing"
	"time"
)

func TestSelectShardUsesRegionSiteAndDevice(t *testing.T) {
	h, err := NewHMFWithConfig(HMFConfig{
		RegionIDs: []string{"west", "east"}, NumShardsPerRegion: 8, MaxSegmentLeaves: 10,
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	east, err := h.SelectShard("east", "site-1", "device-1")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		again, err := h.SelectShard("east", "site-1", "device-1")
		if err != nil || again != east {
			t.Fatalf("same region/site/device moved from shard %d to %d: %v", east, again, err)
		}
	}
	if h.Working.Regions["east"].Shards[east] == nil {
		t.Fatalf("selected shard %d is not configured in east", east)
	}
	restarted, err := NewHMFWithConfig(HMFConfig{
		RegionIDs: []string{"east", "west"}, NumShardsPerRegion: 8, MaxSegmentLeaves: 10,
	}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if again, err := restarted.SelectShard("east", "site-1", "device-1"); err != nil || again != east {
		t.Fatalf("same configuration mapped to shard %d after restart: %v", again, err)
	}
	if _, err := h.SelectShard("missing", "site-1", "device-1"); err == nil {
		t.Fatal("selected a shard in an unknown region")
	}

	// Region is part of the mapping, even when its configured shard IDs match.
	regionChangesPlacement := false
	for i := 0; i < 100; i++ {
		device := fmt.Sprintf("device-%d", i)
		a, err := h.SelectShard("east", "site-1", device)
		if err != nil {
			t.Fatal(err)
		}
		b, err := h.SelectShard("west", "site-1", device)
		if err != nil {
			t.Fatal(err)
		}
		if a != b {
			regionChangesPlacement = true
			break
		}
	}
	if !regionChangesPlacement {
		t.Fatal("region ID did not affect shard placement")
	}
	siteChangesPlacement := false
	for i := 0; i < 100; i++ {
		device := fmt.Sprintf("device-%d", i)
		a, err := h.SelectShard("east", "site-1", device)
		if err != nil {
			t.Fatal(err)
		}
		b, err := h.SelectShard("east", "site-2", device)
		if err != nil {
			t.Fatal(err)
		}
		if a != b {
			siteChangesPlacement = true
			break
		}
	}
	if !siteChangesPlacement {
		t.Fatal("site ID did not affect shard placement")
	}
}

func TestInsertKeepsDeviceLocalityAndDistributesDevices(t *testing.T) {
	h, err := NewHMF(2, 8, 10, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	firstSID, firstSegment, firstLeaf, err := h.Insert("0", "large-site", "device-1", [32]byte{1}, now)
	if err != nil {
		t.Fatal(err)
	}
	secondSID, secondSegment, secondLeaf, err := h.Insert("0", "large-site", "device-1", [32]byte{2}, now)
	if err != nil {
		t.Fatal(err)
	}
	if firstSID != secondSID || firstSegment != 0 || secondSegment != 0 || firstLeaf != 0 || secondLeaf != 1 {
		t.Fatalf("same device addresses = %d/%d/%d and %d/%d/%d", firstSID, firstSegment, firstLeaf, secondSID, secondSegment, secondLeaf)
	}
	selected, err := h.SelectShard("0", "large-site", "device-1")
	if err != nil || firstSID != selected {
		t.Fatalf("Insert chose shard %d, selector chose %d: %v", firstSID, selected, err)
	}

	var counts [8]int
	for i := 0; i < 1024; i++ {
		sid, err := h.SelectShard("0", "large-site", fmt.Sprintf("device-%d", i))
		if err != nil {
			t.Fatal(err)
		}
		counts[sid]++
	}
	for sid, count := range counts {
		if count < 80 || count > 180 {
			t.Fatalf("shard %d received %d of 1024 devices; counts = %v", sid, count, counts)
		}
	}
}
