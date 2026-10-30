package mpm

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSiteRegionsRoundRobinAndDatasetIdentity(t *testing.T) {
	store := NewMemorySiteRegions()
	regions := []string{"R1", "R2", "R3", "R4"}
	sequence := []struct {
		dataset, site, want string
	}{
		{"WADI", "P1", "R1"}, {"WADI", "P2", "R2"},
		{"WADI", "P1", "R1"}, {"WADI", "P3", "R3"},
		{"WADI", "P4", "R4"}, {"WADI", "P2", "R2"},
		{"WADI", "P5", "R1"}, {"HAI", "P1", "R2"},
	}
	for _, item := range sequence {
		got, err := store.Assign(context.Background(), siteKey(item.dataset, item.site), regions)
		if err != nil || got != item.want {
			t.Fatalf("%s:%s: got %q, want %q: %v", item.dataset, item.site, got, item.want, err)
		}
	}
	if siteKey("a:b", "c") == siteKey("a", "b:c") {
		t.Fatal("distinct dataset/site pairs share a key")
	}
	if _, err := store.Assign(context.Background(), siteKey("WADI", "P2"), []string{"R1"}); err == nil {
		t.Fatal("reconfiguration silently moved an existing site")
	}
}

func TestSiteIdentityAcceptsSourceAndCanonicalForms(t *testing.T) {
	for _, input := range []string{"P1", "WADI:P1"} {
		source, canonical := siteIdentity("WADI", input)
		if source != "P1" || canonical != "WADI:P1" {
			t.Fatalf("%q resolved to %q, %q", input, source, canonical)
		}
	}
	_, wadi := siteIdentity("WADI", "P1")
	_, hai := siteIdentity("HAI", "P1")
	_, swat := siteIdentity("SWAT", "P1")
	if wadi == hai || hai == swat || wadi == swat {
		t.Fatal("different datasets share the same authenticated Site")
	}
}

func TestMPMSelectsRegionBeforeAddressAndReusesAcrossManagers(t *testing.T) {
	store := NewMemorySiteRegions()
	first := newRig(t, 10)
	first.manager.opts.SiteRegions = store
	now := time.Unix(300, 0)
	makeInput := func(dataset, site, device string) Input {
		value := input(device)
		value.Dataset, value.SiteID, value.RegionID = dataset, site, ""
		return value
	}
	for _, test := range []struct {
		input Input
		want  string
	}{
		{makeInput("WADI", "P1", "D1"), "r0"},
		{makeInput("WADI", "P2", "D1"), "r1"},
		{makeInput("WADI", "P1", "D2"), "r0"},
		{makeInput("HAI", "P1", "D1"), "r0"},
	} {
		receipt, err := first.manager.Ingest(context.Background(), test.input, now)
		if err != nil || receipt.Address.RegionID != test.want {
			t.Fatalf("%s:%s got %+v, want %s: %v", test.input.Dataset, test.input.SiteID, receipt, test.want, err)
		}
		got := first.v.received[len(first.v.received)-1]
		wantSite := test.input.Dataset + ":" + test.input.SiteID
		if got.Descriptor.RegionID != test.want || got.Address != receipt.Address ||
			got.Descriptor.SiteID != wantSite ||
			first.b.received[len(first.b.received)-1].region != test.want ||
			first.b.received[len(first.b.received)-1].site != wantSite {
			t.Fatal("MVA or HPBF received a different region from HMF")
		}
	}
	second := newRig(t, 10)
	second.manager.opts.SiteRegions = store // Same store represents restored persistent state.
	for _, test := range []struct {
		input Input
		want  string
	}{
		{makeInput("WADI", "P2", "D2"), "r1"},
		{makeInput("WADI", "P3", "D1"), "r1"},
	} {
		receipt, err := second.manager.Ingest(context.Background(), test.input, now)
		if err != nil || receipt.Address.RegionID != test.want {
			t.Fatalf("restart %s:%s got %+v, want %s: %v", test.input.Dataset, test.input.SiteID, receipt, test.want, err)
		}
	}
}

func TestConcurrentFirstSiteAssignment(t *testing.T) {
	r := newRig(t, 128)
	const count = 64
	var wg sync.WaitGroup
	results := make(chan string, count)
	errs := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			value := input(string(rune('a' + i)))
			value.RegionID = ""
			value.SiteID = "new-site"
			receipt, err := r.manager.Ingest(context.Background(), value, time.Unix(400, 0))
			if err != nil {
				errs <- err
				return
			}
			results <- receipt.Address.RegionID
		}(i)
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	for region := range results {
		if region != "r0" {
			t.Fatalf("same site assigned to %q and r0", region)
		}
	}
	next := input("next")
	next.RegionID, next.SiteID = "", "another-site"
	receipt, err := r.manager.Ingest(context.Background(), next, time.Unix(400, 0))
	if err != nil || receipt.Address.RegionID != "r1" {
		t.Fatalf("concurrent first site consumed more than one round-robin slot: %+v, %v", receipt, err)
	}
}

func TestRegionConfigurationAndConflictingHint(t *testing.T) {
	r := newRig(t, 10)
	options := r.manager.opts
	options.Regions = nil
	if _, err := New(options); err == nil || !strings.Contains(err.Error(), "at least one region") {
		t.Fatalf("missing regions accepted: %v", err)
	}
	options.Regions, options.SiteRegions = []string{"r0", "r1"}, nil
	if _, err := New(options); err == nil || !strings.Contains(err.Error(), "site-region store") {
		t.Fatalf("multi-region manager silently created a volatile mapping: %v", err)
	}
	value := input("device")
	value.RegionID = "r1"
	if _, err := r.manager.Ingest(context.Background(), value, time.Unix(400, 0)); err == nil ||
		!strings.Contains(err.Error(), "conflicts with site assignment") {
		t.Fatalf("conflicting caller region accepted: %v", err)
	}
}
