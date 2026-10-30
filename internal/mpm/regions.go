package mpm

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// SiteRegionStore atomically returns an existing assignment or assigns the
// next configured region. A durable implementation must persist both the
// mapping and round-robin cursor atomically for restart recovery.
type SiteRegionStore interface {
	Assign(ctx context.Context, siteKey string, regions []string) (string, error)
}

// MemorySiteRegions is a concurrency-safe store for local runs and tests.
// Share one instance across Manager instances to simulate restart recovery.
type MemorySiteRegions struct {
	mu    sync.RWMutex
	sites map[string]string
	next  int
}

func NewMemorySiteRegions() *MemorySiteRegions {
	return &MemorySiteRegions{sites: make(map[string]string)}
}

func (s *MemorySiteRegions) Assign(ctx context.Context, siteKey string, regions []string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if s == nil || siteKey == "" || len(regions) == 0 {
		return "", fmt.Errorf("assign site region: store, site key, and regions are required")
	}
	s.mu.RLock()
	region, found := s.sites[siteKey]
	s.mu.RUnlock()
	if found {
		return configuredRegion(region, regions)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if s.sites == nil {
		s.sites = make(map[string]string)
	}
	if region, ok := s.sites[siteKey]; ok {
		return configuredRegion(region, regions)
	}
	region = regions[s.next%len(regions)]
	s.sites[siteKey] = region
	s.next = (s.next + 1) % len(regions)
	return region, nil
}

func configuredRegion(region string, regions []string) (string, error) {
	for _, configured := range regions {
		if configured == region {
			return region, nil
		}
	}
	return "", fmt.Errorf("assign site region: existing region %q is no longer configured", region)
}

func siteKey(dataset, site string) string {
	// Length-prefixing prevents ambiguity if either field contains ':'.
	return fmt.Sprintf("%d:%s:%s", len(dataset), dataset, site)
}

// siteIdentity accepts both a source Site (P1) and the canonical Site
// (WADI:P1). The region store keeps the same key for either input form, while
// all authenticated structures see the globally distinct canonical Site.
func siteIdentity(dataset, site string) (sourceSite, canonicalSite string) {
	if dataset == "" {
		return site, site
	}
	sourceSite = strings.TrimPrefix(site, dataset+":")
	return sourceSite, dataset + ":" + sourceSite
}
