package mpm

import (
	"context"
	"fmt"
	"sync"
)

// DeviceShardStore atomically reuses a DeviceKey's Shard or assigns the next
// Shard in its Region. Durable implementations must persist the mapping and
// each Region's cursor together so restart does not change placement.
type DeviceShardStore interface {
	Assign(ctx context.Context, regionID, deviceKey string, shardCount int) (int64, error)
}

// MemoryDeviceShards is the local/test implementation. Sharing it across
// managers preserves placement within one process, including simulated restarts.
type MemoryDeviceShards struct {
	mu      sync.Mutex
	devices map[string]map[string]int64
	next    map[string]int64
}

func NewMemoryDeviceShards() *MemoryDeviceShards {
	return &MemoryDeviceShards{devices: make(map[string]map[string]int64), next: make(map[string]int64)}
}

func (s *MemoryDeviceShards) Assign(ctx context.Context, regionID, key string, count int) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if s == nil || regionID == "" || key == "" || count <= 0 {
		return 0, fmt.Errorf("assign device shard: store, region, device key, and positive shard count are required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if s.devices == nil {
		s.devices = make(map[string]map[string]int64)
	}
	if s.next == nil {
		s.next = make(map[string]int64)
	}
	if s.devices[regionID] == nil {
		s.devices[regionID] = make(map[string]int64)
	}
	if sid, ok := s.devices[regionID][key]; ok {
		if sid >= int64(count) {
			return 0, fmt.Errorf("assign device shard: existing Shard %d is no longer configured in Region %q", sid, regionID)
		}
		return sid, nil
	}
	sid := s.next[regionID] % int64(count)
	s.devices[regionID][key] = sid
	s.next[regionID] = (sid + 1) % int64(count)
	return sid, nil
}

func deviceKey(canonicalSite, device string) string {
	return fmt.Sprintf("%d:%s:%s", len(canonicalSite), canonicalSite, device)
}
