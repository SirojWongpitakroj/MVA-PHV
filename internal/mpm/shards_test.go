package mpm

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestDeviceShardsStickyRoundRobinPerRegion(t *testing.T) {
	store := NewMemoryDeviceShards()
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		key := deviceKey("WADI:P1", fmt.Sprintf("device-%02d", i))
		sid, err := store.Assign(ctx, "0", key, 16)
		if err != nil || sid != int64(i%16) {
			t.Fatalf("device %d: Shard %d, error %v", i, sid, err)
		}
		again, err := store.Assign(ctx, "0", key, 16)
		if err != nil || again != sid {
			t.Fatalf("device %d moved from Shard %d to %d: %v", i, sid, again, err)
		}
	}
	for i := 0; i < 2; i++ {
		sid, err := store.Assign(ctx, "1", deviceKey("HAI:P1", fmt.Sprintf("device-%d", i)), 16)
		if err != nil || sid != int64(i) {
			t.Fatalf("Region 1 cursor: Shard %d, error %v", sid, err)
		}
	}
	if deviceKey("WADI:P1", "D") == deviceKey("HAI:P1", "D") ||
		deviceKey("a:b", "c") == deviceKey("a", "b:c") {
		t.Fatal("distinct device identities merged")
	}
	if _, err := store.Assign(ctx, "0", deviceKey("WADI:P1", "device-15"), 8); err == nil {
		t.Fatal("existing Shard disappeared without error")
	}
	if _, err := store.Assign(ctx, "0", "", 16); err == nil {
		t.Fatal("empty device key accepted")
	}
}

func TestConcurrentFirstDeviceAssignmentIsStable(t *testing.T) {
	store := NewMemoryDeviceShards()
	const n = 64
	var wg sync.WaitGroup
	results := make(chan int64, n)
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sid, err := store.Assign(context.Background(), "0", deviceKey("WADI:P1", "FIT_001"), 16)
			results <- sid
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for sid := range results {
		if sid != 0 {
			t.Fatalf("same device assigned to Shard %d and 0", sid)
		}
	}
	if sid, err := store.Assign(context.Background(), "0", deviceKey("WADI:P1", "LT_001"), 16); err != nil || sid != 1 {
		t.Fatalf("first device consumed multiple cursor positions: Shard %d, %v", sid, err)
	}
}

func TestMPMUsesDevicePlacementForPhysicalAddress(t *testing.T) {
	r := newRig(t, 20)
	now := time.Unix(300, 0)
	for i, device := range []string{"FIT_001", "LT_001", "MV_001", "FIT_001"} {
		value := input(device)
		receipt, err := r.manager.Ingest(context.Background(), value, now.Add(time.Duration(i)*time.Second))
		want := int64(i)
		if i == 3 {
			want = 0
		}
		if err != nil || receipt.Address.ShardID != want {
			t.Fatalf("%s placed on Shard %d, want %d: %v", device, receipt.Address.ShardID, want, err)
		}
		if got := r.v.received[len(r.v.received)-1].Address; got != receipt.Address {
			t.Fatalf("MVA address %+v differs from HMF address %+v", got, receipt.Address)
		}
	}
	shared := r.manager.opts.DeviceShards
	restarted := newRig(t, 20)
	restarted.manager.opts.DeviceShards = shared
	receipt, err := restarted.manager.Ingest(context.Background(), input("LT_001"), now)
	if err != nil || receipt.Address.ShardID != 1 {
		t.Fatalf("restarted manager moved device: %+v, %v", receipt, err)
	}
}
