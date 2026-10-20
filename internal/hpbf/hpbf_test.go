package hpbf

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"strconv"
	"testing"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

func TestHPBFCommitmentAndWorkingEpoch(t *testing.T) {
	const numRegions, numShards, n = 4, 8, 64
	const p = 0.0001

	h, err := NewHPBF(numRegions, numShards, n, p)
	if err != nil {
		t.Fatal(err)
	}
	filters := newExpectedFilters(t, numRegions, numShards, n, p)

	// Put 30 distinct logs into 30 of the 32 shards.
	for i := range 30 {
		regionID := strconv.Itoa(i % numRegions)
		shardID := int64(i / numRegions)
		site, dev, typ := fmt.Sprintf("site-%d", i), fmt.Sprintf("dev-%d", i), fmt.Sprintf("type-%d", i)
		if err := h.AddToken(regionID, shardID, site, dev, typ); err != nil {
			t.Fatalf("add log %d: %v", i, err)
		}
		for _, token := range testTokens(t, site, dev, typ) {
			filters[i%numRegions][int(shardID)].Add(token)
		}
	}

	shards0, regions0, global0, err := h.Commitment(0)
	if err != nil {
		t.Fatal(err)
	}
	root0 := global0.RootHash
	checkHPBFPartitions(t, shards0, regions0, global0, 0, numRegions, numShards)
	first := h.Finalized
	if first == nil || first.Epoch != 0 || h.Working == nil || h.Working.Epoch != 1 || first == h.Working {
		t.Fatal("commitment did not separate finalized epoch 0 from working epoch 1")
	}
	if want := expectedSnapshotRoot(t, first, filters); root0 != want {
		t.Fatalf("epoch 0 root = %x, want %x", root0, want)
	}
	if !slices.Equal(h.Working.Global.Regions["0"].Shards[0].bloomFilter.bits, filters[0][0].bits) {
		t.Fatal("working epoch did not inherit a log from the finalized epoch")
	}

	// The next log goes into Working; it cannot change the finalized snapshot.
	const regionID = "2"
	const shardID int64 = 7
	const site, dev, typ = "next-site", "next-dev", "next-type"
	if err := h.AddToken(regionID, shardID, site, dev, typ); err != nil {
		t.Fatal(err)
	}
	workingShard := h.Working.Global.Regions[regionID].Shards[shardID]
	if contains, err := workingShard.Contains(site, dev, typ); err != nil || !contains {
		t.Fatalf("new log missing from Working: contains=%v, err=%v", contains, err)
	}
	if h.Finalized != first || first.Global.RootHash != root0 {
		t.Fatal("adding a working log changed the finalized snapshot")
	}
	if !slices.Equal(first.Global.Regions[regionID].Shards[shardID].bloomFilter.bits, filters[2][7].bits) {
		t.Fatal("working log changed the finalized shard filter")
	}

	// Finalizing epoch 1 commits both the old logs and the new log.
	filters1 := newExpectedFilters(t, numRegions, numShards, n, p)
	for region := range numRegions {
		for shard := range numShards {
			copy(filters1[region][shard].bits, filters[region][shard].bits)
		}
	}
	for _, token := range testTokens(t, site, dev, typ) {
		filters1[2][7].Add(token)
	}
	shards1, regions1, global1, err := h.Commitment(1)
	if err != nil {
		t.Fatal(err)
	}
	root1 := global1.RootHash
	checkHPBFPartitions(t, shards1, regions1, global1, 1, numRegions, numShards)
	if h.Finalized == first || h.Finalized.Epoch != 1 || h.Working.Epoch != 2 {
		t.Fatal("second commitment did not advance the snapshots")
	}
	if want := expectedSnapshotRoot(t, h.Finalized, filters1); root1 != want {
		t.Fatalf("epoch 1 root = %x, want %x", root1, want)
	}
	if first.Global.RootHash != root0 {
		t.Fatal("second commitment changed the previous finalized root")
	}
	if !slices.Contains(h.CandidateShards(testTokens(t, site, dev, typ)), merkle.TreeID{
		Type: merkle.TreeShard, RegionID: regionID, ShardID: shardID,
	}) {
		t.Fatal("newly finalized log did not identify its shard")
	}
	if !slices.Contains(h.CandidateShards(testTokens(t, "site-0", "dev-0", "type-0")), merkle.TreeID{
		Type: merkle.TreeShard, RegionID: "0", ShardID: 0,
	}) {
		t.Fatal("old log did not remain searchable in the new finalized epoch")
	}
	for region := range numRegions {
		for shard := range numShards {
			workingBF := h.Working.Global.Regions[strconv.Itoa(region)].Shards[int64(shard)].bloomFilter
			if !slices.Equal(workingBF.bits, filters1[region][shard].bits) {
				t.Fatalf("region %d shard %d did not inherit cumulative filter bits", region, shard)
			}
		}
	}
}

func TestHPBFReturnedPartitionsAreCumulative(t *testing.T) {
	const numRegions, numShards, n = 2, 2, 64
	const p = 0.0001
	h, err := NewHPBF(numRegions, numShards, n, p)
	if err != nil {
		t.Fatal(err)
	}
	firstFilters := newExpectedFilters(t, numRegions, numShards, n, p)
	for _, entry := range []struct {
		region int
		shard  int64
		site   string
	}{
		{0, 0, "first"},
		{1, 1, "other-region"},
	} {
		if err := h.AddToken(strconv.Itoa(entry.region), entry.shard, entry.site, "device", "type"); err != nil {
			t.Fatal(err)
		}
		for _, token := range testTokens(t, entry.site, "device", "type") {
			firstFilters[entry.region][int(entry.shard)].Add(token)
		}
	}

	shards0, regions0, global0, err := h.Commitment(0)
	if err != nil {
		t.Fatal(err)
	}
	checkReturnedPartitionContents(t, h.Finalized, shards0, regions0, global0, firstFilters)
	firstBits := slices.Clone(shards0[0].BloomFilter.bits)

	// Add another log to the same shard in the next working epoch.
	if err := h.AddToken("0", 0, "second", "device", "type"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(shards0[0].BloomFilter.bits, firstBits) {
		t.Fatal("new working log mutated the returned epoch 0 partition")
	}
	secondFilters := newExpectedFilters(t, numRegions, numShards, n, p)
	for region := range numRegions {
		for shard := range numShards {
			copy(secondFilters[region][shard].bits, firstFilters[region][shard].bits)
		}
	}
	for _, token := range testTokens(t, "second", "device", "type") {
		secondFilters[0][0].Add(token)
	}

	shards1, regions1, global1, err := h.Commitment(1)
	if err != nil {
		t.Fatal(err)
	}
	checkReturnedPartitionContents(t, h.Finalized, shards1, regions1, global1, secondFilters)
	if global0.RootHash == global1.RootHash {
		t.Fatal("new epoch returned the previous global commitment")
	}
	for _, token := range testTokens(t, "first", "device", "type") {
		if !shards1[0].BloomFilter.Contains(token) || !regions1[0].BloomFilter.Contains(token) {
			t.Fatal("old log is missing from cumulative returned partitions")
		}
	}
	for _, token := range testTokens(t, "second", "device", "type") {
		if !shards1[0].BloomFilter.Contains(token) || !regions1[0].BloomFilter.Contains(token) {
			t.Fatal("new log is missing from returned partitions")
		}
	}
	if !slices.Equal(shards0[0].BloomFilter.bits, firstBits) {
		t.Fatal("second commitment changed the returned epoch 0 partition")
	}
}

func checkReturnedPartitionContents(t *testing.T, snapshot *HPBFSnapshot, shards []ShardHPBFPartition, regions []RegionHPBFPartition, global GlobalHPBFPartition, expected [][]*BloomFilter) {
	t.Helper()
	checkHPBFPartitions(t, shards, regions, global, snapshot.Epoch, len(expected), len(expected[0]))
	if want := expectedSnapshotRoot(t, snapshot, expected); global.RootHash != want {
		t.Fatalf("returned global root = %x, want %x", global.RootHash, want)
	}
	if global.InternalNodes[len(global.InternalNodes)-1][0].Hash != global.RootHash {
		t.Fatal("returned global internal nodes do not lead to the root")
	}
	for regionIndex, region := range regions {
		regionID := strconv.Itoa(regionIndex)
		if region.RootHash != snapshot.Global.Regions[regionID].Root ||
			region.InternalNodes[len(region.InternalNodes)-1][0].Hash != region.RootHash {
			t.Fatalf("region %s returned root or internal nodes differ", regionID)
		}
		mergedBits := make([]uint64, len(expected[regionIndex][0].bits))
		for shardIndex, bf := range expected[regionIndex] {
			shard := shards[regionIndex*len(expected[regionIndex])+shardIndex]
			if !slices.Equal(shard.BloomFilter.bits, bf.bits) ||
				shard.Commitment != snapshot.Global.Regions[regionID].Shards[int64(shardIndex)].RootHash {
				t.Fatalf("region %s shard %d returned partition differs", regionID, shardIndex)
			}
			for i, word := range bf.bits {
				mergedBits[i] |= word
			}
		}
		if !slices.Equal(region.BloomFilter.bits, mergedBits) {
			t.Fatalf("region %s returned Bloom filter is not the union of its shards", regionID)
		}
	}
}

func checkHPBFPartitions(t *testing.T, shards []ShardHPBFPartition, regions []RegionHPBFPartition, global GlobalHPBFPartition, epoch uint64, numRegions, numShards int) {
	t.Helper()
	if len(shards) != numRegions*numShards || len(regions) != numRegions || global.Epoch != epoch || len(global.InternalNodes) == 0 {
		t.Fatalf("epoch %d returned incomplete HPBF partitions", epoch)
	}
	for regionIndex, region := range regions {
		if region.TreeID != (merkle.TreeID{Type: merkle.TreeRegion, RegionID: strconv.Itoa(regionIndex)}) ||
			region.Epoch != epoch || region.Index != uint64(regionIndex) || region.BloomFilter == nil || len(region.InternalNodes) == 0 {
			t.Fatalf("epoch %d region %d partition has incorrect metadata", epoch, regionIndex)
		}
		for shardIndex := range numShards {
			shard := shards[regionIndex*numShards+shardIndex]
			if shard.TreeID != (merkle.TreeID{Type: merkle.TreeShard, RegionID: region.TreeID.RegionID, ShardID: int64(shardIndex)}) ||
				shard.Epoch != epoch || shard.Index != uint64(shardIndex) || shard.BloomFilter == nil || shard.Commitment == ([32]byte{}) {
				t.Fatalf("epoch %d region %d shard %d partition has incorrect metadata", epoch, regionIndex, shardIndex)
			}
		}
	}
}

func newExpectedFilters(t *testing.T, numRegions, numShards, n int, p float64) [][]*BloomFilter {
	t.Helper()
	filters := make([][]*BloomFilter, numRegions)
	for region := range filters {
		filters[region] = make([]*BloomFilter, numShards)
		for shard := range filters[region] {
			bf, err := newBloomFilter(n, p)
			if err != nil {
				t.Fatal(err)
			}
			filters[region][shard] = bf
		}
	}
	return filters
}

func testTokens(t *testing.T, site, dev, typ string) [3][]byte {
	t.Helper()
	parts := [][]any{{site}, {site, dev}, {site, dev, typ}}
	var tokens [3][]byte
	for i, args := range parts {
		encoded, err := domain.Serialize(args...)
		if err != nil {
			t.Fatal(err)
		}
		tokens[i] = encoded
	}
	return tokens
}

func expectedSnapshotRoot(t *testing.T, snapshot *HPBFSnapshot, filters [][]*BloomFilter) [32]byte {
	t.Helper()
	regionRoots := make([][32]byte, len(filters))
	for regionIndex, shards := range filters {
		regionID := strconv.Itoa(regionIndex)
		region := snapshot.Global.Regions[regionID]
		shardRoots := make([][32]byte, len(shards))
		for shardIndex, bf := range shards {
			actual := region.Shards[int64(shardIndex)]
			if !slices.Equal(actual.bloomFilter.bits, bf.bits) {
				t.Fatalf("region %s shard %d filter differs from inserted logs", regionID, shardIndex)
			}
			parts := []any{bf.m, bf.k}
			for _, word := range bf.bits {
				parts = append(parts, word)
			}
			encodedBF, err := domain.Serialize(parts...)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := domain.Serialize([]byte("SHBF"), snapshot.Epoch, regionID, uint64(shardIndex), encodedBF)
			if err != nil {
				t.Fatal(err)
			}
			shardRoots[shardIndex] = sha256.Sum256(encoded)
			if actual.RootHash != shardRoots[shardIndex] {
				t.Fatalf("region %s shard %d commitment differs", regionID, shardIndex)
			}
		}
		regionRoots[regionIndex] = expectedMerkleRoot(t, "HBPFREGINT", shardRoots)
		if region.Root != regionRoots[regionIndex] {
			t.Fatalf("region %s root differs", regionID)
		}
	}
	want := expectedMerkleRoot(t, "HBPFGLOBALINT", regionRoots)
	if snapshot.Global.RootHash != want {
		t.Fatal("global root differs from region commitments")
	}
	return want
}

func expectedMerkleRoot(t *testing.T, tag string, hashes [][32]byte) [32]byte {
	t.Helper()
	for len(hashes) > 1 {
		parents := make([][32]byte, len(hashes)/2)
		for i := range parents {
			encoded, err := domain.Serialize([]byte(tag), hashes[2*i][:], hashes[2*i+1][:])
			if err != nil {
				t.Fatal(err)
			}
			parents[i] = sha256.Sum256(encoded)
		}
		hashes = parents
	}
	return hashes[0]
}
