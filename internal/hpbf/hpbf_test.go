package hpbf

import (
	"crypto/sha256"
	"fmt"
	"reflect"
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
	if contains, _, err := workingShard.Contains(site, dev, typ); err != nil || !contains {
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
	_, newLogShards, _ := h.CandidateRegionShards(testTokens(t, site, dev, typ))
	if !slices.Contains(newLogShards, merkle.TreeID{
		Type: merkle.TreeShard, RegionID: regionID, ShardID: shardID,
	}) {
		t.Fatal("newly finalized log did not identify its shard")
	}
	_, oldLogShards, _ := h.CandidateRegionShards(testTokens(t, "site-0", "dev-0", "type-0"))
	if !slices.Contains(oldLogShards, merkle.TreeID{
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

func TestHPBFProofGenerationAndReturn(t *testing.T) {
	h, err := NewHPBF(3, 3, 64, 0.0001)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct {
		region string
		shard  int64
		site   string
	}{
		{"0", 0, "site-a"},
		{"0", 2, "site-b"},
		{"1", 1, "site-c"},
		{"2", 2, "site-d"},
	} {
		if err := h.AddToken(entry.region, entry.shard, entry.site, "device", "type"); err != nil {
			t.Fatal(err)
		}
	}
	shardPartitions, regionPartitions, globalPartition, err := h.Commitment(0)
	if err != nil {
		t.Fatal(err)
	}

	tokens := testTokens(t, "site-b", "device", "type")
	candidateRegions, candidateShards, proof := h.CandidateRegionShards(tokens)
	if proof.TreeID != (merkle.TreeID{Type: merkle.TreeGlobal}) || proof.Epoch != 0 ||
		len(proof.Regions) != 3 {
		t.Fatal("global proof has incorrect identity, epoch, or region count")
	}

	regionRoots := make([][32]byte, 3)
	var wantRegions, wantShards []merkle.TreeID
	for regionIndex, regionProof := range proof.Regions {
		regionID := strconv.Itoa(regionIndex)
		if regionProof.TreeID != (merkle.TreeID{Type: merkle.TreeRegion, RegionID: regionID}) ||
			len(regionProof.Shards) != 3 ||
			!slices.Equal(regionProof.bits, regionPartitions[regionIndex].BloomFilter.bits) {
			t.Fatalf("region %s proof is incomplete", regionID)
		}
		shardHashes := make([][32]byte, 3)
		regionMatches := true
		for _, token := range tokens {
			if !regionProof.BloomFilter.Contains(token) {
				regionMatches = false
				break
			}
		}
		if regionMatches {
			wantRegions = append(wantRegions, regionProof.TreeID)
		}
		for shardIndex, shardProof := range regionProof.Shards {
			partition := shardPartitions[regionIndex*3+shardIndex]
			if shardProof.TreeID != (merkle.TreeID{Type: merkle.TreeShard, RegionID: regionID, ShardID: int64(shardIndex)}) ||
				!slices.Equal(shardProof.bits, partition.BloomFilter.bits) {
				t.Fatalf("region %s shard %d proof differs from its partition", regionID, shardIndex)
			}
			shardHashes[shardIndex] = proofShardHash(t, proof.Epoch, shardProof)
			if shardHashes[shardIndex] != partition.Commitment {
				t.Fatalf("region %s shard %d proof hashes incorrectly", regionID, shardIndex)
			}
			if regionMatches {
				matches := true
				for _, token := range tokens {
					if !shardProof.BloomFilter.Contains(token) {
						matches = false
						break
					}
				}
				if matches {
					wantShards = append(wantShards, shardProof.TreeID)
				}
			}
		}
		wantLevels := proofMerkleLevels(t, "HBPFREGINT", shardHashes)
		if !reflect.DeepEqual(regionProof.Levels, wantLevels) ||
			wantLevels[len(wantLevels)-1][0] != regionPartitions[regionIndex].RootHash {
			t.Fatalf("region %s proof does not recompute its Merkle root", regionID)
		}
		regionRoots[regionIndex] = regionPartitions[regionIndex].RootHash
	}
	wantGlobalLevels := proofMerkleLevels(t, "HBPFGLOBALINT", regionRoots)
	if !reflect.DeepEqual(proof.Levels, wantGlobalLevels) ||
		wantGlobalLevels[len(wantGlobalLevels)-1][0] != globalPartition.RootHash {
		t.Fatal("global proof does not recompute its Merkle root")
	}
	checkSameTreeIDs(t, candidateRegions, wantRegions)
	checkSameTreeIDs(t, candidateShards, wantShards)
	if !slices.Contains(candidateRegions, merkle.TreeID{Type: merkle.TreeRegion, RegionID: "0"}) ||
		!slices.Contains(candidateShards, merkle.TreeID{Type: merkle.TreeShard, RegionID: "0", ShardID: 2}) {
		t.Fatal("query did not return the region and shard containing the log")
	}

	// Proof data must remain stable while the next epoch receives logs.
	shardBits := slices.Clone(proof.Regions[0].Shards[2].bits)
	if err := h.AddToken("0", 2, "later", "device", "type"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(proof.Regions[0].Shards[2].bits, shardBits) {
		t.Fatal("working epoch changed the returned shard proof")
	}
	globalLeaf := h.Finalized.Global.levels[0][0].Hash
	proof.Levels[0][0][0] ^= 1
	if h.Finalized.Global.levels[0][0].Hash != globalLeaf {
		t.Fatal("returned Merkle levels share storage with the finalized tree")
	}
	finalizedRegion := h.Finalized.Global.Regions["0"]
	regionWord := finalizedRegion.BloomFilter.bits[0]
	proof.Regions[0].bits[0] ^= 1
	if finalizedRegion.BloomFilter.bits[0] != regionWord {
		t.Fatal("returned region filter shares storage with the finalized tree")
	}
	shardWord := finalizedRegion.Shards[2].bloomFilter.bits[0]
	proof.Regions[0].Shards[2].bits[0] ^= 1
	if finalizedRegion.Shards[2].bloomFilter.bits[0] != shardWord {
		t.Fatal("returned shard filter shares storage with the finalized tree")
	}
	regionLeaf := finalizedRegion.levels[0][0].Hash
	proof.Regions[0].Levels[0][0][0] ^= 1
	if finalizedRegion.levels[0][0].Hash != regionLeaf {
		t.Fatal("returned region levels share storage with the finalized tree")
	}
}

func proofShardHash(t *testing.T, epoch uint64, proof ShardHPBFProof) [32]byte {
	t.Helper()
	parts := []any{proof.m, proof.k}
	for _, word := range proof.bits {
		parts = append(parts, word)
	}
	encodedBF, err := domain.Serialize(parts...)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := domain.Serialize([]byte("SHBF"), epoch, proof.RegionID, uint64(proof.ShardID), encodedBF)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(encoded)
}

func proofMerkleLevels(t *testing.T, tag string, leaves [][32]byte) [][][32]byte {
	t.Helper()
	levels := [][][32]byte{slices.Clone(leaves)}
	for len(levels[len(levels)-1]) > 1 {
		children := levels[len(levels)-1]
		parents := make([][32]byte, (len(children)+1)/2)
		for i := range parents {
			parents[i] = children[2*i]
			if 2*i+1 < len(children) {
				encoded, err := domain.Serialize([]byte(tag), children[2*i][:], children[2*i+1][:])
				if err != nil {
					t.Fatal(err)
				}
				parents[i] = sha256.Sum256(encoded)
			}
		}
		levels = append(levels, parents)
	}
	return levels
}

func checkSameTreeIDs(t *testing.T, got, want []merkle.TreeID) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("candidate IDs = %v, want %v", got, want)
	}
	for _, id := range want {
		if !slices.Contains(got, id) {
			t.Fatalf("candidate IDs = %v, missing %v", got, id)
		}
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

func TestHPBFCandidateLifecycleAndReturnedEvidence(t *testing.T) {
	const n, p = 64, 0.000001
	h, err := NewHPBF(2, 2, n, p)
	if err != nil {
		t.Fatal(err)
	}
	sealed := TokenRecord{RegionID: "0", ShardID: 0, SiteID: "sealed-site", DeviceID: "sealed-device", Type: "sealed-type"}
	active := TokenRecord{RegionID: "0", ShardID: 1, SiteID: "active-site", DeviceID: "active-device", Type: "active-type"}
	later := TokenRecord{RegionID: "1", ShardID: 0, SiteID: "later-site", DeviceID: "later-device", Type: "later-type"}
	for _, record := range []TokenRecord{sealed, active} {
		if err := h.AddToken(record.RegionID, record.ShardID, record.SiteID, record.DeviceID, record.Type); err != nil {
			t.Fatal(err)
		}
	}
	firstFinalized := h.Finalized
	root1, err := h.PrepareCandidate(1, []TokenRecord{sealed})
	if err != nil {
		t.Fatal(err)
	}
	if h.Finalized != firstFinalized || h.Finalized.Epoch != 0 || h.Candidate == nil || h.Candidate.Epoch != 1 || h.Working.Epoch != 2 {
		t.Fatal("preparation did not keep Finalized and Working separate")
	}
	shards, regions, global, err := h.CandidatePartitions(1)
	if err != nil {
		t.Fatal(err)
	}
	checkHPBFPartitions(t, shards, regions, global, 1, 2, 2)
	if root1 != global.RootHash {
		t.Fatal("returned Global root differs from candidate")
	}
	expected1 := newExpectedFilters(t, 2, 2, n, p)
	for _, token := range testTokens(t, sealed.SiteID, sealed.DeviceID, sealed.Type) {
		expected1[0][0].Add(token)
	}
	if want := expectedSnapshotRoot(t, h.Candidate, expected1); want != root1 {
		t.Fatalf("candidate root = %x, want %x", root1, want)
	}
	for _, token := range testTokens(t, active.SiteID, active.DeviceID, active.Type) {
		if shards[1].BloomFilter.Contains(token) {
			t.Fatal("active token entered candidate Shard")
		}
	}
	if err := h.AddToken(later.RegionID, later.ShardID, later.SiteID, later.DeviceID, later.Type); err != nil {
		t.Fatal(err)
	}
	if retry, err := h.PrepareCandidate(1, []TokenRecord{active, later}); err != nil || retry != root1 {
		t.Fatalf("retry changed prepared candidate: %x, %v", retry, err)
	}
	// Returned filters and Merkle nodes must be detached from the prepared tree.
	shards[0].BloomFilter.bits[0] ^= 1
	regions[0].BloomFilter.bits[0] ^= 1
	regions[0].InternalNodes[0][0].Hash[0] ^= 1
	global.InternalNodes[0][0].Hash[0] ^= 1
	againShards, againRegions, againGlobal, err := h.CandidatePartitions(1)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(againShards[0].BloomFilter.bits, expected1[0][0].bits) ||
		againRegions[0].RootHash != h.Candidate.Global.Regions["0"].Root ||
		againRegions[0].InternalNodes[0][0].Hash != h.Candidate.Global.Regions["0"].levels[1][0].Hash ||
		againGlobal.InternalNodes[0][0].Hash != h.Candidate.Global.levels[1][0].Hash {
		t.Fatal("returned evidence changed the prepared candidate")
	}
	if err := h.ValidateCandidate(1); err != nil {
		t.Fatal(err)
	}
	if err := h.CommitCandidate(1); err != nil {
		t.Fatal(err)
	}
	if h.Finalized.Epoch != 1 || h.Finalized.Global.RootHash != root1 || h.Candidate != nil {
		t.Fatal("promotion did not publish and clear candidate")
	}
	_, matchedShards, proof := h.CandidateRegionShards(testTokens(t, sealed.SiteID, sealed.DeviceID, sealed.Type))
	if !slices.Contains(matchedShards, merkle.TreeID{Type: merkle.TreeShard, RegionID: "0", ShardID: 0}) || proof.Epoch != 1 {
		t.Fatal("promoted sealed token is not searchable with its proof")
	}
	_, activeShards, _ := h.CandidateRegionShards(testTokens(t, active.SiteID, active.DeviceID, active.Type))
	if len(activeShards) != 0 {
		t.Fatal("active token became searchable before next promotion")
	}
	epoch, m, k, words, err := h.WorkingShardFilter("0", 1)
	if err != nil || epoch != 2 || m == 0 || k == 0 || len(words) == 0 {
		t.Fatalf("working filter metadata: %d/%d/%d, %v", epoch, m, k, err)
	}
	words[0] ^= 1
	_, _, _, untouched, err := h.WorkingShardFilter("0", 1)
	if err != nil || words[0] == untouched[0] {
		t.Fatal("working filter snapshot shares storage")
	}
	root2, err := h.PrepareCandidate(2, []TokenRecord{active})
	if err != nil {
		t.Fatal(err)
	}
	if root2 == root1 || firstFinalized.Epoch != 0 || h.Finalized.Epoch != 1 {
		t.Fatal("second preparation changed historical snapshot")
	}
	expected2 := newExpectedFilters(t, 2, 2, n, p)
	for region := range expected1 {
		for shard := range expected1[region] {
			copy(expected2[region][shard].bits, expected1[region][shard].bits)
		}
	}
	for _, token := range testTokens(t, active.SiteID, active.DeviceID, active.Type) {
		expected2[0][1].Add(token)
	}
	if want := expectedSnapshotRoot(t, h.Candidate, expected2); want != root2 {
		t.Fatalf("second candidate root = %x, want %x", root2, want)
	}
	secondShards, _, _, err := h.CandidatePartitions(2)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range testTokens(t, later.SiteID, later.DeviceID, later.Type) {
		if secondShards[2].BloomFilter.Contains(token) {
			t.Fatal("later working token entered epoch 2")
		}
	}
	if err := h.CommitCandidate(2); err != nil {
		t.Fatal(err)
	}
	_, activeShards, proof = h.CandidateRegionShards(testTokens(t, active.SiteID, active.DeviceID, active.Type))
	if !slices.Contains(activeShards, merkle.TreeID{Type: merkle.TreeShard, RegionID: "0", ShardID: 1}) || proof.Epoch != 2 {
		t.Fatal("second epoch did not publish active token")
	}
}

func TestHPBFCandidateEmptyEpochAndErrors(t *testing.T) {
	var nilHPBF *HPBF
	if _, err := nilHPBF.PrepareCandidate(1, nil); err == nil {
		t.Fatal("nil HPBF prepared")
	}
	h, err := NewHPBF(1, 2, 64, 0.000001)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := h.CandidatePartitions(1); err == nil {
		t.Fatal("unprepared partitions returned")
	}
	if err := h.ValidateCandidate(1); err == nil {
		t.Fatal("unprepared candidate validated")
	}
	if err := h.CommitCandidate(1); err == nil {
		t.Fatal("unprepared candidate promoted")
	}
	if _, err := h.PrepareCandidate(0, nil); err == nil {
		t.Fatal("nonadvancing epoch prepared")
	}
	invalid := TokenRecord{RegionID: "missing", ShardID: 0, SiteID: "site", DeviceID: "device", Type: "type"}
	if _, err := h.PrepareCandidate(1, []TokenRecord{invalid}); err == nil || h.Candidate != nil {
		t.Fatal("invalid Shard record published a candidate")
	}
	sealed := TokenRecord{RegionID: "0", ShardID: 0, SiteID: "sealed", DeviceID: "device", Type: "type"}
	if err := h.AddToken(sealed.RegionID, sealed.ShardID, sealed.SiteID, sealed.DeviceID, sealed.Type); err != nil {
		t.Fatal(err)
	}
	root1, err := h.PrepareCandidate(1, []TokenRecord{sealed})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.PrepareCandidate(2, nil); err == nil {
		t.Fatal("conflicting epoch prepared")
	}
	if _, _, _, err := h.CandidatePartitions(2); err == nil {
		t.Fatal("wrong epoch partitions returned")
	}
	if err := h.ValidateCandidate(2); err == nil {
		t.Fatal("wrong epoch validated")
	}
	if err := h.CommitCandidate(2); err == nil || h.Finalized.Epoch != 0 {
		t.Fatal("wrong epoch promoted")
	}
	if err := h.CommitCandidate(1); err != nil {
		t.Fatal(err)
	}
	if err := h.CommitCandidate(1); err == nil {
		t.Fatal("candidate promoted twice")
	}
	active := TokenRecord{RegionID: "0", ShardID: 1, SiteID: "active", DeviceID: "device", Type: "type"}
	if err := h.AddToken(active.RegionID, active.ShardID, active.SiteID, active.DeviceID, active.Type); err != nil {
		t.Fatal(err)
	}
	emptyRoot, err := h.PrepareCandidate(2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if emptyRoot == root1 {
		t.Fatal("epoch-specific Shard commitments were reused")
	}
	shards, _, _, err := h.CandidatePartitions(2)
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range testTokens(t, sealed.SiteID, sealed.DeviceID, sealed.Type) {
		if !shards[0].BloomFilter.Contains(token) {
			t.Fatal("empty epoch lost finalized filter bits")
		}
	}
	for _, token := range testTokens(t, active.SiteID, active.DeviceID, active.Type) {
		if shards[1].BloomFilter.Contains(token) {
			t.Fatal("empty epoch included active token")
		}
	}
	if _, _, _, _, err := h.WorkingShardFilter("missing", 0); err == nil {
		t.Fatal("unknown Region returned working filter")
	}
	if _, _, _, _, err := h.WorkingShardFilter("0", 9); err == nil {
		t.Fatal("unknown Shard returned working filter")
	}
}
