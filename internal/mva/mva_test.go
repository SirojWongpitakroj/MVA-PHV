package mva

import (
	"crypto/sha256"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

func testMVALog(id byte, regionID string) (attrKey, PhysicalAddress, [32]byte) {
	logID := idKey{}.ID
	logID[15] = id
	return attrKey{
		SiteID: "site", DevID: "device", Type: "type",
		TS: time.Unix(int64(id), 0), ID: logID,
	}, PhysicalAddress{
		RegionID: regionID, ShardID: "0", SegmentID: "0", LeafID: strconv.Itoa(int(id)),
	}, [32]byte{id}
}

func TestNewMVAInitializesGlobalTree(t *testing.T) {
	for _, count := range []int{1, 2, 3, 4, 5} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			mva, err := NewMVA(count, 3)
			if err != nil {
				t.Fatal(err)
			}
			if mva.TreeID.Type != merkle.TreeGlobal || mva.LeafCount != int64(count) ||
				len(mva.Regions) != count || mva.Height != len(mva.Levels)-1 ||
				len(mva.Levels[0]) != count || len(mva.Levels[mva.Height]) != 1 {
				t.Fatalf("invalid global tree metadata for %d regions", count)
			}
			for i, region := range mva.Regions {
				regionID := strconv.Itoa(i)
				if region == nil || region.TreeID.Type != merkle.TreeRegion || region.TreeID.RegionID != regionID ||
					region.IDView == nil || region.AttrView == nil ||
					region.IDView.RootPage.RegionID != regionID || region.AttrView.RootPage.RegionID != regionID {
					t.Fatalf("region %d has incorrect ID or locator views", i)
				}
			}
		})
	}
	for _, count := range []int{0, -1} {
		if _, err := NewMVA(count, 3); err == nil {
			t.Fatalf("NewMVA(%d) should reject a non-positive region count", count)
		}
	}
}

func TestMVAIngestLogRoutesToBothViews(t *testing.T) {
	mva, err := NewMVA(3, 3)
	if err != nil {
		t.Fatal(err)
	}
	logicalAddr, physicalAddr, leafHash := testMVALog(1, "1")
	candidates := []merkle.TreeID{
		{Type: merkle.TreeRegion, RegionID: "0"},
		{Type: merkle.TreeRegion, RegionID: "1"},
		{Type: merkle.TreeRegion, RegionID: "2"},
	}
	idUpdate, attrUpdate, err := mva.IngestLog(candidates, logicalAddr, physicalAddr, leafHash)
	if err != nil {
		t.Fatal(err)
	}
	if idUpdate.RecordCount != 1 || attrUpdate.RecordCount != 1 ||
		idUpdate.RootHash != mva.Regions[1].IDView.RootHash ||
		attrUpdate.RootHash != mva.Regions[1].AttrView.RootHash {
		t.Fatal("ingest did not update both locator views")
	}
	for i, region := range mva.Regions {
		want := int64(0)
		if i == 1 {
			want = 1
		}
		if region.IDView.LeafCount != want || region.AttrView.LeafCount != want {
			t.Fatalf("region %d has unexpected locator record counts", i)
		}
	}
	if _, _, err := mva.Regions[1].resolve(idKey{ID: logicalAddr.ID}); err == nil {
		t.Fatal("working log resolved before the first commitment")
	}
	if _, err := mva.Commitment(); err != nil {
		t.Fatal(err)
	}
	idValues, _, err := mva.Regions[1].resolve(idKey{ID: logicalAddr.ID})
	if err != nil || len(idValues) != 1 || idValues[0].PhysicalAddress != physicalAddr || idValues[0].LeafHash != leafHash {
		t.Fatalf("ID view did not resolve the ingested log: %v", err)
	}
	attrValues, _, err := mva.Regions[1].resolve(AttrRangeQuery{
		SiteID: logicalAddr.SiteID, DevID: logicalAddr.DevID, Type: logicalAddr.Type,
		StartTS: logicalAddr.TS, EndTS: logicalAddr.TS,
	})
	if err != nil || len(attrValues) != 1 || attrValues[0].PhysicalAddress != physicalAddr || attrValues[0].LeafHash != leafHash {
		t.Fatalf("attribute view did not resolve the ingested log: %v", err)
	}
}

func TestMVAResolveReturnsGlobalAndRegionProof(t *testing.T) {
	mva, err := NewMVA(3, 3)
	if err != nil {
		t.Fatal(err)
	}
	mva.Epoch = 7
	key, address, leafHash := testMVALog(1, "1")
	candidate := merkle.TreeID{Type: merkle.TreeRegion, RegionID: "1"}
	if _, _, err := mva.IngestLog([]merkle.TreeID{candidate}, key, address, leafHash); err != nil {
		t.Fatal(err)
	}
	if _, err := mva.Commitment(); err != nil {
		t.Fatal(err)
	}
	query := idKey{ID: key.ID}
	values, proof, err := mva.Resolve(query, []merkle.TreeID{
		{Type: merkle.TreeRegion, RegionID: "0"}, candidate,
		{Type: merkle.TreeRegion, RegionID: "2"}, candidate,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || values[0].PhysicalAddress != address || proof == nil ||
		proof.Epoch != mva.Epoch ||
		len(proof.Regions) != 1 || proof.Regions["1"] == nil ||
		proof.Regions["1"].View != ViewID || len(proof.Regions["1"].Path) == 0 {
		t.Fatal("MVA resolve did not return the matched value and region proof")
	}
	if len(proof.Levels) != len(mva.Levels) {
		t.Fatal("MVA proof has the wrong number of global levels")
	}
	for level := range mva.Levels {
		if !slices.Equal(proof.Levels[level], mva.Levels[level]) {
			t.Fatalf("MVA proof global level %d differs from the commitment", level)
		}
	}
	proof.Levels[0][0] = [32]byte{}
	if mva.Levels[0][0] == ([32]byte{}) {
		t.Fatal("MVA proof shares level storage with the tree")
	}
	noValues, noMatchProof, err := mva.Resolve(query, []merkle.TreeID{{Type: merkle.TreeRegion, RegionID: "0"}})
	if err != nil || len(noValues) != 0 || noMatchProof == nil || len(noMatchProof.Regions) != 0 {
		t.Fatalf("nonmatching candidate returned values or region proofs: %v", err)
	}
}

func TestMVAFinalizedSnapshotIsolation(t *testing.T) {
	mva, err := NewMVA(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	candidates := []merkle.TreeID{{Type: merkle.TreeRegion, RegionID: "0"}}
	var firstKey attrKey
	var firstHash [32]byte
	for id := byte(1); id <= 5; id++ {
		key, address, hash := testMVALog(id, "0")
		if id == 1 {
			firstKey, firstHash = key, hash
		}
		if _, _, err := mva.IngestLog(candidates, key, address, hash); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := mva.Resolve(idKey{ID: firstKey.ID}, candidates); err == nil {
		t.Fatal("MVA resolved a working log before its first commitment")
	}
	mva.Epoch = 3
	firstRoot, err := mva.Commitment()
	if err != nil {
		t.Fatal(err)
	}
	oldGlobal := mva.Finalized
	oldRegion := mva.Regions[0].Finalized
	if oldGlobal == nil || oldGlobal.Epoch != 3 || oldGlobal.Root != firstRoot ||
		oldGlobal.Regions["0"] != oldRegion || oldRegion == nil ||
		oldRegion.IDView.LeafCount != 5 || oldRegion.IDView.RootPage == mva.Regions[0].IDView.RootPage {
		t.Fatal("commitment did not publish an independent finalized snapshot")
	}
	leaf := oldRegion.IDView.RootPage
	for !leaf.IsLeaf {
		leaf = leaf.Children[0]
	}
	var previous *Page
	records := 0
	for leaf != nil {
		if leaf.Prev != previous {
			t.Fatal("finalized leaf links were not copied correctly")
		}
		records += len(leaf.Values)
		previous, leaf = leaf, leaf.Next
	}
	if records != 5 {
		t.Fatalf("finalized leaves hold %d records, want 5", records)
	}

	mva.Epoch = 4
	newKey, newAddress, newHash := testMVALog(6, "0")
	if _, _, err := mva.IngestLog(candidates, newKey, newAddress, newHash); err != nil {
		t.Fatal(err)
	}
	if mva.Regions[0].IDView.LeafCount != 6 || oldRegion.IDView.LeafCount != 5 || mva.Finalized != oldGlobal {
		t.Fatal("working ingestion changed the finalized snapshot")
	}
	if values, _, err := mva.Resolve(idKey{ID: newKey.ID}, candidates); err != nil || len(values) != 0 {
		t.Fatalf("uncommitted log appeared in MVA resolve: %v", err)
	}
	if values, _, err := mva.Regions[0].resolve(idKey{ID: newKey.ID}); err != nil || len(values) != 0 {
		t.Fatalf("uncommitted log appeared in region resolve: %v", err)
	}
	oldValues, oldProof, err := mva.Resolve(idKey{ID: firstKey.ID}, candidates)
	if err != nil || len(oldValues) != 1 || oldValues[0].LeafHash != firstHash ||
		oldProof.Epoch != 3 || oldProof.Levels[len(oldProof.Levels)-1][0] != firstRoot {
		t.Fatalf("finalized query changed after working ingestion: %v", err)
	}
	oldValues[0].LeafHash = [32]byte{99}
	oldValues, _, err = mva.Resolve(idKey{ID: firstKey.ID}, candidates)
	if err != nil || len(oldValues) != 1 || oldValues[0].LeafHash != firstHash {
		t.Fatal("returned value mutated finalized state")
	}

	secondRoot, err := mva.Commitment()
	if err != nil || secondRoot == firstRoot || mva.Finalized == oldGlobal ||
		mva.Finalized.Epoch != 4 || mva.Regions[0].Finalized.IDView.LeafCount != 6 ||
		oldRegion.IDView.LeafCount != 5 {
		t.Fatalf("next commitment did not replace the finalized snapshot: %v", err)
	}
	if values, proof, err := mva.Resolve(idKey{ID: newKey.ID}, candidates); err != nil ||
		len(values) != 1 || values[0].LeafHash != newHash || proof.Epoch != 4 {
		t.Fatalf("newly finalized log did not resolve: %v", err)
	}
}

func TestMVAIngestLogErrors(t *testing.T) {
	logicalAddr, physicalAddr, leafHash := testMVALog(1, "1")
	validCandidate := merkle.TreeID{Type: merkle.TreeRegion, RegionID: "1"}
	var nilMVA *MVA
	if _, _, err := nilMVA.IngestLog([]merkle.TreeID{validCandidate}, logicalAddr, physicalAddr, leafHash); err == nil {
		t.Fatal("nil MVA should reject ingestion")
	}
	tests := []struct {
		name       string
		candidates []merkle.TreeID
		address    PhysicalAddress
		change     func(*MVA)
	}{
		{name: "no candidate", address: physicalAddr},
		{name: "wrong candidate type", candidates: []merkle.TreeID{{Type: merkle.TreeShard, RegionID: "1"}}, address: physicalAddr},
		{name: "unknown region", candidates: []merkle.TreeID{{Type: merkle.TreeRegion, RegionID: "9"}}, address: PhysicalAddress{RegionID: "9"}},
		{name: "wrong region type", candidates: []merkle.TreeID{validCandidate}, address: physicalAddr, change: func(m *MVA) { m.Regions[1].Type = merkle.TreeShard }},
		{name: "missing ID view", candidates: []merkle.TreeID{validCandidate}, address: physicalAddr, change: func(m *MVA) { m.Regions[1].IDView = nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mva, err := NewMVA(2, 3)
			if err != nil {
				t.Fatal(err)
			}
			if test.change != nil {
				test.change(mva)
			}
			if _, _, err := mva.IngestLog(test.candidates, logicalAddr, test.address, leafHash); err == nil {
				t.Fatal("expected an ingestion error")
			}
			for _, region := range mva.Regions {
				if region.IDView != nil && region.IDView.LeafCount != 0 || region.AttrView.LeafCount != 0 {
					t.Fatal("failed ingestion changed a locator view")
				}
			}
		})
	}
}

func TestMVACommitmentTreeSizes(t *testing.T) {
	for _, count := range []int{1, 2, 4, 5} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			mva, err := NewMVA(count, 3)
			if err != nil {
				t.Fatal(err)
			}
			root, err := mva.Commitment()
			if err != nil {
				t.Fatal(err)
			}
			current := make([][32]byte, count)
			for i, region := range mva.Regions {
				current[i] = region.Root
			}
			for level := 0; ; level++ {
				if level >= len(mva.Levels) || !slices.Equal(mva.Levels[level], current) {
					t.Fatalf("global level %d differs from independently hashed region roots", level)
				}
				if len(current) == 1 {
					if level != mva.Height || root != current[0] || mva.Root != root {
						t.Fatal("global root or height is wrong")
					}
					break
				}
				parents := make([][32]byte, (len(current)+1)/2)
				for i := range parents {
					left := current[2*i]
					if 2*i+1 == len(current) {
						parents[i] = left
						continue
					}
					encoded, err := domain.Serialize([]byte("MVAGLOBALINT"), left[:], current[2*i+1][:])
					if err != nil {
						t.Fatal(err)
					}
					parents[i] = sha256.Sum256(encoded)
				}
				current = parents
			}
		})
	}
}

func TestMVACommitmentUsesRegionRootsAsLeaves(t *testing.T) {
	mva, err := NewMVA(3, 3)
	if err != nil {
		t.Fatal(err)
	}
	logID := idKey{}.ID
	logID[15] = 7
	logicalAddr := attrKey{
		SiteID: "site", DevID: "device", Type: "type",
		TS: time.Unix(100, 0), ID: logID,
	}
	physicalAddr := PhysicalAddress{
		RegionID: "1", ShardID: "0", SegmentID: "0", LeafID: "0",
	}
	_, _, err = mva.IngestLog(
		[]merkle.TreeID{{Type: merkle.TreeRegion, RegionID: "1"}},
		logicalAddr, physicalAddr, [32]byte{1},
	)
	if err != nil {
		t.Fatalf("ingest log: %v", err)
	}
	ingestedRegionRoot := mva.Regions[1].Root

	root, err := mva.Commitment()
	if err != nil {
		t.Fatalf("commit MVA: %v", err)
	}
	if len(mva.Levels) != 3 || len(mva.Levels[0]) != 3 ||
		len(mva.Levels[1]) != 2 || len(mva.Levels[2]) != 1 {
		t.Fatalf("unexpected global Merkle level sizes: %d", len(mva.Levels))
	}
	for index, region := range mva.Regions {
		encoded, err := domain.Serialize(
			[]byte("REGMVA"), region.TreeID.RegionID,
			region.IDView.RootHash[:], region.AttrView.RootHash[:],
		)
		if err != nil {
			t.Fatal(err)
		}
		wantLeaf := sha256.Sum256(encoded)
		if region.Root != wantLeaf || mva.Levels[0][index] != wantLeaf {
			t.Fatalf("leaf %d differs from region %q root", index, region.TreeID.RegionID)
		}
	}
	if mva.Levels[0][1] != ingestedRegionRoot {
		t.Fatal("ingested region root is not its global leaf")
	}

	hashPair := func(left, right [32]byte) [32]byte {
		t.Helper()
		encoded, err := domain.Serialize([]byte("MVAGLOBALINT"), left[:], right[:])
		if err != nil {
			t.Fatal(err)
		}
		return sha256.Sum256(encoded)
	}
	wantLeftParent := hashPair(mva.Levels[0][0], mva.Levels[0][1])
	if mva.Levels[1][0] != wantLeftParent || mva.Levels[1][1] != mva.Levels[0][2] {
		t.Fatal("global parent hashes or odd-leaf promotion are wrong")
	}
	wantRoot := hashPair(wantLeftParent, mva.Levels[0][2])
	if root != wantRoot || mva.Root != wantRoot || mva.Levels[2][0] != wantRoot {
		t.Fatal("global MVA root does not match the region-root Merkle tree")
	}
}

func TestMVACommitmentIncludesLaterIngestion(t *testing.T) {
	mva, err := NewMVA(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	candidate := []merkle.TreeID{{Type: merkle.TreeRegion, RegionID: "0"}}
	firstKey, firstAddress, firstHash := testMVALog(1, "0")
	if _, _, err := mva.IngestLog(candidate, firstKey, firstAddress, firstHash); err != nil {
		t.Fatal(err)
	}
	firstRoot, err := mva.Commitment()
	if err != nil {
		t.Fatal(err)
	}
	if again, err := mva.Commitment(); err != nil || again != firstRoot {
		t.Fatalf("unchanged MVA gave a different commitment: %v", err)
	}
	secondKey, secondAddress, secondHash := testMVALog(2, "0")
	if _, _, err := mva.IngestLog(candidate, secondKey, secondAddress, secondHash); err != nil {
		t.Fatal(err)
	}
	secondRoot, err := mva.Commitment()
	if err != nil || secondRoot == firstRoot || mva.Levels[0][0] != mva.Regions[0].Root {
		t.Fatalf("later log was not included in the next commitment: %v", err)
	}
	for _, key := range []attrKey{firstKey, secondKey} {
		values, _, err := mva.Regions[0].resolve(idKey{ID: key.ID})
		if err != nil || len(values) != 1 {
			t.Fatalf("committed log %v could not be resolved: %v", key.ID, err)
		}
	}
}

func TestMVACommitmentErrorsLeavePublishedRoot(t *testing.T) {
	var nilMVA *MVA
	if _, err := nilMVA.Commitment(); err == nil {
		t.Fatal("nil MVA should reject commitment")
	}
	if _, err := (&MVA{}).Commitment(); err == nil {
		t.Fatal("MVA without regions should reject commitment")
	}
	for _, test := range []struct {
		name   string
		change func(*MVA)
	}{
		{name: "leaf count mismatch", change: func(m *MVA) { m.LeafCount++ }},
		{name: "nil region", change: func(m *MVA) { m.Regions[1] = nil }},
		{name: "incomplete region", change: func(m *MVA) { m.Regions[1].AttrView = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			mva, err := NewMVA(2, 3)
			if err != nil {
				t.Fatal(err)
			}
			published, err := mva.Commitment()
			if err != nil {
				t.Fatal(err)
			}
			publishedSnapshot := mva.Finalized
			publishedLeaves := slices.Clone(mva.Levels[0])
			test.change(mva)
			if _, err := mva.Commitment(); err == nil {
				t.Fatal("expected commitment to fail")
			}
			if mva.Root != published || !slices.Equal(mva.Levels[0], publishedLeaves) ||
				mva.Finalized != publishedSnapshot {
				t.Fatal("failed commitment changed the published global tree")
			}
		})
	}
}

func TestMVAIngestAndCommitmentWaitForStateLock(t *testing.T) {
	mva, err := NewMVA(1, 3)
	if err != nil {
		t.Fatal(err)
	}
	logicalAddr, physicalAddr, leafHash := testMVALog(1, "0")
	checkBlocked := func(name string, run func() error) {
		t.Helper()
		mva.mu.Lock()
		locked := true
		defer func() {
			if locked {
				mva.mu.Unlock()
			}
		}()
		started := make(chan struct{})
		done := make(chan error, 1)
		go func() {
			close(started)
			done <- run()
		}()
		<-started
		select {
		case err := <-done:
			t.Fatalf("%s completed while state lock was held: %v", name, err)
		case <-time.After(30 * time.Millisecond):
		}
		mva.mu.Unlock()
		locked = false
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("%s failed after state lock released: %v", name, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s did not finish after state lock released", name)
		}
	}
	checkBlocked("ingestion", func() error {
		_, _, err := mva.IngestLog(
			[]merkle.TreeID{{Type: merkle.TreeRegion, RegionID: "0"}},
			logicalAddr, physicalAddr, leafHash,
		)
		return err
	})
	checkBlocked("commitment", func() error {
		_, err := mva.Commitment()
		return err
	})
	checkBlocked("resolution", func() error {
		_, _, err := mva.Resolve(
			idKey{ID: logicalAddr.ID},
			[]merkle.TreeID{{Type: merkle.TreeRegion, RegionID: "0"}},
		)
		return err
	})
}

func TestMVALockIsPerInstance(t *testing.T) {
	first, err := NewMVA(1, 3)
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewMVA(1, 3)
	if err != nil {
		t.Fatal(err)
	}
	first.mu.Lock()
	locked := true
	defer func() {
		if locked {
			first.mu.Unlock()
		}
	}()
	done := make(chan error, 1)
	go func() {
		_, err := second.Commitment()
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("second MVA commitment failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("locking one MVA blocked a different MVA")
	}
	first.mu.Unlock()
	locked = false
}

func pendingMVALog(id byte, regionID string) PendingRecord {
	key, address, locator := testMVALog(id, regionID)
	return PendingRecord{LogID: key.ID, RegionID: regionID, SiteID: key.SiteID,
		DeviceID: key.DevID, Type: key.Type, TS: key.TS,
		Address: address, Locator: locator}
}

func TestMVACandidateLifecycleAndFinalizedResolve(t *testing.T) {
	tree, err := NewMVA(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	sealed := pendingMVALog(1, "0")
	working := []PendingRecord{pendingMVALog(2, "0"), pendingMVALog(3, "1")}
	for _, record := range append([]PendingRecord{sealed}, working...) {
		if _, _, err := tree.IngestRecord(record); err != nil {
			t.Fatal(err)
		}
	}
	if epoch, order, err := tree.WorkingMetadata(); err != nil || epoch != 1 || order != 3 {
		t.Fatalf("initial working metadata = %d/%d, %v", epoch, order, err)
	}
	root, err := tree.PrepareCandidate(1, []PendingRecord{sealed})
	if err != nil {
		t.Fatal(err)
	}
	if tree.Finalized != nil {
		t.Fatal("candidate became authoritative before promotion")
	}
	if epoch, _, err := tree.WorkingMetadata(); err != nil || epoch != 2 {
		t.Fatalf("working generation after preparation = %d, %v", epoch, err)
	}
	snapshot, err := tree.CandidateSnapshot(1)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Root != root || snapshot.Regions["0"].IDView.LeafCount != 1 ||
		snapshot.Regions["1"].IDView.LeafCount != 0 || tree.Regions[0].IDView.LeafCount != 2 {
		t.Fatal("candidate contains active records or changed working state")
	}
	regions := []merkle.TreeID{{Type: merkle.TreeRegion, RegionID: "0"}, {Type: merkle.TreeRegion, RegionID: "1"}}
	if _, _, err := tree.Resolve(idKey{ID: sealed.LogID}, regions); err == nil {
		t.Fatal("candidate was queryable before promotion")
	}
	if retry, err := tree.PrepareCandidate(1, working); err != nil || retry != root {
		t.Fatalf("same-epoch retry changed candidate: %x, %v", retry, err)
	}
	if err := tree.CommitCandidate(1); err != nil {
		t.Fatal(err)
	}
	first := tree.Finalized
	if first.Root != root || first.Epoch != 1 || tree.Regions[0].Finalized != first.Regions["0"] {
		t.Fatal("promoted Region and Global snapshots disagree")
	}
	values, proof, err := tree.Resolve(idKey{ID: sealed.LogID}, regions)
	if err != nil || len(values) != 1 || values[0].PhysicalAddress != sealed.Address ||
		values[0].LeafHash != sealed.Locator || proof.Epoch != 1 {
		t.Fatalf("sealed record did not resolve from epoch 1: values=%d, err=%v", len(values), err)
	}
	for _, record := range working {
		values, _, err := tree.Resolve(idKey{ID: record.LogID}, regions)
		if err != nil || len(values) != 0 {
			t.Fatalf("active record resolved in epoch 1: %v", err)
		}
	}
	secondRoot, err := tree.PrepareCandidate(2, working)
	if err != nil {
		t.Fatal(err)
	}
	if secondRoot == root || tree.Finalized != first || first.Regions["0"].IDView.LeafCount != 1 {
		t.Fatal("preparing epoch 2 changed epoch 1")
	}
	if err := tree.CommitCandidate(2); err != nil {
		t.Fatal(err)
	}
	if tree.Finalized.Regions["0"].IDView.LeafCount != 2 || tree.Finalized.Regions["1"].IDView.LeafCount != 1 {
		t.Fatal("epoch 2 did not include earlier sealed and newly sealed records")
	}
	for _, record := range working {
		values, proof, err := tree.Resolve(idKey{ID: record.LogID}, regions)
		if err != nil || len(values) != 1 || proof.Epoch != 2 {
			t.Fatalf("epoch 2 resolve: %v", err)
		}
	}
}

func TestMVACandidateRejectsInvalidTransitions(t *testing.T) {
	var absent *MVA
	if _, err := absent.PrepareCandidate(1, nil); err == nil {
		t.Fatal("nil MVA prepared")
	}
	tree, err := NewMVA(1, 3)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tree.CandidateSnapshot(1); err == nil {
		t.Fatal("snapshot existed before prepare")
	}
	if err := tree.ValidateCandidate(1); err == nil {
		t.Fatal("unprepared candidate validated")
	}
	if err := tree.CommitCandidate(1); err == nil {
		t.Fatal("unprepared candidate promoted")
	}
	if _, err := tree.PrepareCandidate(0, nil); err == nil {
		t.Fatal("nonadvancing epoch accepted")
	}
	wrong := pendingMVALog(1, "0")
	wrong.Address.RegionID = "other"
	if _, _, err := tree.IngestRecord(wrong); err == nil {
		t.Fatal("mismatched physical Region ingested")
	}
	if _, err := tree.PrepareCandidate(1, []PendingRecord{wrong}); err == nil || tree.Candidate != nil {
		t.Fatal("invalid sealed record published a candidate")
	}
	valid := pendingMVALog(1, "0")
	if _, err := tree.PrepareCandidate(1, []PendingRecord{valid}); err != nil {
		t.Fatal(err)
	}
	if _, err := tree.PrepareCandidate(2, nil); err == nil {
		t.Fatal("conflicting epoch prepared")
	}
	if _, err := tree.CandidateSnapshot(2); err == nil {
		t.Fatal("wrong epoch snapshot returned")
	}
	if err := tree.ValidateCandidate(2); err == nil {
		t.Fatal("wrong epoch validated")
	}
	if err := tree.CommitCandidate(2); err == nil || tree.Finalized != nil {
		t.Fatal("wrong epoch promoted")
	}
	if err := tree.CommitCandidate(1); err != nil {
		t.Fatal(err)
	}
	if err := tree.CommitCandidate(1); err == nil {
		t.Fatal("candidate promoted twice")
	}
}

func TestMVACandidateEmptyEpochKeepsPriorFinalizedView(t *testing.T) {
	tree, err := NewMVA(1, 3)
	if err != nil {
		t.Fatal(err)
	}
	sealed := pendingMVALog(1, "0")
	active := pendingMVALog(2, "0")
	if _, _, err := tree.IngestRecord(sealed); err != nil {
		t.Fatal(err)
	}
	root, err := tree.PrepareCandidate(1, []PendingRecord{sealed})
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.CommitCandidate(1); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tree.IngestRecord(active); err != nil {
		t.Fatal(err)
	}
	emptyRoot, err := tree.PrepareCandidate(2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if emptyRoot != root || tree.Candidate.Regions["0"].IDView.LeafCount != 1 || tree.Regions[0].IDView.LeafCount != 2 {
		t.Fatal("active record entered empty pending epoch")
	}
	if err := tree.CommitCandidate(2); err != nil {
		t.Fatal(err)
	}
	values, proof, err := tree.Resolve(idKey{ID: active.LogID}, []merkle.TreeID{{Type: merkle.TreeRegion, RegionID: "0"}})
	if err != nil || len(values) != 0 || proof.Epoch != 2 {
		t.Fatalf("active record visible after empty epoch: %v", err)
	}
}
