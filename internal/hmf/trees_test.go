package hmf

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"uuid"
)

func testHash(label string, parts ...[]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(label))
	for _, part := range parts {
		h.Write(part)
	}
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func testLogID(i int) uuid.UUID {
	var id uuid.UUID
	id[15] = byte(i + 1)
	return id
}

func testPayloadHash(i int) [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("ciphertext-%d", i)))
}

func testLogLeaf(id uuid.UUID, h [32]byte) [32]byte {
	inner := sha256.Sum256(h[:])
	return testHash("LOG", id[:], h[:], inner[:])
}

// A standalone reference tree: an unpaired child keeps its hash at the next level.
func testRoot(tag string, leaves [][32]byte) ([32]byte, int) {
	level := append([][32]byte(nil), leaves...)
	height := 0
	for len(level) > 1 {
		parents := make([][32]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				parents = append(parents, level[i])
			} else {
				parents = append(parents, testHash(tag, level[i][:], level[i+1][:]))
			}
		}
		level = parents
		height++
	}
	return level[0], height
}

func testInputHashes(n int) [][32]byte {
	hashes := make([][32]byte, n)
	for i := range hashes {
		hashes[i] = testPayloadHash(i)
	}
	return hashes
}

func TestSegmentTreeRootsAndLifecycle(t *testing.T) {
	for _, count := range []int{1, 2, 3, 5, 6, 9} {
		t.Run(fmt.Sprintf("leaves_%d", count), func(t *testing.T) {
			tree := NewSegmentTree("region", 2, 3, count)
			leaves := make([][32]byte, 0, count)
			for i := 0; i < count; i++ {
				id, h := testLogID(i), testPayloadHash(i)
				if err := tree.Append(id, h); err != nil {
					t.Fatal(err)
				}
				leaves = append(leaves, testLogLeaf(id, h))
			}
			if err := tree.Append(testLogID(count), testPayloadHash(count)); err == nil {
				t.Fatal("append past capacity succeeded")
			}
			updates, err := tree.Seal()
			if err != nil {
				t.Fatal(err)
			}
			wantRoot, wantHeight := testRoot("SEGINT", leaves)
			if tree.Root != wantRoot || tree.Height != wantHeight || tree.LeafCount != int64(count) {
				t.Fatalf("root/height/count = %x/%d/%d, want %x/%d/%d", tree.Root, tree.Height, tree.LeafCount, wantRoot, wantHeight, count)
			}
			for i, leaf := range leaves {
				if updates[i] != (MerkleNode{Level: 0, Index: int64(i), Hash: leaf}) {
					t.Fatalf("leaf %d = %+v, want hash %x", i, updates[i], leaf)
				}
			}
			if updates[len(updates)-1].Hash != wantRoot {
				t.Fatal("sealed updates omit the root")
			}
			if _, err := tree.Seal(); err == nil {
				t.Fatal("second seal succeeded")
			}
			if err := tree.Append(testLogID(count), testPayloadHash(count)); err == nil {
				t.Fatal("append after seal succeeded")
			}
		})
	}
	if _, err := NewSegmentTree("region", 2, 3, 1).Seal(); err == nil {
		t.Fatal("sealing an empty segment succeeded")
	}
}

func TestShardTreeAppendAndFrontiers(t *testing.T) {
	tree := NewShardTree("region", 2)
	leaves := testInputHashes(9)
	for i, leaf := range leaves {
		updates, err := tree.Append(leaf)
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		wantRoot, wantHeight := testRoot("SHARDINT", leaves[:i+1])
		if tree.Root != wantRoot || tree.Height != wantHeight || tree.LeafCount != int64(i+1) {
			t.Fatalf("after %d leaves, root/height/count = %x/%d/%d, want %x/%d/%d", i+1, tree.Root, tree.Height, tree.LeafCount, wantRoot, wantHeight, i+1)
		}
		if updates[0] != (MerkleNode{Level: 0, Index: int64(i), Hash: leaf}) {
			t.Fatalf("append %d omitted its leaf", i)
		}
		if updates[len(updates)-1].Hash != wantRoot {
			t.Fatalf("append %d omitted its root", i)
		}
	}
	frontiers := tree.Frontiers()
	if len(frontiers) == 0 {
		t.Fatal("nonempty tree has no frontier")
	}
	frontiers[0].Hash = [32]byte{}
	if tree.Frontiers()[0].Hash == ([32]byte{}) {
		t.Fatal("Frontiers exposed the tree's backing slice")
	}
}

func TestRegionTreeBuildAndUpdate(t *testing.T) {
	for _, count := range []int{1, 2, 3, 5, 6, 9} {
		t.Run(fmt.Sprintf("shards_%d", count), func(t *testing.T) {
			tree := NewRegionTree("region", count)
			leaves := testInputHashes(count)
			if _, err := tree.Build(leaves[:count-1]); err == nil {
				t.Fatal("build accepted the wrong shard count")
			}
			updates, err := tree.Build(leaves)
			if err != nil {
				t.Fatal(err)
			}
			wantRoot, wantHeight := testRoot("REGINT", leaves)
			if tree.Root != wantRoot || tree.Height != wantHeight || tree.LeafCount != int64(count) {
				t.Fatalf("build root/height/count = %x/%d/%d, want %x/%d/%d", tree.Root, tree.Height, tree.LeafCount, wantRoot, wantHeight, count)
			}
			if updates[len(updates)-1].Hash != wantRoot {
				t.Fatal("build updates omit root")
			}
			for i := range leaves {
				leaves[i] = testPayloadHash(20 + i)
				updates, err = tree.updateShardRoot(i, leaves[i])
				if err != nil {
					t.Fatalf("update shard %d: %v", i, err)
				}
				wantRoot, _ = testRoot("REGINT", leaves)
				if tree.Root != wantRoot || updates[len(updates)-1].Hash != wantRoot {
					t.Fatalf("update shard %d root = %x, want %x", i, tree.Root, wantRoot)
				}
			}
			for _, bad := range []int{-1, count} {
				if _, err := tree.updateShardRoot(bad, [32]byte{}); err == nil {
					t.Fatalf("update accepted index %d", bad)
				}
			}
			if tree.Root != wantRoot {
				t.Fatal("invalid update changed root")
			}
		})
	}
}

func TestGlobalTreeBuildAndUpdate(t *testing.T) {
	for _, count := range []int{1, 2, 3, 5, 6, 9} {
		t.Run(fmt.Sprintf("regions_%d", count), func(t *testing.T) {
			tree := NewGlobalTree(count)
			leaves := testInputHashes(count)
			if _, err := tree.Build(leaves[:count-1]); err == nil {
				t.Fatal("build accepted the wrong region count")
			}
			updates, err := tree.Build(leaves)
			if err != nil {
				t.Fatal(err)
			}
			wantRoot, wantHeight := testRoot("GLOBALINT", leaves)
			if tree.Root != wantRoot || tree.Height != wantHeight || tree.LeafCount != int64(count) {
				t.Fatalf("build root/height/count = %x/%d/%d, want %x/%d/%d", tree.Root, tree.Height, tree.LeafCount, wantRoot, wantHeight, count)
			}
			if updates[len(updates)-1].Hash != wantRoot {
				t.Fatal("build updates omit root")
			}
			for i := range leaves {
				leaves[i] = testPayloadHash(20 + i)
				updates, err = tree.UpdateRegionRoot(i, leaves[i])
				if err != nil {
					t.Fatalf("update region %d: %v", i, err)
				}
				wantRoot, _ = testRoot("GLOBALINT", leaves)
				if tree.Root != wantRoot || updates[len(updates)-1].Hash != wantRoot {
					t.Fatalf("update region %d root = %x, want %x", i, tree.Root, wantRoot)
				}
			}
			for _, bad := range []int{-1, count} {
				if _, err := tree.UpdateRegionRoot(bad, [32]byte{}); err == nil {
					t.Fatalf("update accepted index %d", bad)
				}
			}
			if tree.Root != wantRoot {
				t.Fatal("invalid update changed root")
			}
		})
	}
}

func TestHierarchyPropagatesRoots(t *testing.T) {
	regionRoots := make([][32]byte, 2)
	regions := make([]*RegionTree, 2)
	shards := make([][]*ShardTree, 2)
	segmentRoots := make([][][32]byte, 2)

	for regionIndex := range regionRoots {
		shardRoots := make([][32]byte, 2)
		shards[regionIndex] = make([]*ShardTree, 2)
		for shardIndex := range shardRoots {
			shard := NewShardTree(fmt.Sprintf("region-%d", regionIndex), int64(shardIndex))
			shards[regionIndex][shardIndex] = shard
			for segmentIndex := 0; segmentIndex < 2; segmentIndex++ {
				segment := NewSegmentTree(fmt.Sprintf("region-%d", regionIndex), int64(shardIndex), int64(segmentIndex), 2)
				for logIndex := 0; logIndex < 2; logIndex++ {
					i := regionIndex*8 + shardIndex*4 + segmentIndex*2 + logIndex
					if err := segment.Append(testLogID(i), testPayloadHash(i)); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := segment.Seal(); err != nil {
					t.Fatal(err)
				}
				if _, err := shard.Append(segment.Root); err != nil {
					t.Fatal(err)
				}
				if regionIndex == 1 && shardIndex == 0 {
					segmentRoots[regionIndex] = append(segmentRoots[regionIndex], segment.Root)
				}
			}
			shardRoots[shardIndex] = shard.Root
		}
		region := NewRegionTree(fmt.Sprintf("region-%d", regionIndex), len(shardRoots))
		if _, err := region.Build(shardRoots); err != nil {
			t.Fatal(err)
		}
		regions[regionIndex] = region
		regionRoots[regionIndex] = region.Root
	}
	global := NewGlobalTree(len(regionRoots))
	if _, err := global.Build(regionRoots); err != nil {
		t.Fatal(err)
	}
	wantRoot, _ := testRoot("GLOBALINT", regionRoots)
	if global.Root != wantRoot {
		t.Fatalf("initial global root = %x, want %x", global.Root, wantRoot)
	}

	// A new segment changes one shard, its region, and then the global root.
	segment := NewSegmentTree("region-1", 0, 2, 1)
	if err := segment.Append(testLogID(20), testPayloadHash(20)); err != nil {
		t.Fatal(err)
	}
	if _, err := segment.Seal(); err != nil {
		t.Fatal(err)
	}
	segmentRoots[1] = append(segmentRoots[1], segment.Root)
	if _, err := shards[1][0].Append(segment.Root); err != nil {
		t.Fatal(err)
	}
	wantShard, _ := testRoot("SHARDINT", segmentRoots[1])
	if shards[1][0].Root != wantShard {
		t.Fatalf("updated shard root = %x, want %x", shards[1][0].Root, wantShard)
	}
	if _, err := regions[1].updateShardRoot(0, shards[1][0].Root); err != nil {
		t.Fatal(err)
	}
	wantRegion, _ := testRoot("REGINT", [][32]byte{wantShard, shards[1][1].Root})
	if regions[1].Root != wantRegion {
		t.Fatalf("updated region root = %x, want %x", regions[1].Root, wantRegion)
	}
	regionRoots[1] = regions[1].Root
	if _, err := global.UpdateRegionRoot(1, regionRoots[1]); err != nil {
		t.Fatal(err)
	}
	wantRoot, _ = testRoot("GLOBALINT", regionRoots)
	if global.Root != wantRoot {
		t.Fatalf("updated global root = %x, want %x", global.Root, wantRoot)
	}
}
