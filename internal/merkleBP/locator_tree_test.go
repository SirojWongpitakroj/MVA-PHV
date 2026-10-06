package merkleBP

import (
	"fmt"
	"slices"
	"testing"
	"time"
	"uuid"
)

func testID(n byte) uuid.UUID {
	var id uuid.UUID
	id[15] = n
	return id
}

func TestLocatorTreeInsert(t *testing.T) {
	for _, order := range []int{3, 4} {
		for _, keyType := range []string{"id", "attribute"} {
			t.Run(fmt.Sprintf("order=%d/%s", order, keyType), func(t *testing.T) {
				tree := NewLocatorTree(order, keyType)
				if tree.RootPageID != 0 || tree.NextPageID != 1 || tree.Height != 0 || !tree.RootPage.IsLeaf {
					t.Fatalf("unexpected initial tree: %+v", tree)
				}

				var expected []LocatorKey
				// A fixed permutation exercises insertions before, between, and after
				// existing keys, including splits at multiple levels.
				for i := range 40 {
					n := byte((i*17)%40 + 1)
					var key LocatorKey = idKey{ID: testID(n)}
					if keyType == "attribute" {
						key = attrKey{
							SiteID: fmt.Sprintf("site-%d", n%3),
							DevID:  fmt.Sprintf("device-%d", n%4),
							Type:   fmt.Sprintf("type-%d", n%2),
							TS:     time.Unix(int64(n%5), 0),
							ID:     testID(n),
						}
					}
					value := &LocatorValue{LocatorKey: key, PhysicalAddress: PhysicalAddress{LeafID: fmt.Sprint(n)}}
					before := snapshotPages(tree.RootPage)
					update := tree.InsertWithUpdate(key, value, tree.RootPage)
					expected = append(expected, key)
					slices.SortFunc(expected, func(a, b LocatorKey) int { return a.Compare(b) })

					checkTree(t, tree, expected, order)
					checkUpdate(t, tree, update, before)
				}
			})
		}
	}
}

func TestLocatorTreeInsertReturnsChangedPages(t *testing.T) {
	tree := NewLocatorTree(3, "id")
	key := idKey{ID: testID(1)}
	pages := tree.Insert(key, &LocatorValue{LocatorKey: key}, tree.RootPage)
	if len(pages) != 1 || pages[0].PageID != tree.RootPageID || pages[0].Hash != tree.RootHash {
		t.Fatalf("Insert returned pages = %+v, want the updated root", pages)
	}
}

type pageSnapshot struct {
	hash     [32]byte
	parentID *int64
	nextID   *int64
	keys     []LocatorKey
}

func snapshotPages(root *Page) map[int64]pageSnapshot {
	result := make(map[int64]pageSnapshot)
	var visit func(*Page)
	visit = func(page *Page) {
		result[page.PageID] = pageSnapshot{
			hash: page.Hash, parentID: page.ParentPageID,
			nextID: pageIDPointer(page.Next), keys: slices.Clone(page.Keys),
		}
		for _, child := range page.Children {
			visit(child)
		}
	}
	visit(root)
	return result
}

func checkTree(t *testing.T, tree *LocatorTree, expected []LocatorKey, order int) {
	t.Helper()
	if tree.RootPage == nil || tree.RootPage.PageID != tree.RootPageID || tree.RootPage.Parent != nil || tree.RootPage.ParentPageID != nil {
		t.Fatal("invalid root page or root parent")
	}
	if tree.LeafCount != int64(len(expected)) {
		t.Fatalf("record count = %d, want %d", tree.LeafCount, len(expected))
	}
	if tree.RootHash != tree.RootPage.Hash {
		t.Fatal("root hash differs from root page hash")
	}

	seen := make(map[int64]bool)
	var leaves []*Page
	var visit func(*Page, *Page, int)
	visit = func(page, parent *Page, depth int) {
		t.Helper()
		if page == nil || seen[page.PageID] {
			t.Fatalf("nil or repeated page at depth %d", depth)
		}
		seen[page.PageID] = true
		if page.Parent != parent || (parent == nil && page.ParentPageID != nil) ||
			(parent != nil && (page.ParentPageID == nil || *page.ParentPageID != parent.PageID)) {
			t.Fatalf("page %d has incorrect parent", page.PageID)
		}
		for i := 1; i < len(page.Keys); i++ {
			if page.Keys[i-1].Compare(page.Keys[i]) >= 0 {
				t.Fatalf("page %d has unsorted keys", page.PageID)
			}
		}
		var hash [32]byte
		var err error
		if page.IsLeaf {
			if depth != tree.Height || len(page.Keys) != len(page.Values) || len(page.Keys) >= order || len(page.Children) != 0 {
				t.Fatalf("invalid leaf page %d at depth %d", page.PageID, depth)
			}
			for i, key := range page.Keys {
				if page.Values[i] == nil || key.Compare(page.Values[i].LocatorKey) != 0 {
					t.Fatalf("key/value mismatch on page %d", page.PageID)
				}
			}
			hash, err = page.leafHash()
			leaves = append(leaves, page)
		} else {
			if len(page.Children) != len(page.Keys)+1 || len(page.Children) > order {
				t.Fatalf("invalid internal page %d: %d keys, %d children", page.PageID, len(page.Keys), len(page.Children))
			}
			for _, child := range page.Children {
				visit(child, page, depth+1)
			}
			for i, separator := range page.Keys {
				if page.Children[i+1].Keys[0].Compare(separator) < 0 {
					t.Fatalf("separator %d misroutes right child on page %d", i, page.PageID)
				}
			}
			hash, err = page.internalHash()
		}
		if err != nil || hash != page.Hash {
			t.Fatalf("page %d has invalid hash: %v", page.PageID, err)
		}
	}
	visit(tree.RootPage, nil, 0)
	if int64(len(seen)) != tree.NextPageID {
		t.Fatalf("reachable pages = %d, next page ID = %d", len(seen), tree.NextPageID)
	}
	var actual []LocatorKey
	for i, leaf := range leaves {
		if i+1 < len(leaves) && leaf.Next != leaves[i+1] || i+1 == len(leaves) && leaf.Next != nil {
			t.Fatalf("incorrect next pointer on leaf %d", leaf.PageID)
		}
		actual = append(actual, leaf.Keys...)
	}
	if len(actual) != len(expected) {
		t.Fatalf("found %d keys, want %d", len(actual), len(expected))
	}
	for i := range expected {
		if actual[i].Compare(expected[i]) != 0 {
			t.Fatalf("key %d out of order: got %v, want %v", i, actual[i], expected[i])
		}
	}
}

func checkUpdate(t *testing.T, tree *LocatorTree, update LocatorUpdate, before map[int64]pageSnapshot) {
	t.Helper()
	if update.RootPageID != tree.RootPageID || update.RootHash != tree.RootHash ||
		update.NextPageID != tree.NextPageID || update.Height != tree.Height || update.RecordCount != tree.LeafCount {
		t.Fatal("update metadata differs from tree state")
	}
	updated := make(map[int64]Page)
	for i, page := range update.Pages {
		if i > 0 && update.Pages[i-1].PageID >= page.PageID {
			t.Fatal("updated pages are not in page ID order")
		}
		if _, exists := updated[page.PageID]; exists {
			t.Fatalf("page %d returned twice", page.PageID)
		}
		updated[page.PageID] = page
	}
	var visit func(*Page)
	visit = func(page *Page) {
		old, existed := before[page.PageID]
		changed := !existed || old.hash != page.Hash || !slices.EqualFunc(old.keys, page.Keys, func(a, b LocatorKey) bool { return a.Compare(b) == 0 }) ||
			!sameID(old.parentID, page.ParentPageID) || !sameID(old.nextID, pageIDPointer(page.Next))
		if changed {
			if saved, ok := updated[page.PageID]; !ok || saved.Hash != page.Hash {
				t.Errorf("changed page %d missing or stale in update", page.PageID)
			}
		}
		for _, child := range page.Children {
			visit(child)
		}
	}
	visit(tree.RootPage)
}

func sameID(a, b *int64) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}
