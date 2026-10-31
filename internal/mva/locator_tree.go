package mva

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// Merkle B+ tree

type pageUpdates map[int64]*Page

func newPageUpdates() pageUpdates {
	return make(pageUpdates)
}

func (updates pageUpdates) add(page *Page) {
	updates[page.PageID] = page
}

// REMINDER: come back and read
func (updates pageUpdates) pages() []Page {
	pageIDs := make([]int64, 0, len(updates))
	for pageID := range updates {
		pageIDs = append(pageIDs, pageID)
	}
	sort.Slice(pageIDs, func(left, right int) bool {
		return pageIDs[left] < pageIDs[right]
	})

	pages := make([]Page, 0, len(pageIDs))
	for _, pageID := range pageIDs {
		pages = append(pages, snapshotUpdatedPage(updates[pageID]))
	}
	return pages
}

// snapshotUpdatedPage detaches one changed page from the mutable working tree.
// The repository may serialize this update after another goroutine inserts a
// later record, so its keys, values, links, and child hashes must stay fixed.
func snapshotUpdatedPage(page *Page) Page {
	copyPage := *page
	copyPage.Keys = slices.Clone(page.Keys)
	copyPage.Values = make([]*LocatorValue, len(page.Values))
	for i, value := range page.Values {
		copyPage.Values[i] = cloneLocatorValue(value)
	}
	copyPage.Children = make([]*Page, len(page.Children))
	for i, child := range page.Children {
		if child != nil {
			copyPage.Children[i] = &Page{PageID: child.PageID, Hash: child.Hash}
		}
	}
	if page.Parent != nil {
		copyPage.Parent = &Page{PageID: page.Parent.PageID}
	}
	if page.ParentPageID != nil {
		parentID := *page.ParentPageID
		copyPage.ParentPageID = &parentID
	}
	if page.Prev != nil {
		copyPage.Prev = &Page{PageID: page.Prev.PageID}
	}
	if page.Next != nil {
		copyPage.Next = &Page{PageID: page.Next.PageID}
	}
	return copyPage
}

// Helper fucntion: point to the embed the page to the pageID
func pageIDPointer(page *Page) *int64 {
	if page == nil {
		return nil
	}
	pageID := page.PageID
	return &pageID
}

func NewLocatorTree(order int, viewType string) *LocatorTree {
	tree := LocatorTree{
		RootPageID: 0,
		RootPage: &Page{
			PageID: 0,
			IsLeaf: true,
			Keys:   make([]LocatorKey, 0, order-1),
			Values: make([]*LocatorValue, 0, order),
		},
		NextPageID: 1,
		Order:      order,
		Height:     0,
		LeafCount:  0,
		ViewType:   viewType,
	}
	return &tree
}

func (tree *LocatorTree) setRoot(currPage *Page, updates pageUpdates) {
	currPage.Parent = nil
	currPage.ParentPageID = nil
	tree.RootPageID = currPage.PageID
	tree.RootHash = currPage.Hash
	tree.RootPage = currPage
	updates.add(currPage)
}

func (tree *LocatorTree) insertParent(currPage, rightPage *Page,
	currKey LocatorKey, updates pageUpdates) error {

	parent := currPage.Parent

	//no parent
	if parent == nil {
		parent = &Page{
			PageID:   tree.NextPageID,
			RegionID: currPage.RegionID,
			IsLeaf:   false,
			Keys:     make([]LocatorKey, 0, tree.Order-1),
			Children: make([]*Page, 0, tree.Order),
		}
		tree.NextPageID++

		parent.Keys = append(parent.Keys, currKey)

		parent.Children = append(parent.Children, currPage)
		parent.Children = append(parent.Children, rightPage)
		currPage.Parent = parent
		currPage.ParentPageID = pageIDPointer(parent)
		rightPage.Parent = parent
		rightPage.ParentPageID = pageIDPointer(parent)

		var err error
		parent.Hash, err = parent.internalHash()
		if err != nil {
			return err
		}
		tree.Height++
		updates.add(currPage)
		updates.add(rightPage)
		tree.setRoot(parent, updates)
	} else { //there exist a parent
		currIdx := slices.Index(parent.Children, currPage)
		if currIdx == -1 {
			return fmt.Errorf("insert parent: current page is not a child of its parent")
		}

		parent.Keys = slices.Insert(parent.Keys, currIdx, currKey)
		parent.Children = slices.Insert(parent.Children, currIdx+1, rightPage)
		rightPage.Parent = parent
		rightPage.ParentPageID = pageIDPointer(parent)
		updates.add(parent)
		updates.add(rightPage)
	}
	tree.internalSplit(parent, updates)
	return nil
}

func (tree *LocatorTree) internalSplit(currPage *Page, updates pageUpdates) error {
	if len(currPage.Children) <= tree.Order {
		return nil
	}

	mid := len(currPage.Keys) / 2
	currKey := currPage.Keys[mid]

	// right side
	rightKeys := append([]LocatorKey(nil), currPage.Keys[mid+1:]...)
	rightChildren := append([]*Page(nil), currPage.Children[mid+1:]...)

	rightPage := &Page{
		PageID:       tree.NextPageID,
		RegionID:     currPage.RegionID,
		IsLeaf:       false,
		Parent:       currPage.Parent,
		ParentPageID: pageIDPointer(currPage.Parent),
		Keys:         rightKeys,
		Children:     rightChildren,
	}
	tree.NextPageID++
	for _, child := range rightPage.Children {
		child.Parent = rightPage
		child.ParentPageID = pageIDPointer(rightPage)
		updates.add(child)
	}
	var err error
	rightPage.Hash, err = rightPage.internalHash()
	if err != nil {
		return err
	}

	// left side
	currPage.Keys = currPage.Keys[:mid:mid]
	currPage.Children = currPage.Children[: mid+1 : mid+1]
	currPage.Hash, err = currPage.internalHash()
	if err != nil {
		return err
	}
	updates.add(currPage)
	updates.add(rightPage)

	tree.insertParent(currPage, rightPage, currKey, updates)
	return nil
}

func (tree *LocatorTree) leafSplit(currPage *Page, updates pageUpdates) error {
	mid := len(currPage.Keys) / 2
	// right side
	rightKeys := append([]LocatorKey(nil), currPage.Keys[mid:]...)
	rightValues := append([]*LocatorValue(nil), currPage.Values[mid:]...)

	rightPage := &Page{
		PageID:       tree.NextPageID,
		RegionID:     currPage.RegionID,
		IsLeaf:       true,
		Parent:       currPage.Parent,
		ParentPageID: pageIDPointer(currPage.Parent),
		Keys:         rightKeys,
		Values:       rightValues,
		Prev:         currPage,
		Next:         currPage.Next,
	}
	tree.NextPageID++

	var err error
	currPage.Hash, err = currPage.leafHash()
	if err != nil {
		return err
	}
	rightPage.Hash, err = rightPage.leafHash()
	if err != nil {
		return err
	}

	// left side
	currPage.Keys = currPage.Keys[:mid:mid]
	currPage.Values = currPage.Values[:mid:mid]
	if rightPage.Next != nil {
		rightPage.Next.Prev = rightPage
		updates.add(rightPage.Next)
	}
	currPage.Next = rightPage
	updates.add(currPage)
	updates.add(rightPage)

	tree.insertParent(currPage, rightPage, rightPage.Keys[0], updates)
	return nil
}

func (tree *LocatorTree) updatePathHashes(currPage *Page, updates pageUpdates) error {
	var err error
	for currPage != nil {
		if currPage.IsLeaf {
			currPage.Hash, err = currPage.leafHash()
			if err != nil {
				return err
			}
		} else {
			currPage.Hash, err = currPage.internalHash()
			if err != nil {
				return err
			}
		}

		updates.add(currPage)

		if currPage.Parent == nil {
			break
		}
		currPage = currPage.Parent
	}
	tree.setRoot(currPage, updates)
	return nil
}

func (tree *LocatorTree) Insert(key LocatorKey, value *LocatorValue, currPage *Page) []Page {
	return tree.InsertWithUpdate(key, value, currPage).Pages
}

// InsertWithUpdate adds a locator record and returns every changed page and
// the final authenticated tree state needed for persistence.
func (tree *LocatorTree) InsertWithUpdate(key LocatorKey, value *LocatorValue, currPage *Page) LocatorUpdate {
	updates := newPageUpdates()
	tree.insert(key, value, currPage, updates)

	return LocatorUpdate{
		Pages:       updates.pages(),
		RootPageID:  tree.RootPageID,
		RootHash:    tree.RootHash,
		NextPageID:  tree.NextPageID,
		Height:      tree.Height,
		RecordCount: tree.LeafCount,
	}
}

func (tree *LocatorTree) insert(key LocatorKey, value *LocatorValue, currPage *Page, updates pageUpdates) {
	//base case
	if currPage.IsLeaf {
		currIdx := currPage.findKeyIdx(key)
		currPage.Keys = slices.Insert(currPage.Keys, currIdx, key)
		currPage.Values = slices.Insert(currPage.Values, currIdx, value)
		if len(currPage.Keys) >= tree.Order {
			tree.leafSplit(currPage, updates)
		}
		tree.LeafCount++
		tree.updatePathHashes(currPage, updates)
		return
	}

	idx := currPage.findKeyIdx(key)
	tree.insert(key, value, currPage.Children[idx], updates)
}

type locatorDescentStep struct {
	page       *Page
	childIndex int
	proof      PageProof
}

// internalPathStep snapshots a page while selecting the child to descend into.
func internalPathStep(page *Page, index int) (locatorDescentStep, error) {
	if page == nil || page.IsLeaf || len(page.Children) != len(page.Keys)+1 ||
		index < 0 || index >= len(page.Children) || page.Children[index] == nil {
		return locatorDescentStep{}, fmt.Errorf("locator path proof: invalid child on internal page")
	}
	childHashes := make([][32]byte, len(page.Children))
	for i, child := range page.Children {
		if child == nil {
			return locatorDescentStep{}, fmt.Errorf("locator path proof: nil child on page %d", page.PageID)
		}
		childHashes[i] = child.Hash
	}
	return locatorDescentStep{
		page: page, childIndex: index,
		proof: PageProof{
			PageID: page.PageID, Keys: slices.Clone(page.Keys),
			ChildHashes: childHashes, PathChildIndicdex: []int{index},
		},
	}, nil
}

func leafPathProof(page *Page) (PageProof, error) {
	if page == nil || !page.IsLeaf || len(page.Keys) != len(page.Values) {
		return PageProof{}, fmt.Errorf("locator path proof: invalid leaf")
	}
	values := make([]*LocatorValue, len(page.Values))
	for i, value := range page.Values {
		if value == nil {
			return PageProof{}, fmt.Errorf("locator path proof: nil value on page %d", page.PageID)
		}
		copyValue := *value
		values[i] = &copyValue
	}
	return PageProof{
		PageID: page.PageID, IsLeaf: true,
		Keys: slices.Clone(page.Keys), Values: values,
	}, nil
}

func proofToLeaf(page *Page) ([]PageProof, error) {
	leaf, err := leafPathProof(page)
	if err != nil {
		return nil, err
	}
	path := []PageProof{leaf}
	for child := page; child.Parent != nil; child = child.Parent {
		index := slices.Index(child.Parent.Children, child)
		step, err := internalPathStep(child.Parent, index)
		if err != nil {
			return nil, err
		}
		path = append(path, step.proof)
	}
	return path, nil
}

// nextLeafDescent advances the saved descent to the next leaf without using
// Parent pointers. The leaf link is checked by the caller.
func nextLeafDescent(path []locatorDescentStep) ([]locatorDescentStep, *Page, error) {
	for depth := len(path) - 1; depth >= 0; depth-- {
		step := path[depth]
		index := step.childIndex + 1
		if index >= len(step.page.Children) {
			continue
		}
		nextStep, err := internalPathStep(step.page, index)
		if err != nil {
			return nil, nil, err
		}
		nextPath := append(slices.Clone(path[:depth]), nextStep)
		page := step.page.Children[index]
		for !page.IsLeaf {
			childStep, err := internalPathStep(page, 0)
			if err != nil {
				return nil, nil, err
			}
			nextPath = append(nextPath, childStep)
			page = page.Children[0]
		}
		return nextPath, page, nil
	}
	return nil, nil, nil
}

// resolve returns matching values and a leaf-to-root path for each one.
// The proof also carries the immediate values outside the matched range.
func (tree *LocatorTree) resolve(query LocatorQuery) ([]*LocatorValue, MVARegionProof, error) {
	proof := MVARegionProof{Query: query}
	if tree == nil || tree.RootPage == nil {
		return nil, proof, fmt.Errorf("resolve locator: tree or root page is nil")
	}
	if query == nil {
		return nil, proof, fmt.Errorf("resolve locator: query is nil")
	}
	if rangeQuery, ok := query.(AttrRangeQuery); ok && rangeQuery.EndTS.Before(rangeQuery.StartTS) {
		return nil, proof, fmt.Errorf("resolve locator: end timestamp precedes start timestamp")
	}
	if rangeQuery, ok := query.(TimeRangeQuery); ok && rangeQuery.EndTS.Before(rangeQuery.StartTS) {
		return nil, proof, fmt.Errorf("resolve locator: end timestamp precedes start timestamp")
	}
	if query.isLogViewKey() {
		proof.View = ViewID
	} else {
		proof.View = ViewAttribute
	}
	if tree.ViewType != string(proof.View) {
		return nil, proof, fmt.Errorf("resolve locator: key does not match %q view", tree.ViewType)
	}
	compare := query.Compare
	if key, ok := query.(attrKey); ok && key.ID == (idKey{}).ID {
		// Without an ID, an attribute query covers every key with this
		// SiteID, DevID, and Type, even though each stored ID is unique.
		compare = func(other LocatorKey) int {
			candidate := other.(attrKey)
			if order := strings.Compare(key.SiteID, candidate.SiteID); order != 0 {
				return order
			}
			if order := strings.Compare(key.DevID, candidate.DevID); order != 0 {
				return order
			}
			return strings.Compare(key.Type, candidate.Type)
		}
	}

	page := tree.RootPage
	var descent []locatorDescentStep
	for !page.IsLeaf {
		// Save each chosen child and its sibling hashes on the way down.
		idx := sort.Search(len(page.Keys), func(i int) bool {
			return compare(page.Keys[i]) <= 0
		})
		step, err := internalPathStep(page, idx)
		if err != nil {
			return nil, proof, err
		}
		descent = append(descent, step)
		page = page.Children[idx]
	}

	if len(page.Keys) != len(page.Values) {
		return nil, proof, fmt.Errorf("resolve locator: invalid leaf page %d", page.PageID)
	}

	idx := sort.Search(len(page.Keys), func(i int) bool {
		return compare(page.Keys[i]) <= 0
	})
	var matchedValues []*LocatorValue
	var firstPage, lastPage *Page
	firstIndex, lastIndex := 0, 0
	// Advance the index through each matching leaf, then follow Next.
scan:
	for page != nil {
		if len(page.Keys) != len(page.Values) {
			return nil, proof, fmt.Errorf("resolve locator: invalid leaf page %d", page.PageID)
		}
		leafForScan, err := leafPathProof(page)
		if err != nil {
			return nil, proof, err
		}
		scanPath := []PageProof{leafForScan}
		for i := len(descent) - 1; i >= 0; i-- {
			scanPath = append(scanPath, descent[i].proof)
		}
		proof.ScanPaths = append(proof.ScanPaths, scanPath)
		var leafProof PageProof
		leafProofReady := false
		for idx < len(page.Keys) {
			order := compare(page.Keys[idx])
			if order < 0 {
				break scan
			}
			if Matches(query, page.Keys[idx]) {
				if firstPage == nil {
					firstPage, firstIndex = page, idx
				}
				lastPage, lastIndex = page, idx
				matchedValues = append(matchedValues, page.Values[idx])
				if !leafProofReady {
					var err error
					leafProof, err = leafPathProof(page)
					if err != nil {
						return nil, proof, err
					}
					leafProofReady = true
				}
				// Each matched value gets its leaf-to-root proof.
				proof.Path = append(proof.Path, leafProof)
				for i := len(descent) - 1; i >= 0; i-- {
					proof.Path = append(proof.Path, descent[i].proof)
				}
			}
			idx++
		}
		next := page.Next
		if next != nil {
			nextDescent, nextLeaf, err := nextLeafDescent(descent)
			if err != nil {
				return nil, proof, err
			}
			if nextLeaf != next {
				return nil, proof, fmt.Errorf("resolve locator: leaf links disagree with tree order")
			}
			descent = nextDescent
		}
		page = next
		idx = 0
	}

	if firstPage != nil && !isTimeOnly(query) {
		var leftPage, rightPage *Page
		if firstIndex > 0 {
			proof.LeftBoundary = firstPage.Values[firstIndex-1]
			leftPage = firstPage
		} else if firstPage.Prev != nil && len(firstPage.Prev.Values) > 0 {
			proof.LeftBoundary = firstPage.Prev.Values[len(firstPage.Prev.Values)-1]
			leftPage = firstPage.Prev
		}
		if lastIndex+1 < len(lastPage.Values) {
			proof.RightBoundary = lastPage.Values[lastIndex+1]
			rightPage = lastPage
		} else if lastPage.Next != nil && len(lastPage.Next.Values) > 0 {
			proof.RightBoundary = lastPage.Next.Values[0]
			rightPage = lastPage.Next
		}
		var err error
		if leftPage != nil {
			proof.LeftBoundaryPath, err = proofToLeaf(leftPage)
			if err != nil {
				return nil, proof, err
			}
		}
		if rightPage != nil {
			proof.RightBoundaryPath, err = proofToLeaf(rightPage)
			if err != nil {
				return nil, proof, err
			}
		}
	}
	return matchedValues, proof, nil
}
