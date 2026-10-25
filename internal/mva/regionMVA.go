package mva

import (
	"crypto/sha256"
	"fmt"
	"slices"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

// NewRegionMVA creates the ID and attribute locator views for a region.
func NewRegionMVA(regionID string, order int) *RegionMVA {
	idView := NewLocatorTree(order, "id")
	attrView := NewLocatorTree(order, "attribute")
	idView.RootPage.RegionID = regionID
	attrView.RootPage.RegionID = regionID
	return &RegionMVA{
		Type: merkle.TreeRegion, RegionID: regionID,
		IDView:   idView,
		AttrView: attrView,
	}
}

// insertLog adds one log to both locator views and updates the region root.
func (region *RegionMVA) insertLog(logicalAddr attrKey, physicalAddr PhysicalAddress, leafHash [32]byte) (LocatorUpdate, LocatorUpdate, error) {
	if region == nil {
		return LocatorUpdate{}, LocatorUpdate{}, fmt.Errorf("insert MVA log: region is nil")
	}
	region.mu.Lock()
	defer region.mu.Unlock()
	if region.IDView == nil || region.AttrView == nil ||
		region.IDView.RootPage == nil || region.AttrView.RootPage == nil {
		return LocatorUpdate{}, LocatorUpdate{}, fmt.Errorf("insert MVA log: region views are nil")
	}
	if physicalAddr.RegionID != region.TreeID.RegionID {
		return LocatorUpdate{}, LocatorUpdate{}, fmt.Errorf("insert MVA log: address region %q does not match %q", physicalAddr.RegionID, region.TreeID.RegionID)
	}

	id := idKey{ID: logicalAddr.ID}
	idUpdate := region.IDView.InsertWithUpdate(id, &LocatorValue{
		LocatorKey:      id,
		PhysicalAddress: physicalAddr,
		LeafHash:        leafHash,
	}, region.IDView.RootPage)
	attrUpdate := region.AttrView.InsertWithUpdate(logicalAddr, &LocatorValue{
		LocatorKey:      logicalAddr,
		PhysicalAddress: physicalAddr,
		LeafHash:        leafHash,
	}, region.AttrView.RootPage)
	if err := region.setRoot(); err != nil {
		return idUpdate, attrUpdate, err
	}

	return idUpdate, attrUpdate, nil
}

func (region *RegionMVA) setRoot() error {
	if region == nil || region.IDView == nil || region.AttrView == nil {
		return fmt.Errorf("set MVA region root: region views are nil")
	}
	encoded, err := domain.Serialize([]byte("REGMVA"), region.TreeID.RegionID,
		region.IDView.RootHash[:], region.AttrView.RootHash[:])
	if err != nil {
		return fmt.Errorf("set MVA region root: %w", err)
	}
	region.Root = sha256.Sum256(encoded)
	return nil
}

// prepareSnapshot hashes the working views and copies them for finalization.
func (region *RegionMVA) prepareSnapshot(epoch uint64) (*RegionMVASnapshot, error) {
	if region == nil {
		return nil, fmt.Errorf("commit MVA region: region is nil")
	}
	region.mu.Lock()
	defer region.mu.Unlock()
	if region.IDView == nil || region.AttrView == nil ||
		region.IDView.RootPage == nil || region.AttrView.RootPage == nil {
		return nil, fmt.Errorf("commit MVA region: locator views are incomplete")
	}
	if err := region.setRoot(); err != nil {
		return nil, err
	}
	return &RegionMVASnapshot{
		TreeID: region.TreeID, Epoch: epoch,
		IDView: cloneLocatorTree(region.IDView), AttrView: cloneLocatorTree(region.AttrView),
		Root: region.Root,
	}, nil
}

// resolve searches the last finalized views, not the working views.
func (region *RegionMVA) resolve(query LocatorQuery) ([]*LocatorValue, *MVARegionProof, error) {
	if region == nil {
		return nil, nil, fmt.Errorf("resolve MVA: region is nil")
	}
	if query == nil {
		return nil, nil, fmt.Errorf("resolve MVA: query is nil")
	}
	region.mu.RLock()
	snapshot := region.Finalized
	region.mu.RUnlock()
	if snapshot == nil {
		return nil, nil, fmt.Errorf("resolve MVA: region %q has no finalized state", region.TreeID.RegionID)
	}
	return snapshot.resolve(query)
}

func (snapshot *RegionMVASnapshot) resolve(query LocatorQuery) ([]*LocatorValue, *MVARegionProof, error) {
	if snapshot == nil || query == nil {
		return nil, nil, fmt.Errorf("resolve MVA: finalized region or query is nil")
	}
	view := snapshot.AttrView
	if query.isLogViewKey() {
		view = snapshot.IDView
	}
	if view == nil {
		return nil, nil, fmt.Errorf("resolve MVA: selected locator view is nil")
	}
	values, proof, err := view.resolve(query)
	if err != nil {
		return nil, nil, fmt.Errorf("resolve MVA: %w", err)
	}
	result := make([]*LocatorValue, len(values))
	for i, value := range values {
		result[i] = cloneLocatorValue(value)
	}
	proof.LeftBoundary = cloneLocatorValue(proof.LeftBoundary)
	proof.RightBoundary = cloneLocatorValue(proof.RightBoundary)
	return result, &proof, nil
}

func cloneLocatorValue(value *LocatorValue) *LocatorValue {
	if value == nil {
		return nil
	}
	copyValue := *value
	return &copyValue
}

// cloneLocatorTree preserves the page graph while detaching it from Working.
func cloneLocatorTree(tree *LocatorTree) *LocatorTree {
	if tree == nil {
		return nil
	}
	copyTree := *tree
	pages := make(map[*Page]*Page)
	var clonePage func(*Page) *Page
	clonePage = func(page *Page) *Page {
		if page == nil {
			return nil
		}
		if cloned, ok := pages[page]; ok {
			return cloned
		}
		copyPage := *page
		pages[page] = &copyPage
		copyPage.Keys = slices.Clone(page.Keys)
		copyPage.Values = make([]*LocatorValue, len(page.Values))
		for i, value := range page.Values {
			copyPage.Values[i] = cloneLocatorValue(value)
		}
		copyPage.Children = make([]*Page, len(page.Children))
		for i, child := range page.Children {
			copyPage.Children[i] = clonePage(child)
		}
		copyPage.Parent = clonePage(page.Parent)
		copyPage.Prev = clonePage(page.Prev)
		copyPage.Next = clonePage(page.Next)
		if page.ParentPageID != nil {
			parentID := *page.ParentPageID
			copyPage.ParentPageID = &parentID
		}
		return &copyPage
	}
	copyTree.RootPage = clonePage(tree.RootPage)
	return &copyTree
}
