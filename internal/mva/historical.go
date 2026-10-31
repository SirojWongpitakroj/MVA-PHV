package mva

import (
	"context"
	"fmt"
	"slices"
	"sort"

	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

// HistoricalPage is one versioned, read-only B+ page. A repository supplies
// its content; MVA owns traversal and authenticates the resulting proof.
type HistoricalPage struct {
	PageID       int64
	VersionEpoch uint64
	Hash         [32]byte
	IsLeaf       bool
	Keys         []LocatorKey
	Values       []*LocatorValue
	ChildIDs     []int64
	ChildHashes  [][32]byte
}

type HistoricalView struct {
	RootPageID   int64
	RootHash     [32]byte
	VersionEpoch uint64
}
type HistoricalRegion struct {
	RegionID                     string
	Index                        int
	IDRoot, AttrRoot, RegionRoot [32]byte
}

type HistoricalReader interface {
	GlobalLevels(context.Context, uint64) ([][][32]byte, error)
	RegionManifest(context.Context, uint64) ([]HistoricalRegion, error)
	ViewState(context.Context, uint64, string, ViewType) (HistoricalView, error)
	Page(context.Context, uint64, string, ViewType, int64) (HistoricalPage, error)
}

type historyStep struct {
	page  HistoricalPage
	index int
}

func historyProof(leaf HistoricalPage, descent []historyStep) []PageProof {
	path := []PageProof{{PageID: leaf.PageID, IsLeaf: true, Keys: slices.Clone(leaf.Keys), Values: slices.Clone(leaf.Values)}}
	for i := len(descent) - 1; i >= 0; i-- {
		step := descent[i]
		path = append(path, PageProof{PageID: step.page.PageID, Keys: slices.Clone(step.page.Keys),
			ChildHashes: slices.Clone(step.page.ChildHashes), PathChildIndicdex: []int{step.index}})
	}
	return path
}

func readHistoryPage(ctx context.Context, src HistoricalReader, epoch uint64, rid string, view ViewType, id int64, want [32]byte) (HistoricalPage, error) {
	if err := ctx.Err(); err != nil {
		return HistoricalPage{}, err
	}
	page, err := src.Page(ctx, epoch, rid, view, id)
	if err != nil {
		return page, err
	}
	emptyView := want == ([32]byte{}) && page.IsLeaf && len(page.Keys) == 0
	if page.PageID != id || page.VersionEpoch > epoch || page.Hash != want && !emptyView ||
		page.IsLeaf && (len(page.Keys) != len(page.Values) || len(page.ChildIDs) > 0) ||
		!page.IsLeaf && (len(page.ChildIDs) != len(page.Keys)+1 || len(page.ChildHashes) != len(page.ChildIDs)) {
		return page, fmt.Errorf("resolve historical MVA: malformed or wrong-version page %d", id)
	}
	return page, nil
}

func descendHistorical(ctx context.Context, src HistoricalReader, epoch uint64, rid string, view ViewType, id int64, hash [32]byte, path []historyStep, choose func(HistoricalPage) int) ([]historyStep, HistoricalPage, error) {
	page, err := readHistoryPage(ctx, src, epoch, rid, view, id, hash)
	if err != nil {
		return nil, page, err
	}
	for !page.IsLeaf {
		index := choose(page)
		if index < 0 || index >= len(page.ChildIDs) {
			return nil, page, fmt.Errorf("resolve historical MVA: invalid child index")
		}
		path = append(path, historyStep{page: page, index: index})
		page, err = readHistoryPage(ctx, src, epoch, rid, view, page.ChildIDs[index], page.ChildHashes[index])
		if err != nil {
			return nil, page, err
		}
	}
	return path, page, nil
}

func adjacentHistorical(ctx context.Context, src HistoricalReader, epoch uint64, rid string, view ViewType, path []historyStep, forward bool) ([]historyStep, HistoricalPage, error) {
	for depth := len(path) - 1; depth >= 0; depth-- {
		step := path[depth]
		index := step.index - 1
		if forward {
			index = step.index + 1
		}
		if index < 0 || index >= len(step.page.ChildIDs) {
			continue
		}
		prefix := slices.Clone(path[:depth])
		prefix = append(prefix, historyStep{page: step.page, index: index})
		choose := func(page HistoricalPage) int {
			if forward {
				return 0
			}
			return len(page.ChildIDs) - 1
		}
		return descendHistorical(ctx, src, epoch, rid, view, step.page.ChildIDs[index], step.page.ChildHashes[index], prefix, choose)
	}
	return nil, HistoricalPage{}, nil
}

func resolveHistoricalView(ctx context.Context, src HistoricalReader, epoch uint64, rid string, query LocatorQuery, view ViewType, state HistoricalView) ([]*LocatorValue, MVARegionProof, error) {
	proof := MVARegionProof{View: view, Query: query}
	if state.VersionEpoch > epoch {
		return nil, proof, fmt.Errorf("resolve historical MVA: future view state")
	}
	choose := func(page HistoricalPage) int {
		return sort.Search(len(page.Keys), func(i int) bool { return query.Compare(page.Keys[i]) <= 0 })
	}
	path, page, err := descendHistorical(ctx, src, epoch, rid, view, state.RootPageID, state.RootHash, nil, choose)
	if err != nil {
		return nil, proof, err
	}
	var matches []*LocatorValue
	var first, last HistoricalPage
	var firstPath, lastPath []historyStep
	firstIndex, lastIndex := -1, -1
	index := sort.Search(len(page.Keys), func(i int) bool { return query.Compare(page.Keys[i]) <= 0 })
scan:
	for {
		proof.ScanPaths = append(proof.ScanPaths, historyProof(page, path))
		for ; index < len(page.Keys); index++ {
			order := query.Compare(page.Keys[index])
			if order < 0 {
				break scan
			}
			if Matches(query, page.Keys[index]) {
				if firstIndex < 0 {
					first, firstPath, firstIndex = page, slices.Clone(path), index
				}
				last, lastPath, lastIndex = page, slices.Clone(path), index
				matches = append(matches, page.Values[index])
				proof.Path = append(proof.Path, historyProof(page, path)...)
			}
		}
		path, page, err = adjacentHistorical(ctx, src, epoch, rid, view, path, true)
		if err != nil {
			return nil, proof, err
		}
		if page.Keys == nil {
			break
		}
		index = 0
	}
	if firstIndex >= 0 && !isTimeOnly(query) {
		if firstIndex > 0 {
			proof.LeftBoundary = first.Values[firstIndex-1]
			proof.LeftBoundaryPath = historyProof(first, firstPath)
		} else {
			prevPath, prev, err := adjacentHistorical(ctx, src, epoch, rid, view, firstPath, false)
			if err != nil {
				return nil, proof, err
			}
			if prev.Keys != nil && len(prev.Values) > 0 {
				proof.LeftBoundary = prev.Values[len(prev.Values)-1]
				proof.LeftBoundaryPath = historyProof(prev, prevPath)
			}
		}
		if lastIndex+1 < len(last.Values) {
			proof.RightBoundary = last.Values[lastIndex+1]
			proof.RightBoundaryPath = historyProof(last, lastPath)
		} else {
			nextPath, next, err := adjacentHistorical(ctx, src, epoch, rid, view, lastPath, true)
			if err != nil {
				return nil, proof, err
			}
			if next.Keys != nil && len(next.Values) > 0 {
				proof.RightBoundary = next.Values[0]
				proof.RightBoundaryPath = historyProof(next, nextPath)
			}
		}
	}
	return matches, proof, nil
}

// ResolveHistorical reads only the finalized pages touched by the query and
// validates their proof against the supplied trusted MVA root.
func ResolveHistorical(ctx context.Context, src HistoricalReader, epoch uint64, query LocatorQuery, regions []merkle.TreeID, root [32]byte) ([]*LocatorValue, *MVAProof, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if src == nil || query == nil {
		return nil, nil, fmt.Errorf("resolve historical MVA: reader and query required")
	}
	if batch, ok := query.(LogIDBatchQuery); ok {
		return ResolveHistoricalBatch(ctx, src, epoch, batch, regions, root)
	}
	if q, ok := query.(AttrRangeQuery); ok && q.EndTS.Before(q.StartTS) {
		return nil, nil, fmt.Errorf("resolve historical MVA: invalid time range")
	}
	if q, ok := query.(TimeRangeQuery); ok && q.EndTS.Before(q.StartTS) {
		return nil, nil, fmt.Errorf("resolve historical MVA: invalid time range")
	}
	levels, err := src.GlobalLevels(ctx, epoch)
	if err != nil {
		return nil, nil, err
	}
	manifest, err := src.RegionManifest(ctx, epoch)
	if err != nil {
		return nil, nil, err
	}
	byID := make(map[string]HistoricalRegion, len(manifest))
	for _, r := range manifest {
		if _, duplicate := byID[r.RegionID]; duplicate {
			return nil, nil, fmt.Errorf("resolve historical MVA: duplicate Region")
		}
		byID[r.RegionID] = r
	}
	proof := &MVAProof{Epoch: epoch, Levels: levels, Regions: make(map[string]*MVARegionProof, len(regions))}
	var values []*LocatorValue
	for _, id := range regions {
		region, ok := byID[id.RegionID]
		if !ok {
			return nil, nil, fmt.Errorf("resolve historical MVA: Region %q missing", id.RegionID)
		}
		view := ViewAttribute
		want := region.AttrRoot
		if query.isLogViewKey() {
			view = ViewID
			want = region.IDRoot
		}
		state, err := src.ViewState(ctx, epoch, id.RegionID, view)
		if err != nil {
			return nil, nil, err
		}
		if state.RootHash != want {
			return nil, nil, fmt.Errorf("resolve historical MVA: view root differs from Region manifest")
		}
		matched, part, err := resolveHistoricalView(ctx, src, epoch, id.RegionID, query, view, state)
		if err != nil {
			return nil, nil, err
		}
		part.RegionIndex, part.IDRoot, part.AttrRoot, part.RegionRoot = region.Index, region.IDRoot, region.AttrRoot, region.RegionRoot
		proof.Regions[id.RegionID] = &part
		values = append(values, matched...)
	}
	if err := VerifyResolution(query, regions, values, proof, root); err != nil {
		return nil, nil, err
	}
	return values, proof, nil
}
