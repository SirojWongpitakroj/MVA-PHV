package mva

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

type snapshotHistory struct {
	epochs map[uint64]*MVASnapshot
	reads  int
}

func (h *snapshotHistory) snapshot(epoch uint64) (*MVASnapshot, error) {
	s := h.epochs[epoch]
	if s == nil {
		return nil, fmt.Errorf("epoch unavailable")
	}
	return s, nil
}
func (h *snapshotHistory) GlobalLevels(_ context.Context, epoch uint64) ([][][32]byte, error) {
	s, e := h.snapshot(epoch)
	if e != nil {
		return nil, e
	}
	return cloneHashLevels(s.Levels), nil
}
func (h *snapshotHistory) RegionManifest(_ context.Context, epoch uint64) ([]HistoricalRegion, error) {
	s, e := h.snapshot(epoch)
	if e != nil {
		return nil, e
	}
	out := make([]HistoricalRegion, 0, len(s.Regions))
	for i := 0; i < len(s.Regions); i++ {
		rid := fmt.Sprint(i)
		r := s.Regions[rid]
		out = append(out, HistoricalRegion{RegionID: rid, Index: i, IDRoot: r.IDView.RootHash, AttrRoot: r.AttrView.RootHash, RegionRoot: r.Root})
	}
	return out, nil
}
func (h *snapshotHistory) view(epoch uint64, rid string, kind ViewType) (*LocatorTree, error) {
	s, e := h.snapshot(epoch)
	if e != nil {
		return nil, e
	}
	r := s.Regions[rid]
	if r == nil {
		return nil, fmt.Errorf("unknown Region")
	}
	if kind == ViewID {
		return r.IDView, nil
	}
	return r.AttrView, nil
}
func (h *snapshotHistory) ViewState(_ context.Context, epoch uint64, rid string, kind ViewType) (HistoricalView, error) {
	v, e := h.view(epoch, rid, kind)
	if e != nil {
		return HistoricalView{}, e
	}
	return HistoricalView{RootPageID: v.RootPageID, RootHash: v.RootHash, VersionEpoch: epoch}, nil
}
func (h *snapshotHistory) Page(_ context.Context, epoch uint64, rid string, kind ViewType, id int64) (HistoricalPage, error) {
	v, e := h.view(epoch, rid, kind)
	if e != nil {
		return HistoricalPage{}, e
	}
	var found *Page
	var visit func(*Page)
	visit = func(p *Page) {
		if p == nil || found != nil {
			return
		}
		if p.PageID == id {
			found = p
			return
		}
		for _, child := range p.Children {
			visit(child)
		}
	}
	visit(v.RootPage)
	if found == nil {
		return HistoricalPage{}, fmt.Errorf("missing page")
	}
	h.reads++
	p := HistoricalPage{PageID: id, VersionEpoch: epoch, Hash: found.Hash, IsLeaf: found.IsLeaf, Keys: found.Keys, Values: found.Values}
	for _, child := range found.Children {
		p.ChildIDs = append(p.ChildIDs, child.PageID)
		p.ChildHashes = append(p.ChildHashes, child.Hash)
	}
	return p, nil
}

func TestHistoricalResolutionReadsOnlyTouchedPagesAndKeepsOldEpoch(t *testing.T) {
	tree, err := NewMVA(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	initial := make([]PendingRecord, 0, 200)
	for i := byte(1); i <= 200; i++ {
		k, a, c := testMVALog(i, "0")
		initial = append(initial, PendingRecord{LogID: k.ID, RegionID: "0", SiteID: k.SiteID, DeviceID: k.DevID, Type: k.Type, TS: k.TS, Address: a, Locator: c})
	}
	root1, err := tree.PrepareCandidate(1, initial)
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.CommitCandidate(1); err != nil {
		t.Fatal(err)
	}
	old := tree.Finalized
	k, a, c := testMVALog(201, "0")
	root2, err := tree.PrepareCandidate(2, []PendingRecord{{LogID: k.ID, RegionID: "0", SiteID: k.SiteID, DeviceID: k.DevID, Type: k.Type, TS: k.TS, Address: a, Locator: c}})
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.CommitCandidate(2); err != nil {
		t.Fatal(err)
	}
	h := &snapshotHistory{epochs: map[uint64]*MVASnapshot{1: old, 2: tree.Finalized}}
	region := []merkle.TreeID{{Type: merkle.TreeRegion, RegionID: "0"}, {Type: merkle.TreeRegion, RegionID: "1"}}
	query := AttrRangeQuery{SiteID: "site", DevID: "device", Type: "type", StartTS: time.Unix(199, 0), EndTS: time.Unix(201, 0)}
	values, proof, err := ResolveHistorical(context.Background(), h, 1, query, region, root1)
	if err != nil || len(values) != 2 || proof.Epoch != 1 {
		t.Fatalf("old range: %d values, %v", len(values), err)
	}
	totalPages := 0
	var countPages func(*Page)
	countPages = func(page *Page) {
		if page == nil {
			return
		}
		totalPages++
		for _, child := range page.Children {
			countPages(child)
		}
	}
	countPages(old.Regions["0"].AttrView.RootPage)
	if h.reads*4 >= totalPages {
		t.Fatalf("historical query read %d of %d pages", h.reads, totalPages)
	}
	values, _, err = ResolveHistorical(context.Background(), h, 2, query, region, root2)
	if err != nil || len(values) != 3 {
		t.Fatalf("new range: %d values, %v", len(values), err)
	}
	values, _, err = ResolveHistorical(context.Background(), h, 1, query, region, root1)
	if err != nil || len(values) != 2 {
		t.Fatalf("old snapshot lost after newer epoch: %d values, %v", len(values), err)
	}
	if _, _, err := ResolveHistorical(context.Background(), h, 3, query, region, root2); err == nil {
		t.Fatal("accepted unavailable candidate epoch")
	}
}
