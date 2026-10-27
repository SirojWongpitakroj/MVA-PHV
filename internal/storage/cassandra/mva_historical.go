package cassandra

import (
	"context"
	"fmt"
	"sort"

	"github.com/SirojWongpitakroj/mva-phv/internal/mva"
)

var _ mva.HistoricalReader = (*Store)(nil)

func (s *Store) GlobalLevels(ctx context.Context, epoch uint64) ([][][32]byte, error) {
	rows, err := s.ListMVAGlobalNodes(ctx, epoch)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("cassandra MVA: missing Global levels")
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Level != rows[j].Level {
			return rows[i].Level < rows[j].Level
		}
		return rows[i].Index < rows[j].Index
	})
	var levels [][][32]byte
	for _, row := range rows {
		if row.Level < 0 || row.Index < 0 || row.Level > 64 {
			return nil, fmt.Errorf("cassandra MVA: invalid Global position")
		}
		for len(levels) <= int(row.Level) {
			levels = append(levels, nil)
		}
		if int64(len(levels[row.Level])) != row.Index {
			return nil, fmt.Errorf("cassandra MVA: missing or duplicate Global node")
		}
		levels[row.Level] = append(levels[row.Level], row.Hash)
	}
	return levels, nil
}

func (s *Store) RegionManifest(ctx context.Context, epoch uint64) ([]mva.HistoricalRegion, error) {
	rows, err := s.ListMVARegionCommitments(ctx, epoch)
	if err != nil {
		return nil, err
	}
	result := make([]mva.HistoricalRegion, 0, len(rows))
	for _, row := range rows {
		if row.RegionIndex < 0 || int64(int(row.RegionIndex)) != row.RegionIndex {
			return nil, fmt.Errorf("cassandra MVA: invalid Region index")
		}
		result = append(result, mva.HistoricalRegion{RegionID: row.RegionID, Index: int(row.RegionIndex), IDRoot: row.IDRoot, AttrRoot: row.AttrRoot, RegionRoot: row.RegionRoot})
	}
	return result, nil
}

func (s *Store) ViewState(ctx context.Context, epoch uint64, rid string, view mva.ViewType) (mva.HistoricalView, error) {
	row, err := s.GetViewStateAt(ctx, rid, string(view), epoch)
	if err != nil {
		return mva.HistoricalView{}, err
	}
	if row.Epoch < 0 {
		return mva.HistoricalView{}, fmt.Errorf("cassandra MVA: negative view epoch")
	}
	return mva.HistoricalView{RootPageID: row.RootPageID, RootHash: row.RootHash, VersionEpoch: uint64(row.Epoch)}, nil
}

func (s *Store) Page(ctx context.Context, epoch uint64, rid string, view mva.ViewType, id int64) (mva.HistoricalPage, error) {
	row, err := s.GetPageAt(ctx, rid, string(view), id, epoch)
	if err != nil {
		return mva.HistoricalPage{}, err
	}
	payload, err := row.DecodePageData()
	if err != nil {
		return mva.HistoricalPage{}, err
	}
	if row.VersionEpoch < 0 {
		return mva.HistoricalPage{}, fmt.Errorf("cassandra MVA: negative page epoch")
	}
	page := mva.HistoricalPage{PageID: row.PageID, VersionEpoch: uint64(row.VersionEpoch), Hash: row.Hash, IsLeaf: row.IsLeaf}
	for i, keyBytes := range payload.Keys {
		key, err := mva.DecodeStoredKey(view, keyBytes)
		if err != nil {
			return mva.HistoricalPage{}, err
		}
		page.Keys = append(page.Keys, key)
		if page.IsLeaf {
			value, err := mva.DecodeStoredValue(view, keyBytes, payload.Values[i])
			if err != nil {
				return mva.HistoricalPage{}, err
			}
			page.Values = append(page.Values, value)
		}
	}
	for _, child := range payload.Children {
		page.ChildIDs = append(page.ChildIDs, child.PageID)
		page.ChildHashes = append(page.ChildHashes, child.Hash)
	}
	return page, nil
}
