package mva

import (
	"bytes"
	"context"
	"fmt"
	"reflect"

	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

func batchRegions(target LogIDBatchTarget, available []merkle.TreeID) ([]merkle.TreeID, error) {
	if target.RegionID == "" {
		return available, nil
	}
	for _, region := range available {
		if region.Type == merkle.TreeRegion && region.RegionID == target.RegionID {
			return []merkle.TreeID{region}, nil
		}
	}
	return nil, fmt.Errorf("MVA: LogID batch Region hint %q is not configured", target.RegionID)
}

func validBatch(q LogIDBatchQuery) error {
	normalized, err := NewLogIDBatchQuery(q.Targets)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(normalized.Targets, q.Targets) {
		return fmt.Errorf("MVA: LogID batch is not in canonical order")
	}
	return nil
}

type pointResolve func(context.Context, LogIDQuery, []merkle.TreeID) ([]*LocatorValue, *MVAProof, error)

type batchPageKey struct {
	rid  string
	view ViewType
	id   int64
}
type batchViewKey struct {
	rid  string
	view ViewType
}
type cachedBatchReader struct {
	source   HistoricalReader
	global   [][][32]byte
	manifest []HistoricalRegion
	views    map[batchViewKey]HistoricalView
	pages    map[batchPageKey]HistoricalPage
}

func (r *cachedBatchReader) GlobalLevels(ctx context.Context, epoch uint64) ([][][32]byte, error) {
	if r.global != nil {
		return r.global, nil
	}
	v, e := r.source.GlobalLevels(ctx, epoch)
	if e == nil {
		r.global = v
	}
	return v, e
}
func (r *cachedBatchReader) RegionManifest(ctx context.Context, epoch uint64) ([]HistoricalRegion, error) {
	if r.manifest != nil {
		return r.manifest, nil
	}
	v, e := r.source.RegionManifest(ctx, epoch)
	if e == nil {
		r.manifest = v
	}
	return v, e
}
func (r *cachedBatchReader) ViewState(ctx context.Context, epoch uint64, rid string, view ViewType) (HistoricalView, error) {
	k := batchViewKey{rid, view}
	if v, ok := r.views[k]; ok {
		return v, nil
	}
	v, e := r.source.ViewState(ctx, epoch, rid, view)
	if e == nil {
		r.views[k] = v
	}
	return v, e
}
func (r *cachedBatchReader) Page(ctx context.Context, epoch uint64, rid string, view ViewType, id int64) (HistoricalPage, error) {
	k := batchPageKey{rid, view, id}
	if v, ok := r.pages[k]; ok {
		return v, nil
	}
	v, e := r.source.Page(ctx, epoch, rid, view, id)
	if e == nil {
		r.pages[k] = v
	}
	return v, e
}

// ResolveLogIDBatch combines authenticated point lookups. Each requested ID
// must have exactly one MVA entry; routing hints never establish membership.
func ResolveLogIDBatch(ctx context.Context, query LogIDBatchQuery, regions []merkle.TreeID, resolve pointResolve) ([]*LocatorValue, *MVAProof, error) {
	if err := validBatch(query); err != nil {
		return nil, nil, err
	}
	if resolve == nil {
		return nil, nil, fmt.Errorf("MVA: missing batch point resolver")
	}
	proof := &MVAProof{Batch: make([]MVABatchItem, 0, len(query.Targets))}
	values := make([]*LocatorValue, 0, len(query.Targets))
	for _, target := range query.Targets {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		selectedRegions, err := batchRegions(target, regions)
		if err != nil {
			return nil, nil, err
		}
		found, part, err := resolve(ctx, LogIDQuery{ID: target.ID}, selectedRegions)
		if err != nil {
			return nil, nil, err
		}
		if len(found) != 1 || found[0] == nil || found[0].LocatorKey == nil || found[0].LocatorKey.LogID() != target.ID ||
			(target.RegionID != "" && found[0].RegionID != target.RegionID) {
			return nil, nil, fmt.Errorf("MVA: requested LogID %s not authenticated at hinted Region", target.ID)
		}
		values = append(values, found[0])
		proof.Batch = append(proof.Batch, MVABatchItem{Target: target, Regions: append([]merkle.TreeID(nil), selectedRegions...), Proof: part})
	}
	return values, proof, nil
}

func ResolveHistoricalBatch(ctx context.Context, src HistoricalReader, epoch uint64, query LogIDBatchQuery, regions []merkle.TreeID, root [32]byte) ([]*LocatorValue, *MVAProof, error) {
	if src == nil {
		return nil, nil, fmt.Errorf("MVA: historical batch reader is required")
	}
	src = &cachedBatchReader{source: src, views: make(map[batchViewKey]HistoricalView), pages: make(map[batchPageKey]HistoricalPage)}
	values, proof, err := ResolveLogIDBatch(ctx, query, regions, func(ctx context.Context, q LogIDQuery, rs []merkle.TreeID) ([]*LocatorValue, *MVAProof, error) {
		return ResolveHistorical(ctx, src, epoch, q, rs, root)
	})
	if err != nil {
		return nil, nil, err
	}
	proof.Epoch = epoch
	if err := VerifyResolution(query, regions, values, proof, root); err != nil {
		return nil, nil, err
	}
	return values, proof, nil
}

func verifiedBatchValues(query LogIDBatchQuery, regions []merkle.TreeID, proof *MVAProof, root [32]byte) ([]*LocatorValue, error) {
	if err := validBatch(query); err != nil {
		return nil, err
	}
	if proof == nil || len(proof.Batch) != len(query.Targets) || len(proof.Regions) != 0 || len(proof.Levels) != 0 {
		return nil, fmt.Errorf("verify MVA: malformed LogID batch proof")
	}
	values := make([]*LocatorValue, 0, len(query.Targets))
	for i, target := range query.Targets {
		item := proof.Batch[i]
		selectedRegions, err := batchRegions(target, regions)
		if err != nil {
			return nil, err
		}
		if item.Target != target || !reflect.DeepEqual(item.Regions, selectedRegions) || item.Proof == nil || len(item.Proof.Batch) > 0 || item.Proof.Epoch != proof.Epoch {
			return nil, fmt.Errorf("verify MVA: wrong LogID batch item")
		}
		found, err := VerifiedValues(LogIDQuery{ID: target.ID}, selectedRegions, item.Proof, root)
		if err != nil {
			return nil, err
		}
		if len(found) != 1 || found[0] == nil || found[0].LocatorKey == nil || found[0].LocatorKey.LogID() != target.ID ||
			(target.RegionID != "" && found[0].RegionID != target.RegionID) {
			return nil, fmt.Errorf("verify MVA: missing or misplaced batch LogID %s", target.ID)
		}
		values = append(values, found[0])
	}
	return values, nil
}

func sameBatchValues(a, b []*LocatorValue) error {
	if len(a) != len(b) {
		return fmt.Errorf("verify MVA: incomplete LogID batch")
	}
	for i := range a {
		if a[i] == nil || b[i] == nil {
			return fmt.Errorf("verify MVA: nil batch value")
		}
		x, err := a[i].Serialize()
		if err != nil {
			return err
		}
		y, err := b[i].Serialize()
		if err != nil {
			return err
		}
		if !bytes.Equal(x, y) {
			return fmt.Errorf("verify MVA: batch value differs from authenticated page")
		}
	}
	return nil
}
