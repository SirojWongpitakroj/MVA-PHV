package mpm

import (
	"fmt"

	"github.com/SirojWongpitakroj/mva-phv/internal/hpbf"
	"github.com/SirojWongpitakroj/mva-phv/internal/mva"
)

// MVAAdapter supplies one bound record to both regional locator views.
type MVAAdapter struct{ Tree *mva.MVA }

var _ MVA = (*MVAAdapter)(nil)

func pendingMVA(record Record) mva.PendingRecord {
	return mva.PendingRecord{LogID: record.Log.LogID, RegionID: record.Descriptor.RegionID,
		SiteID: record.Descriptor.SiteID, DeviceID: record.Descriptor.DeviceID,
		Type: record.Descriptor.Type, TS: record.Descriptor.TS,
		Address: record.Address.MVA(), Locator: record.Locator}
}

func (a *MVAAdapter) Ingest(record Record) (MVAUpdate, error) {
	if a == nil || a.Tree == nil {
		return MVAUpdate{}, fmt.Errorf("MPM MVA adapter: nil tree")
	}
	id, attr, err := a.Tree.IngestRecord(pendingMVA(record))
	if err != nil {
		return MVAUpdate{}, err
	}
	epoch, order, err := a.Tree.WorkingMetadata()
	if err != nil {
		return MVAUpdate{}, err
	}
	return MVAUpdate{IDView: id, AttrView: attr, WorkingEpoch: epoch, TreeOrder: order}, nil
}

func (a *MVAAdapter) Prepare(epoch uint64, sealed []Record) ([32]byte, error) {
	if a == nil || a.Tree == nil {
		return [32]byte{}, fmt.Errorf("MPM MVA adapter: nil tree")
	}
	records := make([]mva.PendingRecord, len(sealed))
	for i, record := range sealed {
		records[i] = pendingMVA(record)
	}
	return a.Tree.PrepareCandidate(epoch, records)
}

func (a *MVAAdapter) Promote(epoch uint64) error           { return a.Tree.CommitCandidate(epoch) }
func (a *MVAAdapter) ValidateCandidate(epoch uint64) error { return a.Tree.ValidateCandidate(epoch) }

// HPBFAdapter keeps token construction and Bloom internals inside HPBF.
type HPBFAdapter struct{ Tree *hpbf.HPBF }

var _ HPBF = (*HPBFAdapter)(nil)

func (a *HPBFAdapter) AddToken(rid string, sid int64, site, device, typ string) (HPBFUpdate, error) {
	if a == nil || a.Tree == nil {
		return HPBFUpdate{}, fmt.Errorf("MPM HPBF adapter: nil tree")
	}
	if err := a.Tree.AddToken(rid, sid, site, device, typ); err != nil {
		return HPBFUpdate{}, err
	}
	epoch, bits, hashes, words, err := a.Tree.WorkingShardFilter(rid, sid)
	if err != nil {
		return HPBFUpdate{}, err
	}
	return HPBFUpdate{RegionID: rid, ShardID: sid, WorkingEpoch: epoch,
		BitCount: bits, HashCount: hashes, Words: words}, nil
}

func (a *HPBFAdapter) Prepare(epoch uint64, sealed []Record) ([32]byte, error) {
	if a == nil || a.Tree == nil {
		return [32]byte{}, fmt.Errorf("MPM HPBF adapter: nil tree")
	}
	records := make([]hpbf.TokenRecord, len(sealed))
	for i, record := range sealed {
		records[i] = hpbf.TokenRecord{RegionID: record.Address.RegionID, ShardID: record.Address.ShardID,
			SiteID: record.Descriptor.SiteID, DeviceID: record.Descriptor.DeviceID, Type: record.Descriptor.Type}
	}
	return a.Tree.PrepareCandidate(epoch, records)
}

func (a *HPBFAdapter) Promote(epoch uint64) error           { return a.Tree.CommitCandidate(epoch) }
func (a *HPBFAdapter) ValidateCandidate(epoch uint64) error { return a.Tree.ValidateCandidate(epoch) }
