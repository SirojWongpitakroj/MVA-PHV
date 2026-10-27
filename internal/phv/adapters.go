package phv

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strconv"
	"time"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
	"github.com/SirojWongpitakroj/mva-phv/internal/hpbf"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
	"github.com/SirojWongpitakroj/mva-phv/internal/mpm"
	"github.com/SirojWongpitakroj/mva-phv/internal/mva"
)

// CurrentRoots uses MPM's authoritative latest epoch and confirms its joint
// checkpoint with the trusted checkpoint store. Historical readers can satisfy
// TrustedRoots separately without retaining old Go snapshots.
type CurrentRoots struct {
	Manager     *mpm.Manager
	Checkpoints mpm.CheckpointStore
}

// RootEvidence reads the epoch's untrusted root tuple from evidence storage.
// CheckpointRoots accepts it only if the trusted checkpoint binds all three.
type RootEvidence interface {
	RootTuple(ctx context.Context, epoch uint64) (mpm.Roots, error)
}

type CheckpointRoots struct {
	Evidence    RootEvidence
	Checkpoints mpm.CheckpointStore
}

func (s CheckpointRoots) Roots(ctx context.Context, epoch uint64) (mpm.Roots, error) {
	if s.Evidence == nil || s.Checkpoints == nil {
		return mpm.Roots{}, fmt.Errorf("PHV: root evidence and checkpoint store are required")
	}
	roots, err := s.Evidence.RootTuple(ctx, epoch)
	if err != nil {
		return mpm.Roots{}, err
	}
	return checkedRoots(ctx, s.Checkpoints, epoch, roots)
}

func checkedRoots(ctx context.Context, store mpm.CheckpointStore, epoch uint64, roots mpm.Roots) (mpm.Roots, error) {
	encoded, err := domain.Serialize([]byte("CHECKPOINT"), epoch, roots.MVA[:], roots.HMF[:], roots.HPBF[:])
	if err != nil {
		return mpm.Roots{}, err
	}
	checkpoint, err := store.GetCheckpoint(ctx, epoch)
	if err != nil {
		return mpm.Roots{}, err
	}
	if sha256.Sum256(encoded) != checkpoint {
		return mpm.Roots{}, fmt.Errorf("%w: finalized root tuple", ErrCheckpointMismatch)
	}
	return roots, nil
}

func (s CurrentRoots) Roots(ctx context.Context, epoch uint64) (mpm.Roots, error) {
	if s.Manager == nil || s.Checkpoints == nil {
		return mpm.Roots{}, fmt.Errorf("PHV: missing finalized MPM or checkpoint store")
	}
	current, roots := s.Manager.Finalized()
	if current != epoch {
		return mpm.Roots{}, fmt.Errorf("PHV: epoch %d is not the in-memory finalized epoch %d", epoch, current)
	}
	return checkedRoots(ctx, s.Checkpoints, epoch, roots)
}

// CurrentMVAResolver uses MVA's finalized in-memory query implementation.
type CurrentMVAResolver struct{ Tree *mva.MVA }

// HistoricalMVAResolver reads only versioned pages visited by the query.
// MVA owns B+ traversal and proof verification; Reader owns persistence.
type HistoricalMVAResolver struct{ Reader mva.HistoricalReader }

func (s HistoricalMVAResolver) Resolve(ctx context.Context, epoch uint64, query mva.LocatorQuery, regions []merkle.TreeID, root [32]byte) (Resolution, error) {
	if s.Reader == nil {
		return Resolution{}, fmt.Errorf("PHV: historical MVA reader is required")
	}
	values, proof, err := mva.ResolveHistorical(ctx, s.Reader, epoch, query, regions, root)
	if err != nil {
		return Resolution{}, fmt.Errorf("%w: %v", ErrInvalidMVAProof, err)
	}
	records, err := selectedFromValues(query, regions, values)
	if err != nil {
		return Resolution{}, err
	}
	return Resolution{Epoch: epoch, Records: records, Proof: proof}, nil
}

func parsePositive(raw string) (int64, error) {
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 0 {
		return 0, fmt.Errorf("PHV: invalid physical ID %q", raw)
	}
	return value, nil
}

func (s CurrentMVAResolver) Resolve(ctx context.Context, epoch uint64, query mva.LocatorQuery, regions []merkle.TreeID, root [32]byte) (Resolution, error) {
	if s.Tree == nil {
		return Resolution{}, fmt.Errorf("PHV: nil MVA")
	}
	if err := ctx.Err(); err != nil {
		return Resolution{}, err
	}
	switch query.(type) {
	case mva.AttrRangeQuery, mva.LogIDQuery, mva.SiteQuery, mva.SiteDeviceQuery, mva.TimeRangeQuery:
	default:
		return Resolution{}, fmt.Errorf("PHV: unsupported MVA query type")
	}
	values, proof, err := s.Tree.Resolve(query, regions)
	if err != nil {
		return Resolution{}, err
	}
	if proof == nil || proof.Epoch != epoch {
		return Resolution{}, fmt.Errorf("%w: MVA proof", ErrWrongEpoch)
	}
	if err := mva.VerifyResolution(query, regions, values, proof, root); err != nil {
		return Resolution{}, fmt.Errorf("%w: %v", ErrInvalidMVAProof, err)
	}
	records, err := selectedFromValues(query, regions, values)
	if err != nil {
		return Resolution{}, err
	}
	return Resolution{Epoch: epoch, Records: records, Proof: proof}, nil
}

func selectedFromValues(query mva.LocatorQuery, regions []merkle.TreeID, values []*mva.LocatorValue) ([]SelectedRecord, error) {
	records := make([]SelectedRecord, 0, len(values))
	allowed := make(map[string]struct{}, len(regions))
	for _, region := range regions {
		allowed[region.RegionID] = struct{}{}
	}
	for _, value := range values {
		if value == nil || value.LocatorKey == nil {
			return nil, fmt.Errorf("PHV: invalid MVA locator")
		}
		if !mva.Matches(query, value.LocatorKey) {
			return nil, fmt.Errorf("PHV: MVA returned a value outside the query")
		}
		if _, ok := allowed[value.RegionID]; !ok {
			return nil, fmt.Errorf("PHV: MVA returned a value outside candidate Regions")
		}
		var site, device, kind string
		var ts time.Time
		id := value.LocatorKey.LogID()
		fromLog := false
		if _, isID := query.(mva.LogIDQuery); isID {
			fromLog = true
		} else {
			key, err := value.LocatorKey.Serialize()
			if err != nil {
				return nil, err
			}
			if err := domain.Deserialize(key, &site, &device, &kind, &ts, &id); err != nil {
				return nil, fmt.Errorf("PHV: decode MVA attribute: %w", err)
			}
		}
		var sid, seg, leaf int64
		var err error
		if sid, err = parsePositive(value.ShardID); err != nil {
			return nil, err
		}
		if seg, err = parsePositive(value.SegmentID); err != nil {
			return nil, err
		}
		if leaf, err = parsePositive(value.LeafID); err != nil {
			return nil, err
		}
		records = append(records, SelectedRecord{LogID: id, DescriptorFromLog: fromLog,
			Descriptor: mpm.Descriptor{RegionID: value.RegionID, SiteID: site, DeviceID: device, Type: kind, TS: ts},
			Address:    mpm.Address{RegionID: value.RegionID, ShardID: sid, SegmentID: seg, LeafID: leaf}, Locator: value.LeafHash})
	}
	return records, nil
}

// CurrentHPBFPruner checks every Shard filter commitment, Regional Merkle
// level, derived Region filter, and shared Global level before excluding data.
type CurrentHPBFPruner struct{ Tree *hpbf.HPBF }

type HPBFProofSource interface {
	LoadHPBFProof(context.Context, uint64) (hpbf.HPBFProof, error)
}

// HistoricalHPBFPruner authenticates versioned filter evidence against the
// selected epoch's checkpoint root before using a negative to prune.
type HistoricalHPBFPruner struct{ Source HPBFProofSource }

func (s HistoricalHPBFPruner) Prune(ctx context.Context, epoch uint64, tokens [3][]byte, root [32]byte) (Pruning, error) {
	if s.Source == nil {
		return Pruning{}, fmt.Errorf("PHV: historical HPBF source is required")
	}
	proof, err := s.Source.LoadHPBFProof(ctx, epoch)
	if err != nil {
		return Pruning{}, err
	}
	if proof.Epoch != epoch {
		return Pruning{}, fmt.Errorf("%w: HPBF evidence", ErrWrongEpoch)
	}
	regions, shards := hpbf.ProofCandidates(proof, tokens)
	if err := hpbf.VerifyProof(proof, tokens, root, regions, shards); err != nil {
		return Pruning{}, fmt.Errorf("%w: %v", ErrInvalidHPBFProof, err)
	}
	return Pruning{Regions: regions, Shards: shards, Proof: &proof}, nil
}

func (s CurrentHPBFPruner) Prune(ctx context.Context, epoch uint64, tokens [3][]byte, root [32]byte) (Pruning, error) {
	if s.Tree == nil {
		return Pruning{}, fmt.Errorf("PHV: nil HPBF")
	}
	if err := ctx.Err(); err != nil {
		return Pruning{}, err
	}
	regions, shards, proof := s.Tree.CandidateRegionShards(tokens)
	if proof.Epoch != epoch {
		return Pruning{}, fmt.Errorf("%w: HPBF proof", ErrWrongEpoch)
	}
	if err := hpbf.VerifyProof(proof, tokens, root, regions, shards); err != nil {
		return Pruning{}, fmt.Errorf("%w: %v", ErrInvalidHPBFProof, err)
	}
	return Pruning{Regions: regions, Shards: shards, Proof: &proof}, nil
}
