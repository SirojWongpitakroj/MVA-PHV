package phv

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sort"

	"github.com/SirojWongpitakroj/mva-phv/internal/hpbf"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
	"github.com/SirojWongpitakroj/mva-phv/internal/mpm"
	"github.com/SirojWongpitakroj/mva-phv/internal/mva"
)

// VerifyAuditProof needs only the returned package and the trusted checkpoint
// store. It does not consult PHV, MVA, HPBF, HMF, or Cassandra working state.
func VerifyAuditProof(ctx context.Context, proof Proof, checkpoints mpm.CheckpointStore) (Verification, error) {
	var empty Verification
	if checkpoints == nil || proof.Query == nil || proof.MVA == nil {
		return empty, fmt.Errorf("%w: missing checkpoint store, query, or MVA evidence", ErrMalformedProof)
	}
	if proof.MVA.Epoch != proof.Epoch {
		return empty, fmt.Errorf("%w: MVA proof", ErrWrongEpoch)
	}
	if _, err := checkedRoots(ctx, checkpoints, proof.Epoch, proof.Roots); err != nil {
		return empty, err
	}
	ids, err := proof.Topology.orderedRegions()
	if err != nil {
		return empty, err
	}
	regions := make([]merkle.TreeID, len(ids))
	for i, rid := range ids {
		regions[i] = merkle.TreeID{Type: merkle.TreeRegion, RegionID: rid}
	}
	if proof.HPBF != nil {
		if proof.HPBF.Epoch != proof.Epoch {
			return empty, fmt.Errorf("%w: HPBF proof", ErrWrongEpoch)
		}
		if proof.HPBF.TreeID.Type != merkle.TreeGlobal {
			return empty, fmt.Errorf("%w: HPBF tree ID", ErrInvalidHPBFProof)
		}
		want, usable, err := pruningTokens(proof.Query)
		if err != nil {
			return empty, err
		}
		if !usable {
			return empty, fmt.Errorf("%w: unsupported HPBF pruning query", ErrInvalidQueryScope)
		}
		for i := range want {
			if !bytes.Equal(want[i], proof.Tokens[i]) {
				return empty, fmt.Errorf("%w: HPBF token/query mismatch", ErrInvalidQueryScope)
			}
		}
		candidateRegions, candidateShards := slices.Clone(proof.PrunedRegions), slices.Clone(proof.PrunedShards)
		if err := hpbf.VerifyProof(*proof.HPBF, proof.Tokens, proof.Roots.HPBF, candidateRegions, candidateShards); err != nil {
			return empty, fmt.Errorf("%w: %v", ErrInvalidHPBFProof, err)
		}
		regions = slices.Clone(proof.PrunedRegions)
		sort.Slice(regions, func(i, j int) bool { return regions[i].RegionID < regions[j].RegionID })
	} else if len(proof.PrunedRegions) > 0 || len(proof.PrunedShards) > 0 {
		return empty, fmt.Errorf("%w: pruning claims without HPBF evidence", ErrMalformedProof)
	}
	values, err := mva.VerifiedValues(proof.Query, regions, proof.MVA, proof.Roots.MVA)
	if err != nil {
		return empty, fmt.Errorf("PHV: invalid MVA proof: %w", err)
	}
	records, err := selectedFromValues(proof.Query, regions, values)
	if err != nil {
		return empty, err
	}
	if len(records) != len(proof.Selected) {
		return empty, fmt.Errorf("%w: selected records differ from MVA result", ErrInvalidQueryScope)
	}
	sort.Slice(records, func(i, j int) bool { return lessRecord(records[i], records[j]) })
	for i, record := range records {
		if i > 0 && !lessRecord(proof.Selected[i-1], proof.Selected[i]) ||
			record.DescriptorFromLog != proof.Selected[i].DescriptorFromLog || !sameSelected(record, proof.Selected[i]) {
			return empty, fmt.Errorf("%w: selected record differs from MVA proof", ErrInvalidQueryScope)
		}
	}
	if len(records) == 0 {
		if proof.Root != proof.Roots.HMF || len(proof.Trees) > 0 || len(proof.Nodes) > 0 || len(proof.Logs) > 0 {
			return empty, fmt.Errorf("%w: empty query contains HMF evidence", ErrMalformedProof)
		}
		return Verification{Valid: true, GlobalRoot: proof.Roots.HMF}, nil
	}
	if proof.HPBF != nil {
		allowed := make(map[merkle.TreeID]struct{}, len(proof.PrunedShards))
		for _, id := range proof.PrunedShards {
			allowed[id] = struct{}{}
		}
		for _, record := range records {
			id := merkle.TreeID{Type: merkle.TreeShard, RegionID: record.Address.RegionID, ShardID: record.Address.ShardID}
			if _, ok := allowed[id]; !ok {
				return empty, fmt.Errorf("%w: MVA result outside authenticated HPBF candidates", ErrInvalidQueryScope)
			}
		}
	}
	return VerifyHMF(proof, proof.Roots.HMF)
}
