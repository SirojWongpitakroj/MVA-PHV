package phv

import (
	"context"
	"fmt"

	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
	"github.com/SirojWongpitakroj/mva-phv/internal/mpm"
)

type Localization struct {
	Failures []Failure
	Examined int
	Pruned   int
	Expanded int
}

// referenceLeaf authenticates one expected child commitment to its parent
// root. A repository value alone is never accepted as a localization oracle.
func referenceLeaf(ctx context.Context, repo Repository, epoch uint64, parent TreePlan, index int64, parentRoot [32]byte) ([32]byte, error) {
	path, _, err := Frontier(parent.Tree, parent.LeafCount, []int64{index})
	if err != nil {
		return [32]byte{}, err
	}
	positions := append([]NodeKey{{Tree: parent.Tree, Level: 0, Index: index}}, path.Frontier...)
	nodes, err := repo.FetchNodes(ctx, epoch, parent.Tree, positions)
	if err != nil {
		return [32]byte{}, err
	}
	if err := validateNodes(epoch, positions, nodes); err != nil {
		return [32]byte{}, err
	}
	values := make(map[NodeKey][32]byte, len(nodes))
	for _, node := range nodes {
		values[node.Key] = node.Hash
	}
	value := values[positions[0]]
	got, err := verifyTreePlan(path, values, map[int64][32]byte{index: value})
	if err != nil {
		return [32]byte{}, err
	}
	if got != parentRoot {
		return [32]byte{}, fmt.Errorf("PHV: reference path does not authenticate to finalized parent root")
	}
	return value, nil
}

// Localize descends only mismatching selected paths. A branch whose expected
// reference cannot be authenticated remains unresolved, not confirmed tamper.
func Localize(ctx context.Context, repo Repository, proof Proof, trustedRoot [32]byte, verified Verification) Localization {
	result := Localization{}
	if repo == nil || verified.Valid {
		return result
	}
	plans := make(map[merkle.TreeID]TreePlan, len(proof.Trees))
	for _, plan := range proof.Trees {
		plans[plan.Tree] = plan
	}
	regionIDs, err := proof.Topology.orderedRegions()
	if err != nil {
		result.Failures = append(result.Failures, Failure{Tree: merkle.TreeID{Type: merkle.TreeGlobal}, Unresolved: true, Reason: err.Error()})
		return result
	}
	logs := make(map[mpm.Address]EncryptedRecord, len(proof.Logs))
	selected := make(map[mpm.Address]SelectedRecord, len(proof.Selected))
	for _, log := range proof.Logs {
		logs[log.Address] = log
	}
	for _, record := range proof.Selected {
		selected[record.Address] = record
	}
	var descend func(TreePlan, [32]byte)
	descend = func(parent TreePlan, expectedRoot [32]byte) {
		result.Expanded++
		if ctx.Err() != nil {
			result.Failures = append(result.Failures, Failure{Tree: parent.Tree, Unresolved: true, Reason: ctx.Err().Error()})
			return
		}
		if verified.TreeRoots[parent.Tree] == expectedRoot {
			result.Pruned++
			return
		}
		mismatchFound := false
		for _, index := range parent.Selected {
			result.Examined++
			reference, err := referenceLeaf(ctx, repo, proof.Epoch, parent, index, expectedRoot)
			if err != nil {
				result.Failures = append(result.Failures, Failure{Tree: parent.Tree, Index: index, Unresolved: true, Reason: err.Error()})
				continue
			}
			var child merkle.TreeID
			var actual [32]byte
			var logID [16]byte
			switch parent.Tree.Type {
			case merkle.TreeGlobal:
				child = merkle.TreeID{Type: merkle.TreeRegion, RegionID: regionIDs[index]}
				actual = verified.TreeRoots[child]
			case merkle.TreeRegion:
				child = merkle.TreeID{Type: merkle.TreeShard, RegionID: parent.Tree.RegionID, ShardID: index}
				actual = verified.TreeRoots[child]
			case merkle.TreeShard:
				child = merkle.TreeID{Type: merkle.TreeSegment, RegionID: parent.Tree.RegionID, ShardID: parent.Tree.ShardID, SegmentID: index}
				actual = verified.TreeRoots[child]
			case merkle.TreeSegment:
				child = parent.Tree
				address := mpm.Address{RegionID: child.RegionID, ShardID: child.ShardID, SegmentID: child.SegmentID, LeafID: index}
				record, ok := selected[address]
				if !ok {
					result.Failures = append(result.Failures, Failure{Tree: child, Index: index, Unresolved: true, Reason: "selected log missing"})
					continue
				}
				logID = record.LogID
				actual, _, err = recordHash(record, logs[address])
				if err != nil {
					result.Failures = append(result.Failures, Failure{Tree: child, Index: index, Unresolved: true, Reason: err.Error()})
					continue
				}
			}
			if actual == reference {
				result.Pruned++
				continue
			}
			mismatchFound = true
			if parent.Tree.Type == merkle.TreeSegment {
				result.Failures = append(result.Failures, Failure{Tree: child, Index: index, LogID: logID,
					Reason: "record commitment differs from independently authenticated finalized leaf"})
			} else if next, ok := plans[child]; ok {
				result.Failures = append(result.Failures, Failure{Tree: child, Index: index, Reason: "reconstructed subtree differs from finalized reference"})
				descend(next, reference)
			} else {
				result.Failures = append(result.Failures, Failure{Tree: child, Index: index, Unresolved: true, Reason: "selected subtree proof missing"})
			}
		}
		if !mismatchFound {
			result.Failures = append(result.Failures, Failure{Tree: parent.Tree, Unresolved: true,
				Reason: "selected children match; mismatch is in frontier or unavailable evidence"})
		}
	}
	global := merkle.TreeID{Type: merkle.TreeGlobal}
	plan, ok := plans[global]
	if !ok {
		result.Failures = append(result.Failures, Failure{Tree: global, Unresolved: true, Reason: "Global proof missing"})
		return result
	}
	descend(plan, trustedRoot)
	return result
}
