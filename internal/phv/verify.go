package phv

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"sort"
	"sync"
	"time"
	"uuid"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
	"github.com/SirojWongpitakroj/mva-phv/internal/hmf"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
	"github.com/SirojWongpitakroj/mva-phv/internal/mpm"
)

var ErrEvidence = errors.New("PHV: incomplete or invalid evidence")

type Verification struct {
	Valid          bool
	GlobalRoot     [32]byte
	TreeRoots      map[merkle.TreeID][32]byte
	Issues         []Failure
	HashOperations int
}

func sameSelected(a, b SelectedRecord) bool {
	if a.DescriptorFromLog {
		return a.LogID == b.LogID && a.Address == b.Address && a.Locator == b.Locator &&
			b.Descriptor.RegionID == a.Address.RegionID
	}
	return a.LogID == b.LogID && a.Address == b.Address && a.Locator == b.Locator &&
		a.Descriptor.RegionID == b.Descriptor.RegionID && a.Descriptor.SiteID == b.Descriptor.SiteID &&
		a.Descriptor.DeviceID == b.Descriptor.DeviceID && a.Descriptor.Type == b.Descriptor.Type &&
		a.Descriptor.TS.Equal(b.Descriptor.TS)
}

func recordHash(selected SelectedRecord, log EncryptedRecord) ([32]byte, []Failure, error) {
	issues := []Failure{}
	issue := func(reason string) {
		issues = append(issues, Failure{Tree: merkle.TreeID{Type: merkle.TreeSegment, RegionID: selected.Address.RegionID,
			ShardID: selected.Address.ShardID, SegmentID: selected.Address.SegmentID}, Index: selected.Address.LeafID, LogID: selected.LogID, Reason: reason})
	}
	if !sameSelected(selected, log.SelectedRecord) {
		issue("returned log identity, descriptor, address, or locator differs from MVA")
	}
	descriptor := selected.Descriptor
	if selected.DescriptorFromLog {
		var tag, region, site, device, typ string
		var logID uuid.UUID
		var timestamp time.Time
		if err := domain.Deserialize(log.AD, &tag, &logID, &region, &site, &device, &typ, &timestamp); err != nil || tag != "MVA-PHV:LOG:V1" || logID != selected.LogID {
			issue("encrypted log associated data is malformed or has a different LogID")
		} else {
			descriptor = mpm.Descriptor{RegionID: region, SiteID: site, DeviceID: device, Type: typ, TS: timestamp}
		}
	}
	locator, err := (mpm.CanonicalLocator{}).CommitLocator(selected.LogID, descriptor, selected.Address)
	if err != nil {
		return [32]byte{}, nil, err
	}
	if locator != selected.Locator {
		issue("MVA locator commitment differs from canonical descriptor and address")
	}
	ad, err := domain.Serialize("MVA-PHV:LOG:V1", selected.LogID, descriptor.RegionID,
		descriptor.SiteID, descriptor.DeviceID, descriptor.Type, descriptor.TS.UTC())
	if err != nil {
		return [32]byte{}, nil, err
	}
	if !bytes.Equal(ad, log.AD) {
		issue("encrypted log associated data differs from authenticated descriptor")
	}
	content := make([]byte, 0, len(log.Nonce)+len(log.Ciphertext)+len(log.Tag))
	content = append(content, log.Nonce...)
	content = append(content, log.Ciphertext...)
	content = append(content, log.Tag...)
	digest := sha256.Sum256(content)
	if digest != log.Digest {
		issue("encrypted log digest differs from stored digest")
	}
	preimage, err := domain.Serialize([]byte("LOG"), selected.LogID, selected.Locator[:], digest[:])
	if err != nil {
		return [32]byte{}, nil, err
	}
	leaf := sha256.Sum256(preimage)
	if leaf != log.HMFLeaf {
		issue("reconstructed HMF leaf differs from stored leaf")
	}
	return leaf, issues, nil
}

func verifyTreePlan(plan TreePlan, evidence map[NodeKey][32]byte, leaves map[int64][32]byte) ([32]byte, error) {
	root, _, err := verifyTreePlanCount(plan, evidence, leaves)
	return root, err
}

func verifyTreePlanCount(plan TreePlan, evidence map[NodeKey][32]byte, leaves map[int64][32]byte) ([32]byte, int, error) {
	hashes := 0
	if len(leaves) != len(plan.Selected) {
		return [32]byte{}, hashes, fmt.Errorf("%w: tree %v selected leaves missing", ErrEvidence, plan.Tree)
	}
	current := make(map[int64][32]byte, len(leaves))
	for _, index := range plan.Selected {
		hash, ok := leaves[index]
		if !ok {
			return [32]byte{}, hashes, fmt.Errorf("%w: tree %v leaf %d missing", ErrEvidence, plan.Tree, index)
		}
		current[index] = hash
	}
	width := plan.LeafCount
	for level := 0; width > 1; level++ {
		indexes := make([]int64, 0, len(current))
		for index := range current {
			indexes = append(indexes, index)
		}
		slices.Sort(indexes)
		next := make(map[int64][32]byte, len(indexes))
		for _, index := range indexes {
			parent := index / 2
			if _, done := next[parent]; done {
				continue
			}
			leftIndex := parent * 2
			left, ok := current[leftIndex]
			if !ok {
				left, ok = evidence[NodeKey{Tree: plan.Tree, Level: level, Index: leftIndex}]
			}
			if !ok {
				return [32]byte{}, hashes, fmt.Errorf("%w: missing left node %v/%d/%d", ErrEvidence, plan.Tree, level, leftIndex)
			}
			if leftIndex+1 >= width {
				next[parent] = left // HMF carries the odd node unchanged.
				continue
			}
			rightIndex := leftIndex + 1
			right, ok := current[rightIndex]
			if !ok {
				right, ok = evidence[NodeKey{Tree: plan.Tree, Level: level, Index: rightIndex}]
			}
			if !ok {
				return [32]byte{}, hashes, fmt.Errorf("%w: missing right node %v/%d/%d", ErrEvidence, plan.Tree, level, rightIndex)
			}
			parentHash, err := hmf.InternalHash(plan.Tree.Type, left, right)
			if err != nil {
				return [32]byte{}, hashes, err
			}
			hashes++
			next[parent] = parentHash
		}
		current = next
		width = (width + 1) / 2
	}
	if len(current) != 1 {
		return [32]byte{}, hashes, fmt.Errorf("%w: tree %v has no top", ErrEvidence, plan.Tree)
	}
	root, err := hmf.RootHash(plan.Tree, plan.LeafCount, current[0])
	if err == nil {
		hashes++
	}
	return root, hashes, err
}

// VerifyHMF checks a complete, self-contained HMF multiproof. Missing or
// excess evidence is an error; a fully reconstructed wrong root is an
// integrity result (Valid=false), never a retrieval error.
func VerifyHMF(proof Proof, trustedRoot [32]byte) (Verification, error) {
	result := Verification{TreeRoots: make(map[merkle.TreeID][32]byte)}
	if len(proof.Selected) == 0 {
		return result, fmt.Errorf("%w: empty HMF selection", ErrEvidence)
	}
	ids, err := proof.Topology.orderedRegions()
	if err != nil {
		return result, err
	}
	if proof.Root != trustedRoot || proof.Roots.HMF != trustedRoot {
		return result, fmt.Errorf("%w: proof declares a different trusted root", ErrEvidence)
	}
	regionIndexes := make(map[string]int64, len(ids))
	for i, id := range ids {
		regionIndexes[id] = int64(i)
	}
	wanted := make(map[merkle.TreeID][]int64)
	selected := make(map[mpm.Address]SelectedRecord, len(proof.Selected))
	for _, record := range proof.Selected {
		a := record.Address
		if _, ok := selected[a]; ok {
			return result, fmt.Errorf("%w: duplicate selected address", ErrEvidence)
		}
		index, ok := regionIndexes[a.RegionID]
		if !ok || a.ShardID < 0 || a.ShardID >= int64(proof.Topology.ShardsPerRegion) || a.SegmentID < 0 || a.LeafID < 0 {
			return result, fmt.Errorf("%w: invalid selected address", ErrEvidence)
		}
		selected[a] = record
		wanted[merkle.TreeID{Type: merkle.TreeSegment, RegionID: a.RegionID, ShardID: a.ShardID, SegmentID: a.SegmentID}] = append(wanted[merkle.TreeID{Type: merkle.TreeSegment, RegionID: a.RegionID, ShardID: a.ShardID, SegmentID: a.SegmentID}], a.LeafID)
		wanted[merkle.TreeID{Type: merkle.TreeShard, RegionID: a.RegionID, ShardID: a.ShardID}] = append(wanted[merkle.TreeID{Type: merkle.TreeShard, RegionID: a.RegionID, ShardID: a.ShardID}], a.SegmentID)
		wanted[merkle.TreeID{Type: merkle.TreeRegion, RegionID: a.RegionID}] = append(wanted[merkle.TreeID{Type: merkle.TreeRegion, RegionID: a.RegionID}], a.ShardID)
		wanted[merkle.TreeID{Type: merkle.TreeGlobal}] = append(wanted[merkle.TreeID{Type: merkle.TreeGlobal}], index)
	}
	if len(proof.Trees) != len(wanted) {
		return result, fmt.Errorf("%w: HMF tree plan is incomplete", ErrEvidence)
	}
	frontier := make(map[NodeKey]struct{})
	lastRank := -1
	for _, plan := range proof.Trees {
		if treeRank(plan.Tree.Type) < lastRank {
			return result, fmt.Errorf("%w: tree plan order", ErrEvidence)
		}
		lastRank = treeRank(plan.Tree.Type)
		indexes, ok := wanted[plan.Tree]
		if !ok {
			return result, fmt.Errorf("%w: unexpected tree plan", ErrEvidence)
		}
		if plan.Tree.Type == merkle.TreeGlobal && plan.LeafCount != int64(len(ids)) ||
			plan.Tree.Type == merkle.TreeRegion && plan.LeafCount != int64(proof.Topology.ShardsPerRegion) {
			return result, fmt.Errorf("%w: configured tree size differs", ErrEvidence)
		}
		expected, _, err := Frontier(plan.Tree, plan.LeafCount, indexes)
		if err != nil {
			return result, err
		}
		if !slices.Equal(expected.Selected, plan.Selected) || !slices.Equal(expected.Frontier, plan.Frontier) {
			return result, fmt.Errorf("%w: nonminimal or incorrect frontier", ErrEvidence)
		}
		for _, key := range plan.Frontier {
			if _, duplicate := frontier[key]; duplicate {
				return result, fmt.Errorf("%w: duplicate planned node", ErrEvidence)
			}
			frontier[key] = struct{}{}
		}
		delete(wanted, plan.Tree)
	}
	evidence := make(map[NodeKey][32]byte, len(proof.Nodes))
	for _, node := range proof.Nodes {
		if _, ok := frontier[node.Key]; !ok {
			return result, fmt.Errorf("%w: unexpected node %v", ErrEvidence, node.Key)
		}
		if _, duplicate := evidence[node.Key]; duplicate {
			return result, fmt.Errorf("%w: duplicate node %v", ErrEvidence, node.Key)
		}
		if node.Key.Tree.Type != merkle.TreeSegment && node.VersionEpoch > proof.Epoch {
			return result, fmt.Errorf("%w: future hierarchy node", ErrEvidence)
		}
		evidence[node.Key] = node.Hash
	}
	if len(evidence) != len(frontier) {
		return result, fmt.Errorf("%w: missing planned nodes", ErrEvidence)
	}
	logs := make(map[mpm.Address]EncryptedRecord, len(proof.Logs))
	for _, log := range proof.Logs {
		if _, ok := selected[log.Address]; !ok {
			return result, fmt.Errorf("%w: unexpected log address", ErrEvidence)
		}
		if _, duplicate := logs[log.Address]; duplicate {
			return result, fmt.Errorf("%w: duplicate log", ErrEvidence)
		}
		logs[log.Address] = log
	}
	if len(logs) != len(selected) {
		return result, fmt.Errorf("%w: missing selected logs", ErrEvidence)
	}
	leafHashes := make(map[merkle.TreeID]map[int64][32]byte)
	for address, record := range selected {
		log := logs[address]
		hash, issues, err := recordHash(record, log)
		if err != nil {
			return result, err
		}
		result.Issues = append(result.Issues, issues...)
		key := merkle.TreeID{Type: merkle.TreeSegment, RegionID: address.RegionID, ShardID: address.ShardID, SegmentID: address.SegmentID}
		if leafHashes[key] == nil {
			leafHashes[key] = make(map[int64][32]byte)
		}
		leafHashes[key][address.LeafID] = hash
	}
	type treeResult struct {
		root   [32]byte
		hashes int
		err    error
	}
	for rank := 0; rank < 4; rank++ {
		var plans []TreePlan
		for _, plan := range proof.Trees {
			if treeRank(plan.Tree.Type) == rank {
				plans = append(plans, plan)
			}
		}
		computed := make([]treeResult, len(plans))
		limit := make(chan struct{}, min(8, runtime.GOMAXPROCS(0)))
		var wg sync.WaitGroup
		for i, plan := range plans {
			limit <- struct{}{}
			wg.Add(1)
			go func(i int, plan TreePlan) {
				defer wg.Done()
				defer func() { <-limit }()
				computed[i].root, computed[i].hashes, computed[i].err = verifyTreePlanCount(plan, evidence, leafHashes[plan.Tree])
			}(i, plan)
		}
		wg.Wait()
		for i, plan := range plans {
			computedTree := computed[i]
			if computedTree.err != nil {
				return result, computedTree.err
			}
			root := computedTree.root
			result.HashOperations += computedTree.hashes
			result.TreeRoots[plan.Tree] = root
			var parent merkle.TreeID
			var index int64
			switch plan.Tree.Type {
			case merkle.TreeSegment:
				parent, index = merkle.TreeID{Type: merkle.TreeShard, RegionID: plan.Tree.RegionID, ShardID: plan.Tree.ShardID}, plan.Tree.SegmentID
			case merkle.TreeShard:
				parent, index = merkle.TreeID{Type: merkle.TreeRegion, RegionID: plan.Tree.RegionID}, plan.Tree.ShardID
			case merkle.TreeRegion:
				parent, index = merkle.TreeID{Type: merkle.TreeGlobal}, regionIndexes[plan.Tree.RegionID]
			case merkle.TreeGlobal:
				result.GlobalRoot = root
			}
			if plan.Tree.Type != merkle.TreeGlobal {
				if leafHashes[parent] == nil {
					leafHashes[parent] = make(map[int64][32]byte)
				}
				leafHashes[parent][index] = root
			}
		}
	}
	result.Valid = result.GlobalRoot == trustedRoot && len(result.Issues) == 0
	sort.Slice(result.Issues, func(i, j int) bool {
		a, b := result.Issues[i], result.Issues[j]
		if a.Tree != b.Tree {
			return lessTree(a.Tree, b.Tree)
		}
		if a.Index != b.Index {
			return a.Index < b.Index
		}
		if a.LogID != b.LogID {
			return a.LogID.Compare(b.LogID) < 0
		}
		return a.Reason < b.Reason
	})
	return result, nil
}
