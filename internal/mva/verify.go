package mva

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"reflect"
	"slices"
	"sort"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

// VerifyResolution authenticates both membership and completeness of the
// returned range against a finalized MVA root. It does not read MVA state.
func VerifyResolution(query LocatorQuery, regions []merkle.TreeID, values []*LocatorValue, proof *MVAProof, root [32]byte) error {
	if interval, ok := query.(AttrRangeQuery); ok && interval.EndTS.Before(interval.StartTS) {
		return fmt.Errorf("verify MVA: invalid time range")
	}
	if interval, ok := query.(TimeRangeQuery); ok && interval.EndTS.Before(interval.StartTS) {
		return fmt.Errorf("verify MVA: invalid time range")
	}
	if query == nil || proof == nil || len(proof.Levels) == 0 || len(proof.Levels[0]) == 0 ||
		len(proof.Levels[len(proof.Levels)-1]) != 1 || proof.Levels[len(proof.Levels)-1][0] != root {
		return fmt.Errorf("verify MVA: missing or wrong global root")
	}
	for level := 1; level < len(proof.Levels); level++ {
		children, parents := proof.Levels[level-1], proof.Levels[level]
		if len(parents) != (len(children)+1)/2 {
			return fmt.Errorf("verify MVA: invalid global width")
		}
		for i, hash := range parents {
			calculated := children[2*i]
			if 2*i+1 < len(children) {
				var node merkle.MerkleNode
				if err := node.ComputeInternalHash("MVAGLOBALINT", calculated, children[2*i+1]); err != nil {
					return err
				}
				calculated = node.Hash
			}
			if calculated != hash {
				return fmt.Errorf("verify MVA: invalid global node")
			}
		}
	}
	if len(proof.Regions) != len(regions) {
		return fmt.Errorf("verify MVA: missing or unexpected region proof")
	}
	seen := make(map[string]struct{}, len(regions))
	var matched []*LocatorValue
	for _, id := range regions {
		if id.Type != merkle.TreeRegion {
			return fmt.Errorf("verify MVA: invalid region ID")
		}
		if _, duplicate := seen[id.RegionID]; duplicate {
			return fmt.Errorf("verify MVA: duplicate region")
		}
		seen[id.RegionID] = struct{}{}
		p := proof.Regions[id.RegionID]
		if p == nil || p.RegionIndex < 0 || p.RegionIndex >= len(proof.Levels[0]) ||
			proof.Levels[0][p.RegionIndex] != p.RegionRoot || !reflect.DeepEqual(p.Query, query) {
			return fmt.Errorf("verify MVA: invalid region proof for %q", id.RegionID)
		}
		encoded, err := domain.Serialize([]byte("REGMVA"), id.RegionID, p.IDRoot[:], p.AttrRoot[:])
		if err != nil {
			return err
		}
		if sha256.Sum256(encoded) != p.RegionRoot {
			return fmt.Errorf("verify MVA: region root mismatch")
		}
		viewRoot := p.AttrRoot
		if query.isLogViewKey() {
			if p.View != ViewID {
				return fmt.Errorf("verify MVA: wrong view")
			}
			viewRoot = p.IDRoot
		} else if p.View != ViewAttribute {
			return fmt.Errorf("verify MVA: wrong view")
		}
		regionValues, err := verifyScan(id.RegionID, query, p.ScanPaths, viewRoot)
		if err != nil {
			return err
		}
		if err := verifyRegionBoundaries(id.RegionID, query, p, viewRoot); err != nil {
			return err
		}
		matched = append(matched, regionValues...)
	}
	if len(matched) != len(values) {
		return fmt.Errorf("verify MVA: incomplete result")
	}
	for i := range matched {
		if matched[i] == nil || values[i] == nil {
			return fmt.Errorf("verify MVA: nil locator value")
		}
		a, err := matched[i].Serialize()
		if err != nil {
			return err
		}
		b, err := values[i].Serialize()
		if err != nil {
			return err
		}
		if !bytes.Equal(a, b) {
			return fmt.Errorf("verify MVA: result differs from authenticated pages")
		}
	}
	return nil
}

func sameValue(a, b *LocatorValue) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	x, err := a.Serialize()
	if err != nil {
		return false
	}
	y, err := b.Serialize()
	return err == nil && bytes.Equal(x, y)
}

func verifyRegionBoundaries(rid string, query LocatorQuery, p *MVARegionProof, root [32]byte) error {
	type location struct{ page, index int }
	first, last := location{-1, -1}, location{-1, -1}
	var expectedPath []PageProof
	for pageIndex, path := range p.ScanPaths {
		for i, key := range path[0].Keys {
			if !Matches(query, key) {
				continue
			}
			if first.page < 0 {
				first = location{pageIndex, i}
			}
			last = location{pageIndex, i}
			expectedPath = append(expectedPath, path...)
		}
	}
	if !reflect.DeepEqual(expectedPath, p.Path) {
		return fmt.Errorf("verify MVA: matched paths differ from authenticated scan")
	}
	if isTimeOnly(query) {
		if p.LeftBoundary != nil || p.RightBoundary != nil || len(p.LeftBoundaryPath) > 0 || len(p.RightBoundaryPath) > 0 {
			return fmt.Errorf("verify MVA: time-only scan has boundary claims")
		}
		return nil
	}
	if first.page < 0 {
		if p.LeftBoundary != nil || p.RightBoundary != nil || len(p.LeftBoundaryPath) > 0 || len(p.RightBoundaryPath) > 0 {
			return fmt.Errorf("verify MVA: empty query has boundary evidence")
		}
		return nil
	}
	var left, right *LocatorValue
	var leftPath, rightPath []PageProof
	firstLeaf := p.ScanPaths[first.page][0]
	lastLeaf := p.ScanPaths[last.page][0]
	if first.index > 0 {
		left = firstLeaf.Values[first.index-1]
		leftPath = p.ScanPaths[first.page]
	} else if first.page > 0 {
		leftPath = p.ScanPaths[first.page-1]
		leaf := leftPath[0]
		if len(leaf.Values) > 0 {
			left = leaf.Values[len(leaf.Values)-1]
		}
	} else if len(p.LeftBoundaryPath) > 0 {
		leftPath = p.LeftBoundaryPath
		if err := verifyPagePath(rid, leftPath, root); err != nil {
			return err
		}
		if !adjacentPaths(leftPath, p.ScanPaths[0]) {
			return fmt.Errorf("verify MVA: left boundary is not adjacent")
		}
		leaf := leftPath[0]
		if len(leaf.Values) > 0 {
			left = leaf.Values[len(leaf.Values)-1]
		}
	} else {
		for _, step := range p.ScanPaths[0][1:] {
			if step.PathChildIndicdex[0] != 0 {
				return fmt.Errorf("verify MVA: missing left boundary")
			}
		}
	}
	if last.index+1 < len(lastLeaf.Values) {
		right = lastLeaf.Values[last.index+1]
		rightPath = p.ScanPaths[last.page]
	} else if last.page+1 < len(p.ScanPaths) {
		rightPath = p.ScanPaths[last.page+1]
		if len(rightPath[0].Values) > 0 {
			right = rightPath[0].Values[0]
		}
	}
	if !sameValue(left, p.LeftBoundary) || !sameValue(right, p.RightBoundary) {
		return fmt.Errorf("verify MVA: range boundary value differs")
	}
	if left == nil && len(p.LeftBoundaryPath) > 0 || right == nil && len(p.RightBoundaryPath) > 0 {
		return fmt.Errorf("verify MVA: extra boundary path")
	}
	if left != nil && (!reflect.DeepEqual(leftPath, p.LeftBoundaryPath) || query.Compare(left.LocatorKey) <= 0) {
		return fmt.Errorf("verify MVA: invalid left boundary path")
	}
	if right != nil && (!reflect.DeepEqual(rightPath, p.RightBoundaryPath) || query.Compare(right.LocatorKey) >= 0) {
		return fmt.Errorf("verify MVA: invalid right boundary path")
	}
	return nil
}

// VerifiedValues extracts the exact authenticated result from a proof. This
// lets an independent auditor verify scope without consulting the MVA tree.
func VerifiedValues(query LocatorQuery, regions []merkle.TreeID, proof *MVAProof, root [32]byte) ([]*LocatorValue, error) {
	if proof == nil {
		return nil, fmt.Errorf("verify MVA: missing proof")
	}
	var values []*LocatorValue
	for _, id := range regions {
		part := proof.Regions[id.RegionID]
		if part == nil {
			return nil, fmt.Errorf("verify MVA: missing region proof")
		}
		viewRoot := part.AttrRoot
		if query.isLogViewKey() {
			viewRoot = part.IDRoot
		}
		matched, err := verifyScan(id.RegionID, query, part.ScanPaths, viewRoot)
		if err != nil {
			return nil, err
		}
		values = append(values, matched...)
	}
	if err := VerifyResolution(query, regions, values, proof, root); err != nil {
		return nil, err
	}
	return values, nil
}

func verifyPagePath(rid string, path []PageProof, expected [32]byte) error {
	if len(path) == 0 || !path[0].IsLeaf {
		return fmt.Errorf("verify MVA: missing leaf path")
	}
	leaf := path[0]
	if len(leaf.Keys) != len(leaf.Values) {
		return fmt.Errorf("verify MVA: invalid leaf entries")
	}
	for i, value := range leaf.Values {
		if value == nil || value.LocatorKey == nil || value.RegionID != rid || leaf.Keys[i] == nil || leaf.Keys[i].Compare(value.LocatorKey) != 0 {
			return fmt.Errorf("verify MVA: leaf key/value mismatch")
		}
		if i > 0 && leaf.Keys[i-1].Compare(leaf.Keys[i]) > 0 {
			return fmt.Errorf("verify MVA: unsorted leaf")
		}
	}
	page := &Page{RegionID: rid, PageID: leaf.PageID, IsLeaf: true, Values: leaf.Values}
	hash, err := page.leafHash()
	if err != nil {
		return err
	}
	if expected == ([32]byte{}) && len(path) == 1 && len(leaf.Keys) == 0 {
		return nil
	}
	for _, step := range path[1:] {
		if step.IsLeaf || len(step.ChildHashes) != len(step.Keys)+1 || len(step.PathChildIndicdex) != 1 {
			return fmt.Errorf("verify MVA: malformed internal path")
		}
		index := step.PathChildIndicdex[0]
		if index < 0 || index >= len(step.ChildHashes) || step.ChildHashes[index] != hash {
			return fmt.Errorf("verify MVA: broken child link on page %d, child %d", step.PageID, index)
		}
		children := make([]*Page, len(step.ChildHashes))
		for i, h := range step.ChildHashes {
			children[i] = &Page{Hash: h}
		}
		parent := &Page{RegionID: rid, PageID: step.PageID, Keys: step.Keys, Children: children}
		hash, err = parent.internalHash()
		if err != nil {
			return err
		}
	}
	if hash != expected {
		return fmt.Errorf("verify MVA: page path differs from finalized view root")
	}
	return nil
}

// adjacentPaths checks that no complete leaf subtree can be hidden between
// two authenticated leaf paths.
func adjacentPaths(a, b []PageProof) bool {
	if len(a) != len(b) || len(a) < 2 {
		return false
	}
	for depth := len(a) - 1; depth >= 1; depth-- {
		ai, bi := a[depth].PathChildIndicdex[0], b[depth].PathChildIndicdex[0]
		if ai == bi {
			continue
		}
		if bi != ai+1 {
			return false
		}
		for lower := depth - 1; lower >= 1; lower-- {
			if a[lower].PathChildIndicdex[0] != len(a[lower].ChildHashes)-1 || b[lower].PathChildIndicdex[0] != 0 {
				return false
			}
		}
		return true
	}
	return false
}

func verifyScan(rid string, query LocatorQuery, paths [][]PageProof, viewRoot [32]byte) ([]*LocatorValue, error) {
	if len(paths) == 0 {
		return nil, fmt.Errorf("verify MVA: missing range scan")
	}
	for i, path := range paths {
		if err := verifyPagePath(rid, path, viewRoot); err != nil {
			return nil, err
		}
		if i > 0 && !adjacentPaths(paths[i-1], path) {
			return nil, fmt.Errorf("verify MVA: omitted or repeated leaf page")
		}
	}
	// The first leaf must be the one selected by the authenticated search
	// separators; a later starting point could hide matching records.
	first := paths[0]
	for _, step := range first[1:] {
		want := sort.Search(len(step.Keys), func(i int) bool { return query.Compare(step.Keys[i]) <= 0 })
		if step.PathChildIndicdex[0] != want {
			return nil, fmt.Errorf("verify MVA: range starts in wrong subtree")
		}
	}
	var values []*LocatorValue
	terminated := false
	for pageIndex, path := range paths {
		leaf := path[0]
		start := 0
		if pageIndex == 0 {
			start = sort.Search(len(leaf.Keys), func(i int) bool { return query.Compare(leaf.Keys[i]) <= 0 })
		}
		for i := start; i < len(leaf.Keys); i++ {
			order := query.Compare(leaf.Keys[i])
			if order < 0 {
				terminated = true
				break
			}
			if Matches(query, leaf.Keys[i]) {
				values = append(values, leaf.Values[i])
			}
		}
		if terminated {
			if pageIndex != len(paths)-1 {
				return nil, fmt.Errorf("verify MVA: scan continues after upper boundary")
			}
			break
		}
	}
	if !terminated {
		last := paths[len(paths)-1]
		for _, step := range last[1:] {
			if step.PathChildIndicdex[0] != len(step.ChildHashes)-1 {
				return nil, fmt.Errorf("verify MVA: scan stops before rightmost page")
			}
		}
	}
	return slices.Clone(values), nil
}
