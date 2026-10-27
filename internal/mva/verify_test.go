package mva

import (
	"slices"
	"testing"
	"time"

	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

func TestVerifyResolutionAuthenticatesRangeAndEmptyRegions(t *testing.T) {
	tree, err := NewMVA(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	region := merkle.TreeID{Type: merkle.TreeRegion, RegionID: "0"}
	for i := byte(1); i <= 12; i++ {
		key, address, locator := testMVALog(i, "0")
		if _, _, err := tree.IngestLog([]merkle.TreeID{region}, key, address, locator); err != nil {
			t.Fatal(err)
		}
	}
	root, err := tree.Commitment()
	if err != nil {
		t.Fatal(err)
	}
	query := AttrRangeQuery{SiteID: "site", DevID: "device", Type: "type", StartTS: time.Unix(3, 0), EndTS: time.Unix(9, 0)}
	regions := []merkle.TreeID{region, {Type: merkle.TreeRegion, RegionID: "1"}}
	values, proof, err := tree.Resolve(query, regions)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 7 || len(proof.Regions) != 2 || len(proof.Regions["0"].ScanPaths) < 2 {
		t.Fatalf("incomplete range fixture: values=%d proof=%+v", len(values), proof)
	}
	if err := VerifyResolution(query, regions, values, proof, root); err != nil {
		t.Fatal(err)
	}
	regionProof := proof.Regions["0"]
	left := regionProof.LeftBoundary
	if left == nil || len(regionProof.LeftBoundaryPath) == 0 {
		t.Fatal("missing authenticated left boundary")
	}
	regionProof.LeftBoundary = nil
	if err := VerifyResolution(query, regions, values, proof, root); err == nil {
		t.Fatal("accepted omitted left boundary")
	}
	regionProof.LeftBoundary = left
	boundaryPath := regionProof.LeftBoundaryPath
	regionProof.LeftBoundaryPath = nil
	if err := VerifyResolution(query, regions, values, proof, root); err == nil {
		t.Fatal("accepted unauthenticated boundary")
	}
	regionProof.LeftBoundaryPath = boundaryPath
	if err := VerifyResolution(query, regions, values[:len(values)-1], proof, root); err == nil {
		t.Fatal("accepted omitted range result")
	}
	changed := slices.Clone(values)
	copyValue := *changed[0]
	copyValue.LeafHash[0] ^= 1
	changed[0] = &copyValue
	if err := VerifyResolution(query, regions, changed, proof, root); err == nil {
		t.Fatal("accepted tampered membership")
	}
	missing := AttrRangeQuery{SiteID: "site", DevID: "device", Type: "type", StartTS: time.Unix(20, 0), EndTS: time.Unix(21, 0)}
	empty, emptyProof, err := tree.Resolve(missing, regions)
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 0 || VerifyResolution(missing, regions, empty, emptyProof, root) != nil {
		t.Fatal("authenticated empty range failed")
	}
	emptyProof.Regions["0"].ScanPaths = nil
	if err := VerifyResolution(missing, regions, empty, emptyProof, root); err == nil {
		t.Fatal("accepted empty result without search path")
	}
}

func TestVerifyResolutionRejectsOmittedLeafAndWrongRoot(t *testing.T) {
	tree, _ := NewMVA(1, 3)
	region := merkle.TreeID{Type: merkle.TreeRegion, RegionID: "0"}
	for i := byte(1); i <= 12; i++ {
		key, address, locator := testMVALog(i, "0")
		if _, _, err := tree.IngestLog([]merkle.TreeID{region}, key, address, locator); err != nil {
			t.Fatal(err)
		}
	}
	root, err := tree.Commitment()
	if err != nil {
		t.Fatal(err)
	}
	query := AttrRangeQuery{SiteID: "site", DevID: "device", Type: "type", StartTS: time.Unix(1, 0), EndTS: time.Unix(12, 0)}
	values, proof, err := tree.Resolve(query, []merkle.TreeID{region})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyResolution(query, []merkle.TreeID{region}, values, proof, root); err != nil {
		t.Fatal(err)
	}
	paths := proof.Regions["0"].ScanPaths
	proof.Regions["0"].ScanPaths = append(slices.Clone(paths[:1]), paths[2:]...)
	if err := VerifyResolution(query, []merkle.TreeID{region}, values, proof, root); err == nil {
		t.Fatal("accepted omitted authenticated leaf page")
	}
	proof.Regions["0"].ScanPaths = paths
	root[0] ^= 1
	if err := VerifyResolution(query, []merkle.TreeID{region}, values, proof, root); err == nil {
		t.Fatal("accepted wrong finalized root")
	}
}
