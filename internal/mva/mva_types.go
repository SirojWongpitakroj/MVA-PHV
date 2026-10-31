package mva

import (
	"sync"
	"time"
	"uuid"

	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

type MVA struct {
	merkle.MerkleTree
	Epoch     uint64
	Regions   []*RegionMVA
	Finalized *MVASnapshot
	Candidate *MVASnapshot
	mu        sync.RWMutex

	// Global Merkle tree over RegionMVA.Root values
	Levels [][][32]byte
}

// PendingRecord is one sealed log supplied by MPM for a candidate epoch.
type PendingRecord struct {
	LogID                            uuid.UUID
	RegionID, SiteID, DeviceID, Type string
	TS                               time.Time
	Address                          PhysicalAddress
	Locator                          [32]byte
}

type RegionMVA struct {
	merkle.TreeID // RID

	IDView    *LocatorTree
	AttrView  *LocatorTree
	Finalized *RegionMVASnapshot
	mu        sync.RWMutex

	// H(REGMVA || RID || IDView.Root || AttrView.Root)
	Root [32]byte
}

// MVASnapshot is the immutable global state published by a commitment.
type MVASnapshot struct {
	merkle.MerkleTree
	Epoch   uint64
	Regions map[string]*RegionMVASnapshot
	Levels  [][][32]byte
}

// RegionMVASnapshot holds the committed locator views for one region.
type RegionMVASnapshot struct {
	merkle.TreeID
	Epoch    uint64
	IDView   *LocatorTree
	AttrView *LocatorTree
	Root     [32]byte
}

type ViewType string

const (
	ViewID        ViewType = "id"
	ViewAttribute ViewType = "attribute"
)

// MVAProof carries the global Merkle levels and proofs for matched regions.
type MVAProof struct {
	Epoch   uint64
	Levels  [][][32]byte
	Regions map[string]*MVARegionProof
	Batch   []MVABatchItem
}

type MVABatchItem struct {
	Target  LogIDBatchTarget
	Regions []merkle.TreeID
	Proof   *MVAProof
}

type MVARegionProof struct {
	View                         ViewType
	Query                        LocatorQuery
	RegionIndex                  int
	IDRoot, AttrRoot, RegionRoot [32]byte
	// ScanPaths authenticate every consecutive leaf inspected by the range
	// search, including the insertion leaf for an empty result.
	ScanPaths [][]PageProof

	// authenticated B+ tree pages / nodes
	Path []PageProof

	// for range / attribute completeness
	LeftBoundary                        *LocatorValue
	RightBoundary                       *LocatorValue
	LeftBoundaryPath, RightBoundaryPath []PageProof
}
