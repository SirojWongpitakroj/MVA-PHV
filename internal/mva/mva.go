package mva

import (
	"fmt"
	"strconv"

	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

// NewMVA creates two empty locator views for each region and a global tree.
func NewMVA(numRegions int, locatorOrder int) (*MVA, error) {
	if numRegions <= 0 {
		return nil, fmt.Errorf("new MVA: numRegions must be positive")
	}

	mva := &MVA{
		TreeID:    merkle.TreeID{Type: merkle.TreeGlobal},
		LeafCount: int64(numRegions),
		Regions:   make([]*RegionMVA, numRegions),
	}
	for i := range mva.Regions {
		regionID := strconv.Itoa(i)
		idView := NewLocatorTree(locatorOrder, "id")
		attrView := NewLocatorTree(locatorOrder, "attribute")
		idView.RootPage.RegionID = regionID
		attrView.RootPage.RegionID = regionID
		mva.Regions[i] = &RegionMVA{
			Type: merkle.TreeRegion, RegionID: regionID,
			IDView:   idView,
			AttrView: attrView,
		}
	}
	for nodes := numRegions; ; nodes = (nodes + 1) / 2 {
		mva.Levels = append(mva.Levels, make([][32]byte, nodes))
		if nodes == 1 {
			break
		}
	}
	mva.Height = len(mva.Levels) - 1
	return mva, nil
}

// IngestLog inserts a log into both locator views of its physical region.
// The region must be among the HPBF candidate regions.
func (mva *MVA) IngestLog(candidateRegions []merkle.TreeID, logicalAddr attrKey, physicalAddr PhysicalAddress, leafHash [32]byte) (LocatorUpdate, LocatorUpdate, error) {
	if mva == nil {
		return LocatorUpdate{}, LocatorUpdate{}, fmt.Errorf("ingest MVA log: MVA is nil")
	}
	mva.mu.Lock()
	defer mva.mu.Unlock()

	for _, candidate := range candidateRegions {
		if candidate.RegionID != physicalAddr.RegionID {
			continue
		}
		if candidate.Type != merkle.TreeRegion {
			return LocatorUpdate{}, LocatorUpdate{}, fmt.Errorf("ingest MVA log: candidate %q is not a region", candidate.RegionID)
		}
		for _, region := range mva.Regions {
			if region != nil && region.TreeID.RegionID == candidate.RegionID {
				if region.TreeID.Type != merkle.TreeRegion {
					return LocatorUpdate{}, LocatorUpdate{}, fmt.Errorf("ingest MVA log: region %q has the wrong tree type", candidate.RegionID)
				}
				idUpdate, attrUpdate, err := region.insertLog(logicalAddr, physicalAddr, leafHash)
				if err != nil {
					return idUpdate, attrUpdate, fmt.Errorf("ingest MVA log in region %q: %w", candidate.RegionID, err)
				}
				return idUpdate, attrUpdate, nil
			}
		}
		return LocatorUpdate{}, LocatorUpdate{}, fmt.Errorf("ingest MVA log: region %q does not exist", candidate.RegionID)
	}
	return LocatorUpdate{}, LocatorUpdate{}, fmt.Errorf("ingest MVA log: physical region %q is not a candidate", physicalAddr.RegionID)
}

// Commitment hashes the current region roots into the global MVA Merkle root.
// Ingestion waits until the complete root has been published.
func (mva *MVA) Commitment() ([32]byte, error) {
	if mva == nil {
		return [32]byte{}, fmt.Errorf("commit MVA: MVA is nil")
	}
	mva.mu.Lock()
	defer mva.mu.Unlock()

	if len(mva.Regions) == 0 {
		return [32]byte{}, fmt.Errorf("commit MVA: no regions")
	}
	if mva.LeafCount != int64(len(mva.Regions)) {
		return [32]byte{}, fmt.Errorf("commit MVA: got %d regions, want %d", len(mva.Regions), mva.LeafCount)
	}

	// Region slice order is the canonical global leaf order.
	leaves := make([][32]byte, len(mva.Regions))
	regionSnapshots := make([]*RegionMVASnapshot, len(mva.Regions))
	regionsByID := make(map[string]*RegionMVASnapshot, len(mva.Regions))
	for index, region := range mva.Regions {
		if region == nil {
			return [32]byte{}, fmt.Errorf("commit MVA: region %d is nil", index)
		}
		snapshot, err := region.prepareSnapshot(mva.Epoch)
		if err != nil {
			return [32]byte{}, fmt.Errorf("commit MVA: region %q: %w", region.TreeID.RegionID, err)
		}
		if _, exists := regionsByID[snapshot.TreeID.RegionID]; exists {
			return [32]byte{}, fmt.Errorf("commit MVA: duplicate region %q", snapshot.TreeID.RegionID)
		}
		leaves[index] = snapshot.Root
		regionSnapshots[index] = snapshot
		regionsByID[snapshot.TreeID.RegionID] = snapshot
	}

	levels := [][][32]byte{leaves}
	for len(levels[len(levels)-1]) > 1 {
		children := levels[len(levels)-1]
		parents := make([][32]byte, (len(children)+1)/2)
		for index := range parents {
			left := children[2*index]
			if 2*index+1 == len(children) {
				parents[index] = left
				continue
			}
			var parent merkle.MerkleNode
			if err := parent.ComputeInternalHash("MVAGLOBALINT", left, children[2*index+1]); err != nil {
				return [32]byte{}, fmt.Errorf("commit MVA: global level %d node %d: %w", len(levels), index, err)
			}
			parents[index] = parent.Hash
		}
		levels = append(levels, parents)
	}

	root := levels[len(levels)-1][0]
	finalized := &MVASnapshot{
		MerkleTree: merkle.MerkleTree{
			TreeID: mva.TreeID, Root: root, LeafCount: mva.LeafCount, Height: len(levels) - 1,
		},
		Epoch: mva.Epoch, Regions: regionsByID, Levels: cloneHashLevels(levels),
	}
	// Publish only after every region and the global root were built.
	for index, region := range mva.Regions {
		region.mu.Lock()
		region.Finalized = regionSnapshots[index]
		region.mu.Unlock()
	}
	mva.Levels = levels
	mva.MerkleTree.Root = root
	mva.Finalized = finalized
	return root, nil
}

func cloneHashLevels(levels [][][32]byte) [][][32]byte {
	copyLevels := make([][][32]byte, len(levels))
	for level, hashes := range levels {
		copyLevels[level] = append([][32]byte(nil), hashes...)
	}
	return copyLevels
}

// Resolve searches only the supplied candidate regions, in candidate order.
// The proof snapshots global levels and keeps region proofs keyed by region ID.
func (mva *MVA) Resolve(query LocatorQuery, candidateRegions []merkle.TreeID) ([]*LocatorValue, *MVAProof, error) {
	if mva == nil {
		return nil, nil, fmt.Errorf("resolve MVA: MVA is nil")
	}
	if query == nil {
		return nil, nil, fmt.Errorf("resolve MVA: query is nil")
	}
	if _, batch := query.(LogIDBatchQuery); batch {
		return nil, nil, fmt.Errorf("resolve MVA: use ResolveLogIDBatch for a non-contiguous LogID set")
	}
	mva.mu.RLock()
	defer mva.mu.RUnlock()
	finalized := mva.Finalized
	if finalized == nil {
		return nil, nil, fmt.Errorf("resolve MVA: no finalized state")
	}

	var values []*LocatorValue
	proof := &MVAProof{
		Epoch:   finalized.Epoch,
		Levels:  cloneHashLevels(finalized.Levels),
		Regions: make(map[string]*MVARegionProof),
	}
	seen := make(map[string]bool, len(candidateRegions))
	regionIndexes := make(map[string]int, len(mva.Regions))
	for i, region := range mva.Regions {
		regionIndexes[region.RegionID] = i
	}
	for _, candidate := range candidateRegions {
		if candidate.Type != merkle.TreeRegion {
			return nil, nil, fmt.Errorf("resolve MVA: candidate %q is not a region", candidate.RegionID)
		}
		if seen[candidate.RegionID] {
			continue
		}
		seen[candidate.RegionID] = true
		region := finalized.Regions[candidate.RegionID]
		if region == nil {
			return nil, nil, fmt.Errorf("resolve MVA: region %q does not exist", candidate.RegionID)
		}
		matched, regionProof, err := region.resolve(query)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve MVA: region %q: %w", region.TreeID.RegionID, err)
		}
		regionProof.RegionIndex = regionIndexes[candidate.RegionID]
		values = append(values, matched...)
		proof.Regions[region.TreeID.RegionID] = regionProof
	}
	return values, proof, nil
}
