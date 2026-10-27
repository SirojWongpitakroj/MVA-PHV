package hmf

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"slices"
	"strconv"
	"time"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

var ErrNoCandidateState = errors.New("HMF has no prepared candidate")

// NewHMF uses numeric region and shard IDs starting at zero.
func NewHMF(numRegions, shardsPerRegion, maxSegmentSize int, sealInterval time.Duration) (*HMF, error) {
	if numRegions <= 0 {
		return nil, fmt.Errorf("new HMF: numRegions must be positive")
	}
	ids := make([]string, numRegions)
	for i := range ids {
		ids[i] = strconv.Itoa(i)
	}
	return NewHMFWithConfig(HMFConfig{
		RegionIDs: ids, NumShardsPerRegion: shardsPerRegion, MaxSegmentLeaves: maxSegmentSize,
	}, sealInterval)
}

// NewHMFWithConfig preserves externally assigned region IDs.
func NewHMFWithConfig(config HMFConfig, sealInterval time.Duration) (*HMF, error) {
	if len(config.RegionIDs) == 0 || config.NumShardsPerRegion <= 0 ||
		config.MaxSegmentLeaves <= 0 || sealInterval <= 0 {
		return nil, fmt.Errorf("new HMF: regions, shards, segment size, and seal interval must be positive")
	}
	ids := slices.Clone(config.RegionIDs)
	slices.Sort(ids)
	for i, id := range ids {
		if id == "" || i > 0 && ids[i-1] == id {
			return nil, fmt.Errorf("new HMF: empty or repeated region ID %q", id)
		}
	}

	h := &HMF{
		MaxSegmentSize: config.MaxSegmentLeaves, SealInterval: sealInterval, regionIDs: ids,
		activeShards: make(map[merkle.TreeID]struct{}),
		reservations: make(map[merkle.TreeID]*Reservation),
		Working:      &HMFWorkingState{Global: NewGlobalTree(len(ids)), Regions: make(map[string]*HMFWorkingRegion, len(ids))},
		Finalized:    &HMFState{Global: NewGlobalTree(len(ids)), Regions: make(map[string]*HMFRegionState, len(ids))},
	}
	workingRoots := make([][32]byte, len(ids))
	finalizedRoots := make([][32]byte, len(ids))
	for index, id := range ids {
		workingRegion := &HMFWorkingRegion{
			Tree:   NewRegionTree(id, config.NumShardsPerRegion),
			Shards: make(map[int64]*HMFWorkingShard, config.NumShardsPerRegion),
		}
		finalizedRegion := &HMFRegionState{
			Tree:   NewRegionTree(id, config.NumShardsPerRegion),
			Shards: make(map[int64]*HMFShardState, config.NumShardsPerRegion),
		}
		for shardID := range config.NumShardsPerRegion {
			idNumber := int64(shardID)
			workingRegion.Shards[idNumber] = &HMFWorkingShard{Tree: NewShardTree(id, idNumber)}
			finalizedRegion.Shards[idNumber] = &HMFShardState{Tree: NewShardTree(id, idNumber)}
		}
		h.Working.Regions[id] = workingRegion
		h.Finalized.Regions[id] = finalizedRegion
		workingRoots[index] = workingRegion.Tree.Root
		finalizedRoots[index] = finalizedRegion.Tree.Root
	}
	if _, err := h.Working.Global.Build(workingRoots); err != nil {
		return nil, err
	}
	if _, err := h.Finalized.Global.Build(finalizedRoots); err != nil {
		return nil, err
	}
	return h, nil
}

// SelectShard maps a device to a configured Shard within an already selected Region.
func (h *HMF) SelectShard(rid, siteID, devID string) (int64, error) {
	if h == nil {
		return 0, fmt.Errorf("select HMF shard: HMF is nil")
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	region := h.Working.Regions[rid]
	if region == nil || region.Tree == nil {
		return 0, fmt.Errorf("select HMF shard: unknown region %q", rid)
	}
	count := region.Tree.numShards
	if count <= 0 || len(region.Shards) != count {
		return 0, fmt.Errorf("select HMF shard: invalid shards in region %q", rid)
	}
	encoded, err := domain.Serialize([]byte("HMF-SHARD-MAP"), rid, siteID, devID)
	if err != nil {
		return 0, fmt.Errorf("select HMF shard: encode device: %w", err)
	}
	digest := sha256.Sum256(encoded)
	sid := int64(binary.BigEndian.Uint64(digest[:8]) % uint64(count))
	if region.Shards[sid] == nil {
		return 0, fmt.Errorf("select HMF shard: shard %d is not configured in region %q", sid, rid)
	}
	return sid, nil
}

// Insert selects the physical Shard from Region, Site, and Device.
func (h *HMF) Insert(rid, siteID, devID string, commitment [32]byte, now time.Time) (int64, int64, int64, error) {
	sid, err := h.SelectShard(rid, siteID, devID)
	if err != nil {
		return 0, 0, 0, err
	}
	segmentID, leafID, err := h.insertIntoShard(rid, sid, commitment, now)
	if err != nil {
		return 0, 0, 0, err
	}
	return sid, segmentID, leafID, nil
}

// insertIntoShard stores a precomputed d_i in the selected physical Shard.
func (h *HMF) insertIntoShard(rid string, sid int64, commitment [32]byte, now time.Time) (int64, int64, error) {
	if h == nil {
		return 0, 0, fmt.Errorf("insert HMF: HMF is nil")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	region := h.Working.Regions[rid]
	if region == nil {
		return 0, 0, fmt.Errorf("insert HMF: unknown region %q", rid)
	}
	shard := region.Shards[sid]
	if shard == nil {
		return 0, 0, fmt.Errorf("insert HMF: unknown shard %d in region %q", sid, rid)
	}
	if h.reservations[shardTreeID(rid, sid)] != nil {
		return 0, 0, fmt.Errorf("insert HMF: Shard %q/%d has an outstanding address reservation", rid, sid)
	}
	if shard.Active != nil && now.Sub(shard.OpenedAt) >= h.SealInterval {
		if _, err := h.sealSegment(rid, sid, shard.Active.TreeID.SegmentID, now); err != nil {
			return 0, 0, err
		}
	}
	if shard.Active == nil {
		segment := NewSegmentTree(rid, sid, shard.nextSegID, h.MaxSegmentSize)
		segment.OpenedAt = now
		shard.nextSegID++
		shard.Active = segment
		h.activeShards[shardTreeID(rid, sid)] = struct{}{}
		shard.OpenedAt = now
	}
	segmentID := shard.Active.TreeID.SegmentID
	leafID := shard.Active.LeafCount
	if err := shard.Active.AppendCommitment(commitment); err != nil {
		return 0, 0, fmt.Errorf("insert HMF: append segment %d: %w", segmentID, err)
	}
	if shard.Active.LeafCount >= int64(h.MaxSegmentSize) {
		if _, err := h.sealSegment(rid, sid, segmentID, now); err != nil {
			return 0, 0, err
		}
	}
	return segmentID, leafID, nil
}

// sealSegment is called with h.mu held. It caches the root and queues it once.
func (h *HMF) sealSegment(rid string, sid, segmentID int64, now time.Time) (*SegmentTree, error) {
	region := h.Working.Regions[rid]
	if region == nil || region.Shards[sid] == nil {
		return nil, fmt.Errorf("seal HMF segment: unknown region/shard %q/%d", rid, sid)
	}
	shard := region.Shards[sid]
	segment := shard.Active
	if segment == nil || segment.TreeID.SegmentID != segmentID || segment.LeafCount == 0 {
		return nil, fmt.Errorf("seal HMF segment: segment %q/%d/%d is not active and nonempty", rid, sid, segmentID)
	}
	if _, err := segment.Seal(); err != nil {
		return nil, fmt.Errorf("seal HMF segment: %w", err)
	}
	segment.SealedAt = now
	if _, err := shard.Tree.Append(segment.Root); err != nil {
		return nil, fmt.Errorf("seal HMF segment: update working shard: %w", err)
	}
	if _, err := region.Tree.updateShardRoot(int(sid), shard.Tree.Root); err != nil {
		return nil, fmt.Errorf("seal HMF segment: update working region: %w", err)
	}
	regionIndex, found := slices.BinarySearch(h.regionIDs, rid)
	if !found {
		return nil, fmt.Errorf("seal HMF segment: region %q has no global position", rid)
	}
	if _, err := h.Working.Global.UpdateRegionRoot(regionIndex, region.Tree.Root); err != nil {
		return nil, fmt.Errorf("seal HMF segment: update working global: %w", err)
	}
	shard.Active = nil // The next segment is opened on the next insertion.
	delete(h.activeShards, shardTreeID(rid, sid))
	h.pendingSealed = append(h.pendingSealed, segment)
	return segment, nil
}

// SealExpired seals only nonempty active segments whose age reached the limit.
func (h *HMF) SealExpired(now time.Time) ([]*SegmentTree, error) {
	if h == nil {
		return nil, fmt.Errorf("seal expired HMF segments: HMF is nil")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	var sealed []*SegmentTree
	keys := make([]merkle.TreeID, 0, len(h.activeShards))
	for key := range h.activeShards {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, compareHMFShardIDs)
	for _, key := range keys {
		if h.reservations[key] != nil {
			continue
		}
		shard := h.Working.Regions[key.RegionID].Shards[key.ShardID]
		if shard.Active == nil || shard.Active.LeafCount == 0 || now.Sub(shard.OpenedAt) < h.SealInterval {
			continue
		}
		segment, err := h.sealSegment(key.RegionID, key.ShardID, shard.Active.TreeID.SegmentID, now)
		if err != nil {
			return sealed, err
		}
		sealed = append(sealed, segment)
	}
	return sealed, nil
}

func shardTreeID(rid string, sid int64) merkle.TreeID {
	return merkle.TreeID{Type: merkle.TreeShard, RegionID: rid, ShardID: sid}
}

func compareHMFShardIDs(a, b merkle.TreeID) int {
	if a.RegionID < b.RegionID {
		return -1
	}
	if a.RegionID > b.RegionID {
		return 1
	}
	if a.ShardID < b.ShardID {
		return -1
	}
	if a.ShardID > b.ShardID {
		return 1
	}
	return 0
}

// PendingSegments returns the sealed trees awaiting promotion.
func (h *HMF) PendingSegments() []*SegmentTree {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return slices.Clone(h.pendingSealed)
}

// PendingSegmentNodes returns the sealed nodes for external proof storage.
func (h *HMF) PendingSegmentNodes(id merkle.TreeID) ([]merkle.MerkleNode, error) {
	if h == nil {
		return nil, fmt.Errorf("pending HMF segment nodes: HMF is nil")
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, segment := range h.pendingSealed {
		if segment.TreeID != id {
			continue
		}
		if segment.builder == nil {
			return nil, fmt.Errorf("pending HMF segment nodes: segment %v was already released", id)
		}
		var nodes []merkle.MerkleNode
		for _, level := range segment.levels {
			nodes = append(nodes, level...)
		}
		return nodes, nil
	}
	return nil, fmt.Errorf("pending HMF segment nodes: unknown segment %v", id)
}

// AcknowledgeSegmentPersisted releases proof nodes after the caller stores them.
func (h *HMF) AcknowledgeSegmentPersisted(id merkle.TreeID) error {
	if h == nil {
		return fmt.Errorf("acknowledge HMF segment: HMF is nil")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, segment := range h.pendingSealed {
		if segment.TreeID != id {
			continue
		}
		if !segment.Sealed {
			return fmt.Errorf("acknowledge HMF segment: segment %v is not sealed", id)
		}
		segment.builder = nil
		segment.persisted = true
		return nil
	}
	return fmt.Errorf("acknowledge HMF segment: unknown segment %v", id)
}

func cloneShardTree(tree *ShardTree) *ShardTree {
	cloned := *tree
	metadata := *tree.MerkleTree
	cloned.MerkleTree = &metadata
	cloned.frontiers = slices.Clone(tree.frontiers)
	return &cloned
}

func cloneRegionState(region *HMFRegionState) *HMFRegionState {
	cloned := *region
	tree := *region.Tree
	metadata := *tree.MerkleTree
	tree.MerkleTree = &metadata
	cloned.Tree = &tree
	cloned.Shards = make(map[int64]*HMFShardState, len(region.Shards))
	for id, shard := range region.Shards {
		cloned.Shards[id] = shard
	}
	cloned.nodes = slices.Clone(region.nodes)
	return &cloned
}

func cloneFinalizedState(state *HMFState, epoch uint64) *HMFState {
	cloned := *state
	cloned.Epoch = epoch
	tree := *state.Global
	metadata := *tree.MerkleTree
	tree.MerkleTree = &metadata
	cloned.Global = &tree
	cloned.Regions = make(map[string]*HMFRegionState, len(state.Regions))
	for id, region := range state.Regions {
		cloned.Regions[id] = region
	}
	cloned.nodes = slices.Clone(state.nodes)
	return &cloned
}

func hmfNodeAt(base []merkle.MerkleNode, override *hmfSparseNode, index int) merkle.MerkleNode {
	depth := bits.Len(uint(len(base) - 1))
	for depth > 0 && override != nil {
		depth--
		if index&(1<<depth) == 0 {
			override = override.left
		} else {
			override = override.right
		}
	}
	if override != nil && override.value != nil {
		return *override.value
	}
	return base[index]
}

func hmfPutNode(root *hmfSparseNode, depth, index int, value merkle.MerkleNode) *hmfSparseNode {
	var node hmfSparseNode
	if root != nil {
		node = *root
	}
	if depth == 0 {
		node.value = &value
		return &node
	}
	depth--
	if index&(1<<depth) == 0 {
		node.left = hmfPutNode(node.left, depth, index, value)
	} else {
		node.right = hmfPutNode(node.right, depth, index, value)
	}
	return &node
}

func hmfLevelNode(levels [][]merkle.MerkleNode, overrides []*hmfSparseNode, level, index int) merkle.MerkleNode {
	var override *hmfSparseNode
	if level < len(overrides) {
		override = overrides[level]
	}
	return hmfNodeAt(levels[level], override, index)
}

func hmfSetLevelNode(levels [][]merkle.MerkleNode, overrides *[]*hmfSparseNode, value merkle.MerkleNode) {
	if len(*overrides) == 0 {
		*overrides = make([]*hmfSparseNode, len(levels))
	}
	level, index := value.Level, int(value.Index)
	(*overrides)[level] = hmfPutNode((*overrides)[level], bits.Len(uint(len(levels[level])-1)), index, value)
}

// hmfUpdateRegionPath changes one shard leaf and only its authentication path.
func hmfUpdateRegionPath(region *HMFRegionState, shardIndex int, hash [32]byte) ([]merkle.MerkleNode, error) {
	levels := region.Tree.levels
	if shardIndex < 0 || shardIndex >= len(levels[0]) {
		return nil, fmt.Errorf("update finalized region: shard index %d out of range", shardIndex)
	}
	updates := []merkle.MerkleNode{{Level: 0, Index: int64(shardIndex), Hash: hash}}
	hmfSetLevelNode(levels, &region.nodes, updates[0])
	index := shardIndex
	for level := 1; level < len(levels); level++ {
		parentIndex := index / 2
		leftIndex := parentIndex * 2
		left := hmfLevelNode(levels, region.nodes, level-1, leftIndex)
		parent := merkle.MerkleNode{Level: level, Index: int64(parentIndex), Hash: left.Hash}
		if rightIndex := leftIndex + 1; rightIndex < len(levels[level-1]) {
			right := hmfLevelNode(levels, region.nodes, level-1, rightIndex)
			if err := parent.ComputeInternalHash("REGINT", left.Hash, right.Hash); err != nil {
				return nil, err
			}
		}
		hmfSetLevelNode(levels, &region.nodes, parent)
		updates = append(updates, parent)
		index = parentIndex
	}
	root := hmfLevelNode(levels, region.nodes, len(levels)-1, 0)
	return updates, region.Tree.setRoot(root.Hash)
}

// hmfUpdateGlobalPath changes one region leaf and only its authentication path.
func hmfUpdateGlobalPath(state *HMFState, regionIndex int, hash [32]byte) ([]merkle.MerkleNode, error) {
	levels := state.Global.levels
	if regionIndex < 0 || regionIndex >= len(levels[0]) {
		return nil, fmt.Errorf("update finalized global: region index %d out of range", regionIndex)
	}
	updates := []merkle.MerkleNode{{Level: 0, Index: int64(regionIndex), Hash: hash}}
	hmfSetLevelNode(levels, &state.nodes, updates[0])
	index := regionIndex
	for level := 1; level < len(levels); level++ {
		parentIndex := index / 2
		leftIndex := parentIndex * 2
		left := hmfLevelNode(levels, state.nodes, level-1, leftIndex)
		parent := merkle.MerkleNode{Level: level, Index: int64(parentIndex), Hash: left.Hash}
		if rightIndex := leftIndex + 1; rightIndex < len(levels[level-1]) {
			right := hmfLevelNode(levels, state.nodes, level-1, rightIndex)
			if err := parent.ComputeInternalHash("GLOBALINT", left.Hash, right.Hash); err != nil {
				return nil, err
			}
		}
		hmfSetLevelNode(levels, &state.nodes, parent)
		updates = append(updates, parent)
		index = parentIndex
	}
	root := hmfLevelNode(levels, state.nodes, len(levels)-1, 0)
	return updates, state.Global.setRoot(root.Hash)
}

// PrepareFinalization incorporates only currently pending sealed segments.
// The previous Finalized hierarchy remains untouched until promotion.
func (h *HMF) PrepareFinalization(epoch uint64) error {
	if h == nil {
		return fmt.Errorf("prepare HMF finalization: HMF is nil")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.Candidate != nil {
		if h.Candidate.Epoch == epoch {
			return nil // Retry the same prepared candidate after an anchor failure.
		}
		return fmt.Errorf("prepare HMF finalization: epoch %d candidate is still pending", h.Candidate.Epoch)
	}
	if epoch <= h.Finalized.Epoch {
		return fmt.Errorf("prepare HMF finalization: epoch %d is not newer than finalized epoch %d", epoch, h.Finalized.Epoch)
	}

	groups := make(map[merkle.TreeID][]*SegmentTree)
	for _, segment := range h.pendingSealed {
		if segment == nil {
			return fmt.Errorf("prepare HMF finalization: nil pending segment")
		}
		key := shardTreeID(segment.TreeID.RegionID, segment.TreeID.ShardID)
		groups[key] = append(groups[key], segment)
	}
	keys := make([]merkle.TreeID, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, compareHMFShardIDs)

	candidate := cloneFinalizedState(h.Finalized, epoch)
	var changes []HMFChangedNode
	dirtyRegions := make(map[string]struct{})
	for _, key := range keys {
		region := candidate.Regions[key.RegionID]
		if region == nil || region.Shards[key.ShardID] == nil {
			return fmt.Errorf("prepare HMF finalization: unknown region/shard %q/%d", key.RegionID, key.ShardID)
		}
		if _, dirty := dirtyRegions[key.RegionID]; !dirty {
			region = cloneRegionState(region)
			candidate.Regions[key.RegionID] = region
			dirtyRegions[key.RegionID] = struct{}{}
		}
		oldShard := region.Shards[key.ShardID]
		shard := &HMFShardState{Tree: cloneShardTree(oldShard.Tree)}
		segments := groups[key]
		slices.SortFunc(segments, func(a, b *SegmentTree) int {
			if a.TreeID.SegmentID < b.TreeID.SegmentID {
				return -1
			}
			if a.TreeID.SegmentID > b.TreeID.SegmentID {
				return 1
			}
			return 0
		})
		for _, segment := range segments {
			if segment.TreeID.Type != merkle.TreeSegment || !segment.Sealed ||
				segment.TreeID.SegmentID != shard.Tree.LeafCount {
				return fmt.Errorf("prepare HMF finalization: invalid pending segment %q/%d/%d", segment.TreeID.RegionID, segment.TreeID.ShardID, segment.TreeID.SegmentID)
			}
			updates, err := shard.Tree.Append(segment.Root)
			if err != nil {
				return fmt.Errorf("prepare HMF finalization: append segment %d: %w", segment.TreeID.SegmentID, err)
			}
			for _, node := range updates {
				changes = append(changes, HMFChangedNode{TreeID: key, Node: node})
			}
		}
		region.Shards[key.ShardID] = shard
		updates, err := hmfUpdateRegionPath(region, int(key.ShardID), shard.Tree.Root)
		if err != nil {
			return fmt.Errorf("prepare HMF finalization: update region %q: %w", key.RegionID, err)
		}
		for _, node := range updates {
			changes = append(changes, HMFChangedNode{TreeID: region.Tree.TreeID, Node: node})
		}
	}
	// Update Global only after all changed Region roots are available.
	changedIDs := make([]string, 0, len(dirtyRegions))
	for rid := range dirtyRegions {
		changedIDs = append(changedIDs, rid)
	}
	slices.Sort(changedIDs)
	for _, rid := range changedIDs {
		index, found := slices.BinarySearch(h.regionIDs, rid)
		if !found {
			return fmt.Errorf("prepare HMF finalization: unknown region %q", rid)
		}
		updates, err := hmfUpdateGlobalPath(candidate, index, candidate.Regions[rid].Tree.Root)
		if err != nil {
			return fmt.Errorf("prepare HMF finalization: update global region %q: %w", rid, err)
		}
		for _, node := range updates {
			changes = append(changes, HMFChangedNode{TreeID: candidate.Global.TreeID, Node: node})
		}
	}
	h.Candidate = candidate
	h.candidateChanges = changes
	h.candidatePending = len(h.pendingSealed)
	return nil
}

// Commitment returns the prepared candidate's already computed Global Root.
func (h *HMF) Commitment() ([32]byte, error) {
	if h == nil {
		return [32]byte{}, fmt.Errorf("HMF commitment: HMF is nil")
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.Candidate == nil {
		return [32]byte{}, ErrNoCandidateState
	}
	return h.Candidate.Global.Root, nil
}

// FinalizedRoot returns the root currently authoritative for audits.
func (h *HMF) FinalizedRoot() ([32]byte, error) {
	if h == nil {
		return [32]byte{}, fmt.Errorf("finalized HMF root: HMF is nil")
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.Finalized == nil {
		return [32]byte{}, fmt.Errorf("finalized HMF root: no finalized state")
	}
	return h.Finalized.Global.Root, nil
}

// CommitFinalization promotes a prepared candidate after external success.
func (h *HMF) ValidateFinalization(epoch uint64) error {
	if h == nil {
		return fmt.Errorf("validate HMF finalization: HMF is nil")
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.Candidate == nil {
		return ErrNoCandidateState
	}
	if h.Candidate.Epoch != epoch {
		return fmt.Errorf("validate HMF finalization: candidate epoch %d, got %d", h.Candidate.Epoch, epoch)
	}
	for _, segment := range h.pendingSealed[:h.candidatePending] {
		if !segment.persisted {
			return fmt.Errorf("validate HMF finalization: Segment %v is not persisted", segment.TreeID)
		}
	}
	return nil
}

func (h *HMF) CommitFinalization(epoch uint64) error {
	if h == nil {
		return fmt.Errorf("commit HMF finalization: HMF is nil")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.Candidate == nil {
		return ErrNoCandidateState
	}
	if h.Candidate.Epoch != epoch {
		return fmt.Errorf("commit HMF finalization: candidate epoch %d, got %d", h.Candidate.Epoch, epoch)
	}
	for _, segment := range h.pendingSealed[:h.candidatePending] {
		if !segment.persisted {
			return fmt.Errorf("commit HMF finalization: segment %v has not been persisted", segment.TreeID)
		}
	}
	h.Finalized = h.Candidate
	h.Candidate = nil
	h.candidateChanges = nil
	h.pendingSealed = slices.Clone(h.pendingSealed[h.candidatePending:])
	h.candidatePending = 0
	return nil
}
