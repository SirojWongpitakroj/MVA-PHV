package system

import (
	"context"
	"fmt"
	"strconv"
	"sync"

	"uuid"

	"github.com/SirojWongpitakroj/mva-phv/internal/hmf"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
	"github.com/SirojWongpitakroj/mva-phv/internal/mpm"
	"github.com/SirojWongpitakroj/mva-phv/internal/phv"
)

// MemoryEvidence is an ephemeral implementation of MPM's write port and
// PHV's read port. It copies sealed nodes before HMF releases their builders.
type MemoryEvidence struct {
	mu          sync.RWMutex
	hmf         *hmf.HMF
	logs        map[mpm.Address]phv.EncryptedRecord
	logIDs      map[uuid.UUID]mpm.Address
	segments    map[merkle.TreeID]mpm.Segment
	segmentNode map[phv.NodeKey]phv.Node
	higherNode  map[phv.NodeKey]map[uint64]phv.Node
	shardCount  map[merkle.TreeID]map[uint64]int64
	candidates  map[uint64]mpm.Roots
}

func newMemoryEvidence(numRegions, shardsPerRegion int, tree *hmf.HMF) (*MemoryEvidence, error) {
	r := &MemoryEvidence{
		hmf: tree, logs: make(map[mpm.Address]phv.EncryptedRecord),
		logIDs: make(map[uuid.UUID]mpm.Address), segments: make(map[merkle.TreeID]mpm.Segment),
		segmentNode: make(map[phv.NodeKey]phv.Node), higherNode: make(map[phv.NodeKey]map[uint64]phv.Node),
		shardCount: make(map[merkle.TreeID]map[uint64]int64), candidates: make(map[uint64]mpm.Roots),
	}
	// HMF's initial Region and Global leaves represent empty Shards/Regions.
	// Keep those authenticated siblings for the first audit. Build uses HMF's
	// own tree implementation and does not duplicate its hashing rules.
	regionRoots := make([][32]byte, numRegions)
	for i := range regionRoots {
		region := hmf.NewRegionTree(strconv.Itoa(i), shardsPerRegion)
		nodes, err := region.Build(make([][32]byte, shardsPerRegion))
		if err != nil {
			return nil, err
		}
		regionRoots[i] = region.Root
		r.seed(region.TreeID, nodes)
	}
	global := hmf.NewGlobalTree(numRegions)
	nodes, err := global.Build(regionRoots)
	if err != nil {
		return nil, err
	}
	r.seed(global.TreeID, nodes)
	if tree == nil || tree.Finalized == nil || tree.Finalized.Global == nil || tree.Finalized.Global.Root != global.Root {
		return nil, fmt.Errorf("memory evidence: initial HMF root differs from seeded proof nodes")
	}
	return r, nil
}

func (r *MemoryEvidence) seed(id merkle.TreeID, nodes []merkle.MerkleNode) {
	for _, node := range nodes {
		key := phv.NodeKey{Tree: id, Level: node.Level, Index: node.Index}
		r.higherNode[key] = map[uint64]phv.Node{0: {Key: key, Hash: node.Hash}}
	}
}

func copyEncrypted(record phv.EncryptedRecord) phv.EncryptedRecord {
	record.Ciphertext = append([]byte(nil), record.Ciphertext...)
	record.Nonce = append([]byte(nil), record.Nonce...)
	record.Tag = append([]byte(nil), record.Tag...)
	record.AD = append([]byte(nil), record.AD...)
	return record
}

func (r *MemoryEvidence) PersistAccepted(ctx context.Context, record mpm.Record, _ mpm.MVAUpdate, _ mpm.HPBFUpdate) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r == nil || record.Log.LogID == (uuid.UUID{}) || record.Address.RegionID == "" ||
		record.Address.RegionID != record.Descriptor.RegionID {
		return fmt.Errorf("memory evidence: invalid accepted record")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.logIDs[record.Log.LogID]; exists {
		return fmt.Errorf("memory evidence: duplicate LogID %s", record.Log.LogID)
	}
	if _, exists := r.logs[record.Address]; exists {
		return fmt.Errorf("memory evidence: duplicate physical address %+v", record.Address)
	}
	r.logs[record.Address] = copyEncrypted(phv.EncryptedRecord{
		SelectedRecord: phv.SelectedRecord{LogID: record.Log.LogID, Descriptor: record.Descriptor,
			Address: record.Address, Locator: record.Locator},
		Ciphertext: record.Log.Ciphertext, Nonce: record.Log.Nonce, Tag: record.Log.Tag,
		AD: record.Log.AD, Digest: record.Log.Digest, HMFLeaf: record.HMFLeaf,
	})
	r.logIDs[record.Log.LogID] = record.Address
	return nil
}

func (r *MemoryEvidence) PersistSealed(ctx context.Context, segment mpm.Segment, nodes []merkle.MerkleNode) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r == nil || segment.ID.Type != merkle.TreeSegment || segment.LeafCount <= 0 ||
		segment.Height < 0 || len(nodes) == 0 {
		return fmt.Errorf("memory evidence: invalid sealed Segment")
	}
	newNodes := make(map[phv.NodeKey]phv.Node, len(nodes))
	leaves := make(map[int64]struct{})
	var top [32]byte
	topFound := false
	for _, node := range nodes {
		if node.Level < 0 || node.Index < 0 {
			return fmt.Errorf("memory evidence: invalid Segment node")
		}
		key := phv.NodeKey{Tree: segment.ID, Level: node.Level, Index: node.Index}
		if _, duplicate := newNodes[key]; duplicate {
			return fmt.Errorf("memory evidence: duplicate Segment node %v", key)
		}
		newNodes[key] = phv.Node{Key: key, Hash: node.Hash}
		if node.Level == 0 {
			leaves[node.Index] = struct{}{}
		}
		if node.Level == segment.Height && node.Index == 0 {
			top, topFound = node.Hash, true
		}
	}
	if int64(len(leaves)) != segment.LeafCount || !topFound {
		return fmt.Errorf("memory evidence: incomplete sealed Segment nodes")
	}
	root, err := hmf.RootHash(segment.ID, segment.LeafCount, top)
	if err != nil || root != segment.Root {
		return fmt.Errorf("memory evidence: sealed Segment root differs from nodes: %v", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, exists := r.segments[segment.ID]; exists {
		if old.Root != segment.Root || old.LeafCount != segment.LeafCount {
			return fmt.Errorf("memory evidence: conflicting sealed Segment")
		}
		for key, node := range newNodes {
			if r.segmentNode[key] != node {
				return fmt.Errorf("memory evidence: conflicting Segment node %v", key)
			}
		}
		return nil
	}
	for i := int64(0); i < segment.LeafCount; i++ {
		address := mpm.Address{RegionID: segment.ID.RegionID, ShardID: segment.ID.ShardID,
			SegmentID: segment.ID.SegmentID, LeafID: i}
		if _, exists := r.logs[address]; !exists {
			return fmt.Errorf("memory evidence: missing accepted log at %+v", address)
		}
	}
	r.segments[segment.ID] = segment
	for key, node := range newNodes {
		r.segmentNode[key] = node
	}
	return nil
}

func (r *MemoryEvidence) PersistCandidate(ctx context.Context, candidate mpm.Candidate) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r == nil || r.hmf == nil {
		return fmt.Errorf("memory evidence: HMF is missing")
	}
	evidence, err := r.hmf.CandidateEvidence(candidate.Epoch)
	if err != nil {
		return err
	}
	if evidence.GlobalRoot != candidate.Roots.HMF {
		return fmt.Errorf("memory evidence: candidate HMF root differs")
	}
	// A batched candidate can update the same path more than once. Its final
	// node for each structural position is the version retained for this epoch.
	finalNodes := make(map[phv.NodeKey]phv.Node)
	for _, change := range evidence.Nodes {
		key := phv.NodeKey{Tree: change.TreeID, Level: change.Node.Level, Index: change.Node.Index}
		finalNodes[key] = phv.Node{Key: key, Hash: change.Node.Hash, VersionEpoch: candidate.Epoch}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, segment := range candidate.Segments {
		if saved, ok := r.segments[segment.ID]; !ok || saved.Root != segment.Root {
			return fmt.Errorf("memory evidence: candidate Segment %v is not stored", segment.ID)
		}
	}
	if old, exists := r.candidates[candidate.Epoch]; exists && old != candidate.Roots {
		return fmt.Errorf("memory evidence: conflicting candidate for epoch %d", candidate.Epoch)
	}
	for key, node := range finalNodes {
		if versions := r.higherNode[key]; versions != nil {
			if old, exists := versions[candidate.Epoch]; exists && old.Hash != node.Hash {
				return fmt.Errorf("memory evidence: conflicting node at %v", key)
			}
		}
	}
	for _, shard := range evidence.Shards {
		if versions := r.shardCount[shard.TreeID]; versions != nil {
			if old, exists := versions[candidate.Epoch]; exists && old != shard.SegmentCount {
				return fmt.Errorf("memory evidence: conflicting Shard size")
			}
		}
	}
	for key, node := range finalNodes {
		if r.higherNode[key] == nil {
			r.higherNode[key] = make(map[uint64]phv.Node)
		}
		r.higherNode[key][candidate.Epoch] = node
	}
	for _, shard := range evidence.Shards {
		if r.shardCount[shard.TreeID] == nil {
			r.shardCount[shard.TreeID] = make(map[uint64]int64)
		}
		r.shardCount[shard.TreeID][candidate.Epoch] = shard.SegmentCount
	}
	r.candidates[candidate.Epoch] = candidate.Roots
	return nil
}

func (r *MemoryEvidence) LeafCount(ctx context.Context, epoch uint64, id merkle.TreeID) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if r == nil {
		return 0, fmt.Errorf("memory evidence: not initialized")
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	switch id.Type {
	case merkle.TreeSegment:
		if segment, exists := r.segments[id]; exists {
			return segment.LeafCount, nil
		}
	case merkle.TreeShard:
		var latest uint64
		var count int64
		found := false
		for version, value := range r.shardCount[id] {
			if version <= epoch && (!found || version > latest) {
				latest, count, found = version, value, true
			}
		}
		if found {
			return count, nil
		}
	}
	return 0, fmt.Errorf("memory evidence: no tree size for %v at epoch %d", id, epoch)
}

func (r *MemoryEvidence) FetchNodes(ctx context.Context, epoch uint64, id merkle.TreeID, positions []phv.NodeKey) ([]phv.Node, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r == nil {
		return nil, fmt.Errorf("memory evidence: not initialized")
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]phv.Node, 0, len(positions))
	for _, key := range positions {
		if key.Tree != id {
			return nil, fmt.Errorf("memory evidence: node outside requested tree")
		}
		if id.Type == merkle.TreeSegment {
			node, exists := r.segmentNode[key]
			if !exists {
				return nil, fmt.Errorf("memory evidence: missing Segment node %v", key)
			}
			result = append(result, node)
			continue
		}
		var latest uint64
		var selected phv.Node
		found := false
		for version, node := range r.higherNode[key] {
			if version <= epoch && (!found || version > latest) {
				latest, selected, found = version, node, true
			}
		}
		if !found {
			return nil, fmt.Errorf("memory evidence: missing hierarchy node %v at epoch %d", key, epoch)
		}
		result = append(result, selected)
	}
	return result, nil
}

func (r *MemoryEvidence) FetchLogs(ctx context.Context, segment merkle.TreeID, leaves []int64) ([]phv.EncryptedRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r == nil || segment.Type != merkle.TreeSegment {
		return nil, fmt.Errorf("memory evidence: invalid Segment")
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]phv.EncryptedRecord, 0, len(leaves))
	for _, leaf := range leaves {
		address := mpm.Address{RegionID: segment.RegionID, ShardID: segment.ShardID,
			SegmentID: segment.SegmentID, LeafID: leaf}
		log, exists := r.logs[address]
		if !exists {
			return nil, fmt.Errorf("memory evidence: missing log at %+v", address)
		}
		result = append(result, copyEncrypted(log))
	}
	return result, nil
}

// MemoryCheckpoints is a process-local append-only checkpoint store.
type MemoryCheckpoints struct {
	mu     sync.RWMutex
	values map[uint64][32]byte
}

func NewMemoryCheckpoints() *MemoryCheckpoints {
	return &MemoryCheckpoints{values: make(map[uint64][32]byte)}
}

func (s *MemoryCheckpoints) Commit(ctx context.Context, epoch uint64, checkpoint [32]byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil {
		return fmt.Errorf("memory checkpoint store: not initialized")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.values == nil {
		s.values = make(map[uint64][32]byte)
	}
	if old, exists := s.values[epoch]; exists {
		if old != checkpoint {
			return fmt.Errorf("memory checkpoint store: conflicting checkpoint for epoch %d", epoch)
		}
		return nil
	}
	s.values[epoch] = checkpoint
	return nil
}

func (s *MemoryCheckpoints) GetCheckpoint(ctx context.Context, epoch uint64) ([32]byte, error) {
	if err := ctx.Err(); err != nil {
		return [32]byte{}, err
	}
	if s == nil {
		return [32]byte{}, fmt.Errorf("memory checkpoint store: not initialized")
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	checkpoint, exists := s.values[epoch]
	if !exists {
		return [32]byte{}, fmt.Errorf("memory checkpoint store: epoch %d is not committed", epoch)
	}
	return checkpoint, nil
}
