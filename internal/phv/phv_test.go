package phv

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/SirojWongpitakroj/mva-phv/internal/cloudprovider"
	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
	"github.com/SirojWongpitakroj/mva-phv/internal/hmf"
	"github.com/SirojWongpitakroj/mva-phv/internal/hpbf"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
	"github.com/SirojWongpitakroj/mva-phv/internal/mpm"
	"github.com/SirojWongpitakroj/mva-phv/internal/mva"
)

type proofRepo struct {
	mu        sync.Mutex
	counts    map[merkle.TreeID]int64
	nodes     map[NodeKey]Node
	logs      map[mpm.Address]EncryptedRecord
	requests  map[NodeKey]int
	missing   *NodeKey
	duplicate bool
	extra     *Node
	reverse   bool
	shuffle   bool
	rng       *rand.Rand
	delay     time.Duration
}

type partitionedProofRepo struct{ *proofRepo }

func (r partitionedProofRepo) NodePartition(key NodeKey) (string, error) {
	if key.Tree.Type == merkle.TreeSegment {
		return fmt.Sprintf("segment:%s:%d:%d", key.Tree.RegionID, key.Tree.ShardID, key.Tree.SegmentID), nil
	}
	return fmt.Sprintf("upper:%s:%s:%d:%d", key.Tree.Type, key.Tree.RegionID, key.Tree.ShardID, key.Level), nil
}

type sparseCountRepo struct{ calls int }

func (r *sparseCountRepo) LeafCount(_ context.Context, _ uint64, _ merkle.TreeID) (int64, error) {
	r.calls++
	return 10_000_000, nil
}
func (*sparseCountRepo) FetchNodes(context.Context, uint64, merkle.TreeID, []NodeKey) ([]Node, error) {
	panic("planning fetched proof nodes")
}

func newProofRepo() *proofRepo {
	return &proofRepo{counts: map[merkle.TreeID]int64{}, nodes: map[NodeKey]Node{}, logs: map[mpm.Address]EncryptedRecord{}, requests: map[NodeKey]int{}}
}
func (r *proofRepo) add(id merkle.TreeID, nodes []merkle.MerkleNode) {
	for _, node := range nodes {
		r.nodes[NodeKey{Tree: id, Level: node.Level, Index: node.Index}] = Node{Key: NodeKey{Tree: id, Level: node.Level, Index: node.Index}, Hash: node.Hash, VersionEpoch: 1}
	}
}
func (r *proofRepo) LeafCount(_ context.Context, _ uint64, id merkle.TreeID) (int64, error) {
	count, ok := r.counts[id]
	if !ok {
		return 0, fmt.Errorf("missing size")
	}
	return count, nil
}
func (r *proofRepo) FetchNodes(_ context.Context, _ uint64, id merkle.TreeID, positions []NodeKey) ([]Node, error) {
	if r.delay > 0 {
		time.Sleep(r.delay)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var nodes []Node
	for _, key := range positions {
		if key.Tree != id {
			return nil, fmt.Errorf("wrong tree")
		}
		r.requests[key]++
		if r.missing != nil && *r.missing == key {
			continue
		}
		node, ok := r.nodes[key]
		if !ok {
			return nil, fmt.Errorf("missing node %v", key)
		}
		nodes = append(nodes, node)
	}
	if r.duplicate && len(nodes) > 0 {
		nodes = append(nodes, nodes[0])
	}
	if r.extra != nil {
		nodes = append(nodes, *r.extra)
	}
	if r.reverse {
		slices.Reverse(nodes)
	}
	if r.shuffle {
		r.rng.Shuffle(len(nodes), func(i, j int) { nodes[i], nodes[j] = nodes[j], nodes[i] })
	}
	return nodes, nil
}

// The test CP is a separate interface: audits request only authenticated
// LogIDs, while proofRepo's node methods model CLS.
func (r *proofRepo) GetCiphertexts(_ context.Context, region string, ids []uuid.UUID) ([]cloudprovider.Ciphertext, error) {
	if r.delay > 0 {
		time.Sleep(r.delay)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []cloudprovider.Ciphertext
	for _, id := range ids {
		for _, log := range r.logs {
			if log.LogID == id && log.Address.RegionID == region {
				out = append(out, cloudprovider.Ciphertext{LogID: log.LogID, Ciphertext: slices.Clone(log.Ciphertext), Nonce: slices.Clone(log.Nonce), Tag: slices.Clone(log.Tag), AD: slices.Clone(log.AD), Version: cloudprovider.EncryptionVersionAESGCM})
				break
			}
		}
	}
	if r.reverse {
		slices.Reverse(out)
	}
	return out, nil
}

type fixedRoots struct{ value mpm.Roots }

func (r fixedRoots) Roots(context.Context, uint64) (mpm.Roots, error) { return r.value, nil }

type fixedResolver struct {
	records []SelectedRecord
	epoch   uint64
}

type hpbfHistory map[uint64]hpbf.HPBFProof

func (h hpbfHistory) LoadHPBFProof(_ context.Context, epoch uint64) (hpbf.HPBFProof, error) {
	proof, ok := h[epoch]
	if !ok {
		return hpbf.HPBFProof{}, fmt.Errorf("unpublished HPBF epoch")
	}
	return proof, nil
}

type mvaSnapshotHistory map[uint64]*mva.MVASnapshot

func (h mvaSnapshotHistory) GlobalLevels(_ context.Context, epoch uint64) ([][][32]byte, error) {
	s := h[epoch]
	if s == nil {
		return nil, fmt.Errorf("MVA epoch unavailable")
	}
	return s.Levels, nil
}
func (h mvaSnapshotHistory) RegionManifest(_ context.Context, epoch uint64) ([]mva.HistoricalRegion, error) {
	s := h[epoch]
	if s == nil {
		return nil, fmt.Errorf("MVA epoch unavailable")
	}
	var regions []mva.HistoricalRegion
	for i := 0; i < len(s.Regions); i++ {
		rid := fmt.Sprint(i)
		r := s.Regions[rid]
		regions = append(regions, mva.HistoricalRegion{RegionID: rid, Index: i, IDRoot: r.IDView.RootHash, AttrRoot: r.AttrView.RootHash, RegionRoot: r.Root})
	}
	return regions, nil
}
func (h mvaSnapshotHistory) view(epoch uint64, rid string, kind mva.ViewType) (*mva.LocatorTree, error) {
	s := h[epoch]
	if s == nil {
		return nil, fmt.Errorf("MVA epoch unavailable")
	}
	r := s.Regions[rid]
	if r == nil {
		return nil, fmt.Errorf("Region unavailable")
	}
	if kind == mva.ViewID {
		return r.IDView, nil
	}
	return r.AttrView, nil
}
func (h mvaSnapshotHistory) ViewState(_ context.Context, epoch uint64, rid string, kind mva.ViewType) (mva.HistoricalView, error) {
	v, err := h.view(epoch, rid, kind)
	if err != nil {
		return mva.HistoricalView{}, err
	}
	return mva.HistoricalView{RootPageID: v.RootPageID, RootHash: v.RootHash, VersionEpoch: epoch}, nil
}
func (h mvaSnapshotHistory) Page(_ context.Context, epoch uint64, rid string, kind mva.ViewType, id int64) (mva.HistoricalPage, error) {
	v, err := h.view(epoch, rid, kind)
	if err != nil {
		return mva.HistoricalPage{}, err
	}
	var found *mva.Page
	var visit func(*mva.Page)
	visit = func(p *mva.Page) {
		if p == nil || found != nil {
			return
		}
		if p.PageID == id {
			found = p
			return
		}
		for _, child := range p.Children {
			visit(child)
		}
	}
	visit(v.RootPage)
	if found == nil {
		return mva.HistoricalPage{}, fmt.Errorf("page unavailable")
	}
	p := mva.HistoricalPage{PageID: id, VersionEpoch: epoch, Hash: found.Hash, IsLeaf: found.IsLeaf, Keys: found.Keys, Values: found.Values}
	for _, child := range found.Children {
		p.ChildIDs = append(p.ChildIDs, child.PageID)
		p.ChildHashes = append(p.ChildHashes, child.Hash)
	}
	return p, nil
}

type fixedEvidence struct{ value mpm.Roots }

func (e fixedEvidence) RootTuple(context.Context, uint64) (mpm.Roots, error) { return e.value, nil }

type fixedCheckpoint struct{ value [32]byte }

func (s fixedCheckpoint) Commit(context.Context, uint64, [32]byte) error { return nil }
func (s fixedCheckpoint) GetCheckpoint(context.Context, uint64) ([32]byte, error) {
	return s.value, nil
}

type epochEvidence map[uint64]mpm.Roots

func (e epochEvidence) RootTuple(_ context.Context, epoch uint64) (mpm.Roots, error) {
	root, ok := e[epoch]
	if !ok {
		return mpm.Roots{}, fmt.Errorf("unpublished epoch")
	}
	return root, nil
}

type epochCheckpoints map[uint64][32]byte

func (e epochCheckpoints) Commit(context.Context, uint64, [32]byte) error {
	return fmt.Errorf("read only")
}
func (e epochCheckpoints) GetCheckpoint(_ context.Context, epoch uint64) ([32]byte, error) {
	checkpoint, ok := e[epoch]
	if !ok {
		return [32]byte{}, fmt.Errorf("unpublished epoch")
	}
	return checkpoint, nil
}

func (r fixedResolver) Resolve(_ context.Context, epoch uint64, _ mva.LocatorQuery, _ []merkle.TreeID, _ [32]byte) (Resolution, error) {
	return Resolution{Epoch: r.epoch, Records: slices.Clone(r.records), Proof: &mva.MVAProof{Epoch: epoch}}, nil
}

type fixture struct {
	repo     *proofRepo
	root     [32]byte
	records  []SelectedRecord
	topology Topology
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	repo := newProofRepo()
	topology := Topology{RegionIDs: []string{"0", "1"}, ShardsPerRegion: 2}
	var records []SelectedRecord
	segment := func(rid string, sid, segID int64, count int) *hmf.SegmentTree {
		seg := hmf.NewSegmentTree(rid, sid, segID, 8)
		for leaf := range count {
			id := uuid.UUID{byte(len(records) + 1)}
			desc := mpm.Descriptor{RegionID: rid, SiteID: "site", DeviceID: fmt.Sprintf("device-%d", len(records)), Type: "alarm", TS: time.Unix(int64(len(records)+1), 0).UTC()}
			addr := mpm.Address{RegionID: rid, ShardID: sid, SegmentID: segID, LeafID: int64(leaf)}
			locator, err := (mpm.CanonicalLocator{}).CommitLocator(id, desc, addr)
			if err != nil {
				t.Fatal(err)
			}
			nonce, cipher, tag := make([]byte, 12), []byte{byte(len(records) + 7)}, make([]byte, 16)
			nonce[0], nonce[1], tag[0] = 1, byte(leaf), 9
			content := append(append(slices.Clone(nonce), cipher...), tag...)
			digest := sha256.Sum256(content)
			ad, err := domain.Serialize("MVA-PHV:LOG:V1", id, desc.RegionID, desc.SiteID, desc.DeviceID, desc.Type, desc.TS.UTC())
			if err != nil {
				t.Fatal(err)
			}
			preimage, err := domain.Serialize([]byte("LOG"), id, locator[:], digest[:])
			if err != nil {
				t.Fatal(err)
			}
			leafHash := sha256.Sum256(preimage)
			if err := seg.AppendCommitment(leafHash); err != nil {
				t.Fatal(err)
			}
			record := SelectedRecord{LogID: id, Descriptor: desc, Address: addr, Locator: locator}
			records = append(records, record)
			repo.logs[addr] = EncryptedRecord{SelectedRecord: record, Ciphertext: cipher, Nonce: nonce, Tag: tag, AD: ad, Version: cloudprovider.EncryptionVersionAESGCM, Digest: digest, HMFLeaf: leafHash}
		}
		nodes, err := seg.Seal()
		if err != nil {
			t.Fatal(err)
		}
		repo.counts[seg.TreeID] = seg.LeafCount
		repo.add(seg.TreeID, nodes)
		return seg
	}
	segments := map[string]map[int64][]*hmf.SegmentTree{
		"0": {0: {segment("0", 0, 0, 3), segment("0", 0, 1, 2)}, 1: {segment("0", 1, 0, 1)}},
		"1": {0: {segment("1", 0, 0, 2)}},
	}
	regionRoots := make([][32]byte, 2)
	for ridx, rid := range []string{"0", "1"} {
		shardRoots := make([][32]byte, 2)
		for sid := int64(0); sid < 2; sid++ {
			shard := hmf.NewShardTree(rid, sid)
			for _, seg := range segments[rid][sid] {
				updates, err := shard.Append(seg.Root)
				if err != nil {
					t.Fatal(err)
				}
				repo.add(shard.TreeID, updates)
			}
			if len(segments[rid][sid]) > 0 {
				repo.counts[shard.TreeID] = shard.LeafCount
			}
			shardRoots[sid] = shard.Root
		}
		region := hmf.NewRegionTree(rid, 2)
		nodes, err := region.Build(shardRoots)
		if err != nil {
			t.Fatal(err)
		}
		repo.add(region.TreeID, nodes)
		regionRoots[ridx] = region.Root
	}
	global := hmf.NewGlobalTree(2)
	nodes, err := global.Build(regionRoots)
	if err != nil {
		t.Fatal(err)
	}
	repo.add(global.TreeID, nodes)
	return fixture{repo: repo, root: global.Root, records: records, topology: topology}
}

func TestFrontierIsMinimalAndStructural(t *testing.T) {
	id := merkle.TreeID{Type: merkle.TreeSegment, RegionID: "0", ShardID: 0, SegmentID: 0}
	plan, naive, err := Frontier(id, 8, []int64{2, 3})
	if err != nil {
		t.Fatal(err)
	}
	if naive <= len(plan.Frontier) || len(plan.Frontier) != 2 {
		t.Fatalf("naive=%d frontier=%v", naive, plan.Frontier)
	}
	odd, _, err := Frontier(id, 5, []int64{4})
	if err != nil || len(odd.Frontier) != 1 || odd.Frontier[0].Level != 2 {
		t.Fatalf("odd=%v error=%v", odd.Frontier, err)
	}
	separate, _, err := Frontier(id, 8, []int64{0, 4})
	if err != nil || len(separate.Frontier) != 4 {
		t.Fatalf("separate=%v error=%v", separate.Frontier, err)
	}
}

func TestClusteredMultiproofSavesMoreThanScattered(t *testing.T) {
	id := merkle.TreeID{Type: merkle.TreeSegment, RegionID: "0", ShardID: 0, SegmentID: 0}
	clustered := make([]int64, 64)
	scattered := make([]int64, 64)
	for i := range clustered {
		clustered[i] = int64(i)
		scattered[i] = int64(i * 16)
	}
	cluster, clusterNaive, err := Frontier(id, 1024, clustered)
	if err != nil {
		t.Fatal(err)
	}
	scatter, scatterNaive, err := Frontier(id, 1024, scattered)
	if err != nil {
		t.Fatal(err)
	}
	if len(cluster.Frontier) >= len(scatter.Frontier) ||
		len(cluster.Frontier) >= clusterNaive || len(scatter.Frontier) >= scatterNaive {
		t.Fatalf("64-leaf comparison cluster=%d/%d scatter=%d/%d", len(cluster.Frontier), clusterNaive, len(scatter.Frontier), scatterNaive)
	}
	if len(cluster.Frontier)*32 >= len(scatter.Frontier)*32 {
		t.Fatal("clustered proof did not save bytes")
	}
}

func TestAuditGroupsSelectedAddressesAtEveryHierarchyLevel(t *testing.T) {
	f := newFixture(t)
	for _, tc := range []struct {
		name    string
		indexes []int
		want    [4]int // Segment, Shard, Region, Global trees.
	}{
		{"one leaf", []int{0}, [4]int{1, 1, 1, 1}},
		{"same Segment", []int{0, 1}, [4]int{1, 1, 1, 1}},
		{"two Segments", []int{0, 3}, [4]int{2, 1, 1, 1}},
		{"two Shards", []int{0, 5}, [4]int{2, 2, 1, 1}},
		{"two Regions", []int{0, 6}, [4]int{2, 2, 2, 1}},
		{"clustered and scattered", []int{0, 1, 3, 5, 6}, [4]int{4, 3, 2, 1}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selected := make([]SelectedRecord, 0, len(tc.indexes))
			for _, i := range tc.indexes {
				selected = append(selected, f.records[i])
			}
			plan, err := BuildPlan(context.Background(), f.repo, 1, f.topology, selected)
			if err != nil {
				t.Fatal(err)
			}
			var counts [4]int
			for _, tree := range plan.Trees {
				counts[treeRank(tree.Tree.Type)]++
			}
			if counts != tc.want || len(plan.Selected) != len(selected) {
				t.Fatalf("tree counts=%v, selected=%d, want %v/%d", counts, len(plan.Selected), tc.want, len(selected))
			}
		})
	}
}

func TestBuildPlanPartitionsEveryFrontierNodeExactlyOnce(t *testing.T) {
	f := newFixture(t)
	repo := partitionedProofRepo{f.repo}
	selected := []SelectedRecord{f.records[0], f.records[3], f.records[6]}
	plan, err := BuildPlan(context.Background(), repo, 1, f.topology, selected)
	if err != nil {
		t.Fatal(err)
	}
	wanted := make(map[NodeKey]struct{})
	for _, tree := range plan.Trees {
		for _, key := range tree.Frontier {
			wanted[key] = struct{}{}
		}
	}
	seen := make(map[NodeKey]struct{})
	segments := make(map[merkle.TreeID]struct{})
	for _, group := range plan.Groups {
		if group.Tree.Type == merkle.TreeSegment && len(group.Leaves) > 0 {
			segments[group.Tree] = struct{}{}
		}
		for _, key := range group.Positions {
			partition, _ := repo.NodePartition(key)
			if partition != group.Partition || key.Tree != group.Tree {
				t.Fatalf("node %v assigned to wrong partition %q", key, group.Partition)
			}
			if _, duplicate := seen[key]; duplicate {
				t.Fatalf("duplicate planned node %v", key)
			}
			seen[key] = struct{}{}
		}
	}
	if len(seen) != len(wanted) || len(segments) != 3 {
		t.Fatalf("planned nodes=%d/%d Segment groups=%d", len(seen), len(wanted), len(segments))
	}
	for key := range wanted {
		if _, ok := seen[key]; !ok {
			t.Fatalf("missing node %v", key)
		}
	}
}

func TestPlanningTinyQueryInLargeForestIsSparse(t *testing.T) {
	repo := &sparseCountRepo{}
	record := SelectedRecord{Descriptor: mpm.Descriptor{RegionID: "0"}, Address: mpm.Address{RegionID: "0", ShardID: 1, SegmentID: 7_000_000, LeafID: 8_000_000}}
	plan, err := BuildPlan(context.Background(), repo, 4, Topology{RegionIDs: []string{"0", "1", "2", "3"}, ShardsPerRegion: 8}, []SelectedRecord{record})
	if err != nil {
		t.Fatal(err)
	}
	if repo.calls != 2 || len(plan.Selected) != 1 || plan.UniqueNodes > 60 || len(plan.Groups) > 4 {
		t.Fatalf("planning scaled with forest size: calls=%d plan=%+v", repo.calls, plan)
	}
}

func TestAuditSharedMultiproofAndLocalization(t *testing.T) {
	f := newFixture(t)
	f.repo.delay = time.Millisecond
	query := mva.AttrRangeQuery{SiteID: "site", DevID: "device-0", Type: "alarm", StartTS: time.Unix(0, 0), EndTS: time.Unix(100, 0)}
	selected := []SelectedRecord{f.records[0], f.records[1], f.records[3], f.records[6]}
	a := Auditor{Roots: fixedRoots{mpm.Roots{HMF: f.root}}, Resolver: fixedResolver{selected, 1}, Repository: f.repo, Ciphertexts: f.repo, Topology: f.topology, Workers: 4}
	result, err := a.Audit(context.Background(), Request{Epoch: 1, Query: query})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Verified || result.Metrics.UniqueNodes >= result.Metrics.NaiveNodes ||
		result.Metrics.HashOperations >= result.Metrics.NaiveHashOperations || result.Metrics.MaxConcurrent < 2 {
		t.Fatalf("verified=%v metrics=%+v", result.Verified, result.Metrics)
	}
	for key, count := range f.repo.requests {
		if count != 1 {
			t.Fatalf("node %v requested %d times", key, count)
		}
	}
	verification, err := VerifyHMF(result.Proof, f.root)
	if err != nil || !verification.Valid {
		t.Fatalf("independent HMF verify: %+v, %v", verification, err)
	}
	invalid := result.Proof
	invalid.Nodes = append(slices.Clone(result.Proof.Nodes), result.Proof.Nodes[0])
	if _, err := VerifyHMF(invalid, f.root); !errors.Is(err, ErrEvidence) {
		t.Fatalf("duplicate proof node error=%v", err)
	}
	f.repo.reverse = true
	reordered, err := a.Audit(context.Background(), Request{Epoch: 1, Query: query})
	if err != nil || !reordered.Verified || !reflect.DeepEqual(result.Proof.Nodes, reordered.Proof.Nodes) ||
		!reflect.DeepEqual(result.Proof.Logs, reordered.Proof.Logs) {
		t.Fatalf("repository order changed proof: %v", err)
	}
	reversedSelection := slices.Clone(selected)
	slices.Reverse(reversedSelection)
	a.Resolver = fixedResolver{reversedSelection, 1}
	reordered, err = a.Audit(context.Background(), Request{Epoch: 1, Query: query})
	if err != nil || !reordered.Verified || !reflect.DeepEqual(result.Proof.Selected, reordered.Proof.Selected) ||
		!reflect.DeepEqual(result.Proof.Trees, reordered.Proof.Trees) || !reflect.DeepEqual(result.Proof.Nodes, reordered.Proof.Nodes) {
		t.Fatalf("MVA return order changed structural proof: %v", err)
	}
	f.repo.reverse = false
	log := f.repo.logs[selected[0].Address]
	log.Ciphertext = []byte("tampered")
	content := append(append(slices.Clone(log.Nonce), log.Ciphertext...), log.Tag...)
	log.Digest = sha256.Sum256(content)
	f.repo.logs[selected[0].Address] = log
	result, err = a.Audit(context.Background(), Request{Epoch: 1, Query: query})
	if err != nil || result.Verified {
		t.Fatalf("altered log: verified=%v err=%v", result.Verified, err)
	}
	confirmed := false
	for _, failure := range result.Failures {
		if failure.LogID == selected[0].LogID && !failure.Unresolved {
			confirmed = true
		}
	}
	if !confirmed {
		t.Fatalf("record not localized: %+v", result.Failures)
	}
	for _, kind := range []merkle.TreeType{merkle.TreeRegion, merkle.TreeShard, merkle.TreeSegment} {
		found := false
		for _, failure := range result.Failures {
			if failure.Tree.Type == kind && !failure.Unresolved {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("localization did not descend through %s: %+v", kind, result.Failures)
		}
	}
	if result.Metrics.PrunedBranches == 0 {
		t.Fatal("localization did not prune matching query branches")
	}
}

func TestProofDeterministicAcrossOneHundredShuffledAudits(t *testing.T) {
	f := newFixture(t)
	f.repo.shuffle = true
	f.repo.rng = rand.New(rand.NewSource(51))
	f.repo.delay = time.Millisecond
	selected := []SelectedRecord{f.records[0], f.records[1], f.records[3], f.records[6]}
	selectionRNG := rand.New(rand.NewSource(77))
	query := mva.AttrRangeQuery{SiteID: "site", DevID: "device-0", Type: "alarm", StartTS: time.Unix(0, 0), EndTS: time.Unix(100, 0)}
	a := Auditor{Roots: fixedRoots{mpm.Roots{HMF: f.root}}, Repository: f.repo, Ciphertexts: f.repo, Topology: f.topology, Workers: 4}
	var baseline []byte
	for run := 0; run < 100; run++ {
		order := slices.Clone(selected)
		selectionRNG.Shuffle(len(order), func(i, j int) { order[i], order[j] = order[j], order[i] })
		a.Resolver = fixedResolver{order, 1}
		result, err := a.Audit(context.Background(), Request{Epoch: 1, Query: query})
		if err != nil || !result.Verified {
			t.Fatalf("run %d: audit=%+v, %v", run, result.Metrics, err)
		}
		encoded, err := EncodeProof(result.Proof)
		if err != nil {
			t.Fatal(err)
		}
		if run == 0 {
			baseline = encoded
		} else if !bytes.Equal(baseline, encoded) {
			t.Fatalf("run %d produced a different proof", run)
		}
	}
}

func TestAuditRejectsMissingAndDuplicateEvidence(t *testing.T) {
	for _, kind := range []merkle.TreeType{merkle.TreeSegment, merkle.TreeShard, merkle.TreeRegion, merkle.TreeGlobal} {
		t.Run(string(kind), func(t *testing.T) {
			f := newFixture(t)
			query := mva.AttrRangeQuery{SiteID: "site", DevID: "device-0", Type: "alarm", StartTS: time.Unix(0, 0), EndTS: time.Unix(100, 0)}
			a := Auditor{Roots: fixedRoots{mpm.Roots{HMF: f.root}}, Resolver: fixedResolver{f.records[:1], 1}, Repository: f.repo, Ciphertexts: f.repo, Topology: f.topology}
			plan, err := BuildPlan(context.Background(), f.repo, 1, f.topology, f.records[:1])
			if err != nil {
				t.Fatal(err)
			}
			var key NodeKey
			found := false
			for _, tree := range plan.Trees {
				if tree.Tree.Type == kind && len(tree.Frontier) > 0 {
					key, found = tree.Frontier[0], true
					break
				}
			}
			if !found {
				t.Fatal("fixture needs proof frontier")
			}
			f.repo.missing = &key
			missingResult, auditErr := a.Audit(context.Background(), Request{Epoch: 1, Query: query})
			if !errors.Is(auditErr, ErrMissingEvidence) || !missingResult.Unresolved || len(missingResult.Failures) == 0 || !missingResult.Failures[0].Unresolved {
				t.Fatalf("missing node result=%+v error=%v", missingResult.Failures, auditErr)
			}
			f.repo.missing = nil
			f.repo.duplicate = true
			_, err = a.Audit(context.Background(), Request{Epoch: 1, Query: query})
			if !errors.Is(err, ErrEvidence) {
				t.Fatalf("duplicate node error=%v", err)
			}
		})
	}
}

func TestAuditRejectsUnexpectedAndFutureNodes(t *testing.T) {
	f := newFixture(t)
	query := mva.AttrRangeQuery{SiteID: "site", DevID: "device-0", Type: "alarm", StartTS: time.Unix(0, 0), EndTS: time.Unix(100, 0)}
	a := Auditor{Roots: fixedRoots{mpm.Roots{HMF: f.root}}, Resolver: fixedResolver{f.records[:1], 1}, Repository: f.repo, Ciphertexts: f.repo, Topology: f.topology}
	f.repo.extra = &Node{Key: NodeKey{Tree: merkle.TreeID{Type: merkle.TreeSegment, RegionID: "0", ShardID: 0, SegmentID: 0}, Level: 0, Index: 999}}
	if _, err := a.Audit(context.Background(), Request{Epoch: 1, Query: query}); !errors.Is(err, ErrEvidence) {
		t.Fatalf("unexpected evidence error=%v", err)
	}
	f.repo.extra = nil
	plan, err := BuildPlan(context.Background(), f.repo, 1, f.topology, f.records[:1])
	if err != nil {
		t.Fatal(err)
	}
	var key NodeKey
	for _, tree := range plan.Trees {
		if tree.Tree.Type != merkle.TreeSegment && len(tree.Frontier) > 0 {
			key = tree.Frontier[0]
			break
		}
	}
	if key.Tree.Type == "" {
		t.Fatal("fixture needs a hierarchy frontier")
	}
	node := f.repo.nodes[key]
	node.VersionEpoch = 2
	f.repo.nodes[key] = node
	if _, err := a.Audit(context.Background(), Request{Epoch: 1, Query: query}); !errors.Is(err, ErrEvidence) {
		t.Fatalf("future evidence error=%v", err)
	}
}

func TestStructuralIdentityRetainsEqualHashes(t *testing.T) {
	id := merkle.TreeID{Type: merkle.TreeSegment, RegionID: "0", ShardID: 0, SegmentID: 0}
	plan, _, err := Frontier(id, 8, []int64{0})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Frontier) < 2 {
		t.Fatal("fixture needs two structural frontier positions")
	}
	hash := [32]byte{7}
	nodes := []Node{{Key: plan.Frontier[0], Hash: hash}, {Key: plan.Frontier[1], Hash: hash}}
	if err := validateNodes(1, plan.Frontier[:2], nodes); err != nil {
		t.Fatalf("equal hashes at different positions were collapsed: %v", err)
	}
	nodes[1].Key = nodes[0].Key
	if err := validateNodes(1, plan.Frontier[:2], nodes); !errors.Is(err, ErrEvidence) {
		t.Fatalf("same-position duplicate error=%v", err)
	}
}

func TestAuditBoundsConcurrentRetrievalAndHonorsCancellation(t *testing.T) {
	f := newFixture(t)
	f.repo.delay = 25 * time.Millisecond
	selected := []SelectedRecord{f.records[0], f.records[3], f.records[5], f.records[6]}
	query := mva.AttrRangeQuery{SiteID: "site", DevID: "device-0", Type: "alarm", StartTS: time.Unix(0, 0), EndTS: time.Unix(100, 0)}
	a := Auditor{Roots: fixedRoots{mpm.Roots{HMF: f.root}}, Resolver: fixedResolver{selected, 1}, Repository: f.repo, Ciphertexts: f.repo, Topology: f.topology, Workers: 2}
	result, err := a.Audit(context.Background(), Request{Epoch: 1, Query: query})
	if err != nil || !result.Verified || result.Metrics.MaxConcurrent != 2 {
		t.Fatalf("bounded retrieval: %+v, %v", result.Metrics, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := a.Audit(ctx, Request{Epoch: 1, Query: query}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled audit error=%v", err)
	}
}

func TestLocatorBindingRejectsEachChangedField(t *testing.T) {
	f := newFixture(t)
	selected := []SelectedRecord{f.records[0]}
	query := mva.AttrRangeQuery{SiteID: "site", DevID: "device-0", Type: "alarm", StartTS: time.Unix(0, 0), EndTS: time.Unix(100, 0)}
	a := Auditor{Roots: fixedRoots{mpm.Roots{HMF: f.root}}, Resolver: fixedResolver{selected, 1}, Repository: f.repo, Ciphertexts: f.repo, Topology: f.topology}
	base, err := a.Audit(context.Background(), Request{Epoch: 1, Query: query})
	if err != nil || !base.Verified {
		t.Fatal(err)
	}
	changes := map[string]func(*EncryptedRecord){
		"LogID":      func(r *EncryptedRecord) { r.LogID[0] ^= 1 },
		"Region":     func(r *EncryptedRecord) { r.Descriptor.RegionID = "other" },
		"Site":       func(r *EncryptedRecord) { r.Descriptor.SiteID = "other" },
		"Device":     func(r *EncryptedRecord) { r.Descriptor.DeviceID = "other" },
		"Type":       func(r *EncryptedRecord) { r.Descriptor.Type = "other" },
		"Timestamp":  func(r *EncryptedRecord) { r.Descriptor.TS = r.Descriptor.TS.Add(time.Second) },
		"Shard":      func(r *EncryptedRecord) { r.Address.ShardID++ },
		"Segment":    func(r *EncryptedRecord) { r.Address.SegmentID++ },
		"Leaf":       func(r *EncryptedRecord) { r.Address.LeafID++ },
		"Ciphertext": func(r *EncryptedRecord) { r.Ciphertext = []byte("changed") },
		"Locator":    func(r *EncryptedRecord) { r.Locator[0] ^= 1 },
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			proof := base.Proof
			proof.Logs = slices.Clone(base.Proof.Logs)
			change(&proof.Logs[0])
			verified, err := VerifyHMF(proof, f.root)
			if err == nil && verified.Valid {
				t.Fatal("accepted altered binding")
			}
		})
	}
}

func TestAuditSingleLeafSegment(t *testing.T) {
	f := newFixture(t)
	record := f.records[5] // Region 0 / Shard 1 / Segment 0 has one leaf.
	query := mva.AttrRangeQuery{SiteID: record.Descriptor.SiteID, DevID: record.Descriptor.DeviceID,
		Type: record.Descriptor.Type, StartTS: record.Descriptor.TS, EndTS: record.Descriptor.TS}
	a := Auditor{Roots: fixedRoots{mpm.Roots{HMF: f.root}}, Resolver: fixedResolver{[]SelectedRecord{record}, 1}, Repository: f.repo, Ciphertexts: f.repo, Topology: f.topology}
	result, err := a.Audit(context.Background(), Request{Epoch: 1, Query: query})
	if err != nil || !result.Verified {
		t.Fatalf("one-leaf audit=%+v err=%v", result, err)
	}
	if len(result.Proof.Trees[0].Frontier) != 0 {
		t.Fatal("single-leaf Segment fetched an unnecessary sibling")
	}
}

func TestAuditProofPortableAcrossRegions(t *testing.T) {
	f := newFixture(t)
	selected := []SelectedRecord{f.records[0], f.records[6]}
	query := mva.AttrRangeQuery{SiteID: "site", DevID: "device-0", Type: "alarm",
		StartTS: time.Unix(0, 0), EndTS: time.Unix(100, 0)}
	a := Auditor{Roots: fixedRoots{mpm.Roots{HMF: f.root}}, Resolver: fixedResolver{selected, 1},
		Repository: f.repo, Ciphertexts: f.repo, Topology: f.topology}
	result, err := a.Audit(context.Background(), Request{Epoch: 1, Query: query})
	if err != nil || !result.Verified {
		t.Fatalf("audit verified=%v err=%v", result.Verified, err)
	}
	if result.Proof.Epoch != 1 || result.Proof.Roots.HMF != f.root || result.Proof.MVA == nil || len(result.Proof.Logs) != 2 {
		t.Fatalf("incomplete audit proof: %+v", result.Proof)
	}
	counts := make(map[merkle.TreeType]int)
	seen := make(map[NodeKey]struct{})
	for _, tree := range result.Proof.Trees {
		counts[tree.Tree.Type]++
		if tree.Tree.Type == merkle.TreeGlobal && len(tree.Frontier) != 0 {
			t.Fatal("selected Regions should share the complete Global subtree")
		}
	}
	for _, node := range result.Proof.Nodes {
		if _, duplicate := seen[node.Key]; duplicate {
			t.Fatalf("duplicate structural proof node %v", node.Key)
		}
		seen[node.Key] = struct{}{}
	}
	if counts[merkle.TreeSegment] != 2 || counts[merkle.TreeShard] != 2 ||
		counts[merkle.TreeRegion] != 2 || counts[merkle.TreeGlobal] != 1 {
		t.Fatalf("wrong proof hierarchy: %v", counts)
	}
	// The HMF verifier consumes the returned package without consulting storage.
	f.repo.nodes, f.repo.logs = nil, nil
	checked, err := VerifyHMF(result.Proof, f.root)
	if err != nil || !checked.Valid || checked.GlobalRoot != f.root {
		t.Fatalf("portable proof invalid: %+v, %v", checked, err)
	}
	altered := result.Proof
	altered.Logs = slices.Clone(result.Proof.Logs)
	altered.Logs[0].Ciphertext = []byte("altered")
	checked, err = VerifyHMF(altered, f.root)
	if err != nil || checked.Valid {
		t.Fatalf("altered proof accepted: %+v, %v", checked, err)
	}
}

func TestAuditRejectsWrongAddressAndStoredLeaf(t *testing.T) {
	f := newFixture(t)
	record := f.records[0]
	query := mva.AttrRangeQuery{SiteID: record.Descriptor.SiteID, DevID: record.Descriptor.DeviceID,
		Type: record.Descriptor.Type, StartTS: record.Descriptor.TS, EndTS: record.Descriptor.TS}
	a := Auditor{Roots: fixedRoots{mpm.Roots{HMF: f.root}}, Resolver: fixedResolver{[]SelectedRecord{record}, 1}, Repository: f.repo, Ciphertexts: f.repo, Topology: f.topology}
	wrong := record
	wrong.Address.LeafID++
	a.Resolver = fixedResolver{[]SelectedRecord{wrong}, 1}
	if result, err := a.Audit(context.Background(), Request{Epoch: 1, Query: query}); err == nil && result.Verified {
		t.Fatal("MVA-selected wrong physical address was accepted")
	}
	a.Resolver = fixedResolver{[]SelectedRecord{record}, 1}
	log := f.repo.logs[record.Address]
	log.Ciphertext[0] ^= 0xff
	f.repo.logs[record.Address] = log
	result, err := a.Audit(context.Background(), Request{Epoch: 1, Query: query})
	confirmed := false
	for _, failure := range result.Failures {
		if failure.LogID == record.LogID && !failure.Unresolved {
			confirmed = true
		}
	}
	if err != nil || result.Verified || !confirmed {
		t.Fatalf("altered stored leaf result=%+v err=%v", result, err)
	}
}

func TestAuditTreatsCorruptFrontierAsUnresolved(t *testing.T) {
	for _, kind := range []merkle.TreeType{merkle.TreeSegment, merkle.TreeShard, merkle.TreeRegion, merkle.TreeGlobal} {
		t.Run(string(kind), func(t *testing.T) {
			f := newFixture(t)
			query := mva.AttrRangeQuery{SiteID: "site", DevID: "device-0", Type: "alarm", StartTS: time.Unix(0, 0), EndTS: time.Unix(100, 0)}
			selected := f.records[:1]
			plan, err := BuildPlan(context.Background(), f.repo, 1, f.topology, selected)
			if err != nil {
				t.Fatal(err)
			}
			var key NodeKey
			found := false
			for _, tree := range plan.Trees {
				if tree.Tree.Type == kind && len(tree.Frontier) > 0 {
					key, found = tree.Frontier[0], true
					break
				}
			}
			if !found {
				t.Fatal("fixture needs frontier at this level")
			}
			node := f.repo.nodes[key]
			node.Hash[0] ^= 0xff
			f.repo.nodes[key] = node
			a := Auditor{Roots: fixedRoots{mpm.Roots{HMF: f.root}}, Resolver: fixedResolver{selected, 1}, Repository: f.repo, Ciphertexts: f.repo, Topology: f.topology}
			result, err := a.Audit(context.Background(), Request{Epoch: 1, Query: query})
			if err != nil || result.Verified {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			unresolved, confirmed := false, false
			for _, failure := range result.Failures {
				if failure.Unresolved {
					unresolved = true
				}
				if failure.LogID == selected[0].LogID && !failure.Unresolved {
					confirmed = true
				}
			}
			if !unresolved || confirmed || !result.Unresolved || !errors.Is(result.IntegrityError, ErrHMFRootMismatch) {
				t.Fatalf("unsafe localization: %+v", result.Failures)
			}
		})
	}
}

func TestLocalizationRejectsForgedMatchingReference(t *testing.T) {
	f := newFixture(t)
	selected := []SelectedRecord{f.records[0]}
	query := mva.AttrRangeQuery{SiteID: "site", DevID: "device-0", Type: "alarm", StartTS: time.Unix(0, 0), EndTS: time.Unix(100, 0)}
	a := Auditor{Roots: fixedRoots{mpm.Roots{HMF: f.root}}, Resolver: fixedResolver{selected, 1}, Repository: f.repo, Ciphertexts: f.repo, Topology: f.topology}
	valid, err := a.Audit(context.Background(), Request{Epoch: 1, Query: query})
	if err != nil || !valid.Verified {
		t.Fatal(err)
	}
	proof := valid.Proof
	proof.Logs = slices.Clone(valid.Proof.Logs)
	proof.Logs[0].Ciphertext = []byte("altered")
	verification, err := VerifyHMF(proof, f.root)
	if err != nil || verification.Valid {
		t.Fatalf("tampered proof=%+v, %v", verification, err)
	}
	forged, _, err := recordHash(selected[0], proof.Logs[0])
	if err != nil {
		t.Fatal(err)
	}
	key := NodeKey{Tree: merkle.TreeID{Type: merkle.TreeSegment, RegionID: "0", ShardID: 0, SegmentID: 0}, Level: 0, Index: 0}
	node := f.repo.nodes[key]
	node.Hash = forged
	f.repo.nodes[key] = node
	local := Localize(context.Background(), f.repo, proof, f.root, verification)
	unresolved := false
	for _, failure := range local.Failures {
		if failure.Unresolved {
			unresolved = true
		}
		if failure.LogID == selected[0].LogID && !failure.Unresolved {
			t.Fatalf("forged reference falsely confirmed a leaf: %+v", local.Failures)
		}
	}
	if !unresolved {
		t.Fatalf("forged reference was trusted: %+v", local.Failures)
	}
}

func TestCurrentHPBFPrunerAuthenticatesExclusions(t *testing.T) {
	tree, err := hpbf.NewHPBF(2, 2, 100, 0.01)
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.AddToken("0", 0, "site", "device", "alarm"); err != nil {
		t.Fatal(err)
	}
	_, _, global, err := tree.Commitment(0)
	if err != nil {
		t.Fatal(err)
	}
	token, err := domain.Serialize("site")
	if err != nil {
		t.Fatal(err)
	}
	token2, err := domain.Serialize("site", "device")
	if err != nil {
		t.Fatal(err)
	}
	token3, err := domain.Serialize("site", "device", "alarm")
	if err != nil {
		t.Fatal(err)
	}
	pruned, err := (CurrentHPBFPruner{tree}).Prune(context.Background(), 0, [3][]byte{token, token2, token3}, global.RootHash)
	if err != nil || len(pruned.Regions) != 1 || len(pruned.Shards) != 1 {
		t.Fatalf("pruned=%+v err=%v", pruned, err)
	}
	_, err = (CurrentHPBFPruner{tree}).Prune(context.Background(), 0, [3][]byte{token, token2, token3}, [32]byte{9})
	if err == nil {
		t.Fatal("accepted untrusted HPBF root")
	}
	proofCopy := *pruned.Proof
	proofCopy.Regions = slices.Clone(pruned.Proof.Regions)
	proofCopy.Regions[0].Shards = slices.Clone(pruned.Proof.Regions[0].Shards)
	proofCopy.Regions[0].Shards[0].BloomFilter = *pruned.Proof.Regions[0].Shards[0].BloomFilter.Clone()
	proofCopy.Regions[0].Shards[0].BloomFilter.Add([]byte("forged token"))
	if err := hpbf.VerifyProof(proofCopy, [3][]byte{token, token2, token3}, global.RootHash,
		slices.Clone(pruned.Regions), slices.Clone(pruned.Shards)); err == nil {
		t.Fatal("accepted forged HPBF exclusion/commitment evidence")
	}
}

func TestHistoricalHPBFPrunerKeepsEpochSpecificExclusions(t *testing.T) {
	tree, err := hpbf.NewHPBF(2, 2, 100, 0.001)
	if err != nil {
		t.Fatal(err)
	}
	one := []hpbf.TokenRecord{{RegionID: "0", ShardID: 0, SiteID: "site", DeviceID: "device", Type: "alarm"}}
	root1, err := tree.PrepareCandidate(1, one)
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.CommitCandidate(1); err != nil {
		t.Fatal(err)
	}
	site, _ := domain.Serialize("site")
	pair, _ := domain.Serialize("site", "device")
	full, _ := domain.Serialize("site", "device", "alarm")
	tokens := [3][]byte{site, pair, full}
	_, _, proof1 := tree.CandidateRegionShards(tokens)
	two := []hpbf.TokenRecord{{RegionID: "1", ShardID: 1, SiteID: "site", DeviceID: "device", Type: "alarm"}}
	root2, err := tree.PrepareCandidate(2, two)
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.CommitCandidate(2); err != nil {
		t.Fatal(err)
	}
	_, _, proof2 := tree.CandidateRegionShards(tokens)
	pruner := HistoricalHPBFPruner{Source: hpbfHistory{1: proof1, 2: proof2}}
	old, err := pruner.Prune(context.Background(), 1, tokens, root1)
	if err != nil || len(old.Shards) != 1 || old.Shards[0].RegionID != "0" {
		t.Fatalf("historical HPBF candidates=%+v, %v", old.Shards, err)
	}
	newer, err := pruner.Prune(context.Background(), 2, tokens, root2)
	if err != nil || len(newer.Shards) != 2 {
		t.Fatalf("new HPBF candidates=%+v, %v", newer.Shards, err)
	}
	if _, err := pruner.Prune(context.Background(), 1, tokens, root2); !errors.Is(err, ErrInvalidHPBFProof) {
		t.Fatalf("cross-epoch root error=%v", err)
	}
	if _, err := pruner.Prune(context.Background(), 3, tokens, root2); err == nil {
		t.Fatal("accepted unpublished HPBF epoch")
	}
}

func TestCurrentMVAResolverUsesFinalizedEpoch(t *testing.T) {
	tree, err := mva.NewMVA(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.UUID{42}
	desc := mpm.Descriptor{RegionID: "0", SiteID: "site", DeviceID: "device", Type: "alarm", TS: time.Unix(10, 0).UTC()}
	address := mpm.Address{RegionID: "0", ShardID: 1, SegmentID: 2, LeafID: 3}
	locator, err := (mpm.CanonicalLocator{}).CommitLocator(id, desc, address)
	if err != nil {
		t.Fatal(err)
	}
	root, err := tree.PrepareCandidate(1, []mva.PendingRecord{{LogID: id, RegionID: "0", SiteID: desc.SiteID,
		DeviceID: desc.DeviceID, Type: desc.Type, TS: desc.TS, Address: address.MVA(), Locator: locator}})
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.CommitCandidate(1); err != nil {
		t.Fatal(err)
	}
	query := mva.AttrRangeQuery{SiteID: desc.SiteID, DevID: desc.DeviceID, Type: desc.Type,
		StartTS: desc.TS, EndTS: desc.TS}
	resolved, err := (CurrentMVAResolver{tree}).Resolve(context.Background(), 1, query,
		[]merkle.TreeID{{Type: merkle.TreeRegion, RegionID: "0"}}, root)
	if err != nil || len(resolved.Records) != 1 || resolved.Records[0].Address != address || resolved.Records[0].Locator != locator {
		t.Fatalf("resolution=%+v err=%v", resolved, err)
	}
	_, err = (CurrentMVAResolver{tree}).Resolve(context.Background(), 0, query,
		[]merkle.TreeID{{Type: merkle.TreeRegion, RegionID: "0"}}, root)
	if err == nil {
		t.Fatal("accepted mismatched MVA epoch")
	}
}

func TestCheckpointRootsRejectsUntrustedEvidence(t *testing.T) {
	roots := mpm.Roots{MVA: [32]byte{1}, HMF: [32]byte{2}, HPBF: [32]byte{3}}
	encoded, err := domain.Serialize([]byte("CHECKPOINT"), uint64(7), roots.MVA[:], roots.HMF[:], roots.HPBF[:])
	if err != nil {
		t.Fatal(err)
	}
	store := CheckpointRoots{Evidence: fixedEvidence{roots}, Checkpoints: fixedCheckpoint{sha256.Sum256(encoded)}}
	got, err := store.Roots(context.Background(), 7)
	if err != nil || got != roots {
		t.Fatalf("roots=%+v err=%v", got, err)
	}
	store.Evidence = fixedEvidence{mpm.Roots{MVA: [32]byte{9}, HMF: roots.HMF, HPBF: roots.HPBF}}
	if _, err := store.Roots(context.Background(), 7); err == nil {
		t.Fatal("accepted untrusted Cassandra roots")
	}
}

func TestHistoricalCheckpointEpochsAndCandidateRejection(t *testing.T) {
	f := newFixture(t)
	roots := mpm.Roots{MVA: [32]byte{1}, HMF: f.root, HPBF: [32]byte{2}}
	evidence := epochEvidence{4: roots, 5: roots}
	checkpoints := epochCheckpoints{}
	for _, epoch := range []uint64{4, 5} {
		data, err := domain.Serialize([]byte("CHECKPOINT"), epoch, roots.MVA[:], roots.HMF[:], roots.HPBF[:])
		if err != nil {
			t.Fatal(err)
		}
		checkpoints[epoch] = sha256.Sum256(data)
	}
	query := mva.AttrRangeQuery{SiteID: "site", DevID: "device-0", Type: "alarm", StartTS: time.Unix(0, 0), EndTS: time.Unix(100, 0)}
	a := Auditor{Roots: CheckpointRoots{Evidence: evidence, Checkpoints: checkpoints}, Resolver: fixedResolver{f.records[:1], 4}, Repository: f.repo, Ciphertexts: f.repo, Topology: f.topology}
	old, err := a.Audit(context.Background(), Request{Epoch: 4, Query: query})
	if err != nil || !old.Verified || old.Proof.Epoch != 4 {
		t.Fatalf("historical audit=%+v, %v", old.Metrics, err)
	}
	if _, err := a.Audit(context.Background(), Request{Epoch: 6, Query: query}); err == nil {
		t.Fatal("accepted unpublished candidate epoch")
	}
	if _, err := a.Audit(context.Background(), Request{Epoch: 5, Query: query}); !errors.Is(err, ErrWrongEpoch) {
		t.Fatalf("cross-epoch MVA evidence error=%v", err)
	}
	a.Resolver = fixedResolver{f.records[:1], 5}
	newer, err := a.Audit(context.Background(), Request{Epoch: 5, Query: query})
	if err != nil || !newer.Verified {
		t.Fatalf("newer epoch audit=%+v, %v", newer.Metrics, err)
	}
	// Publishing epoch 5 did not erase epoch 4's independently bound root.
	got, err := (CheckpointRoots{Evidence: evidence, Checkpoints: checkpoints}).Roots(context.Background(), 4)
	if err != nil || got != roots {
		t.Fatalf("old root unavailable: %+v, %v", got, err)
	}
}

func TestAuditHistoricalMVAHPBFAndHMFAtTwoFinalizedEpochs(t *testing.T) {
	f := newFixture(t)
	index, err := mva.NewMVA(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	filter, err := hpbf.NewHPBF(2, 2, 100, 0.001)
	if err != nil {
		t.Fatal(err)
	}
	record := f.records[0]
	d := record.Descriptor
	pending := mva.PendingRecord{LogID: record.LogID, RegionID: d.RegionID, SiteID: d.SiteID, DeviceID: d.DeviceID, Type: d.Type, TS: d.TS, Address: record.Address.MVA(), Locator: record.Locator}
	mva1, err := index.PrepareCandidate(1, []mva.PendingRecord{pending})
	if err != nil {
		t.Fatal(err)
	}
	if err := index.CommitCandidate(1); err != nil {
		t.Fatal(err)
	}
	oldMVA := index.Finalized
	hpbf1, err := filter.PrepareCandidate(1, []hpbf.TokenRecord{{RegionID: d.RegionID, ShardID: record.Address.ShardID, SiteID: d.SiteID, DeviceID: d.DeviceID, Type: d.Type}})
	if err != nil {
		t.Fatal(err)
	}
	if err := filter.CommitCandidate(1); err != nil {
		t.Fatal(err)
	}
	site, _ := domain.Serialize(d.SiteID)
	pair, _ := domain.Serialize(d.SiteID, d.DeviceID)
	full, _ := domain.Serialize(d.SiteID, d.DeviceID, d.Type)
	tokens := [3][]byte{site, pair, full}
	_, _, proof1 := filter.CandidateRegionShards(tokens)
	mva2, err := index.PrepareCandidate(2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := index.CommitCandidate(2); err != nil {
		t.Fatal(err)
	}
	hpbf2, err := filter.PrepareCandidate(2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := filter.CommitCandidate(2); err != nil {
		t.Fatal(err)
	}
	_, _, proof2 := filter.CandidateRegionShards(tokens)
	if mva1 != mva2 || hpbf1 == hpbf2 {
		t.Fatal("unchanged MVA root or epoch-bound HPBF root has wrong semantics")
	}
	roots := epochEvidence{1: {MVA: mva1, HMF: f.root, HPBF: hpbf1}, 2: {MVA: mva2, HMF: f.root, HPBF: hpbf2}}
	checkpoints := epochCheckpoints{}
	for _, epoch := range []uint64{1, 2} {
		r := roots[epoch]
		encoded, err := domain.Serialize([]byte("CHECKPOINT"), epoch, r.MVA[:], r.HMF[:], r.HPBF[:])
		if err != nil {
			t.Fatal(err)
		}
		checkpoints[epoch] = sha256.Sum256(encoded)
	}
	a := Auditor{Roots: CheckpointRoots{Evidence: roots, Checkpoints: checkpoints},
		Resolver: HistoricalMVAResolver{Reader: mvaSnapshotHistory{1: oldMVA, 2: index.Finalized}},
		Pruner:   HistoricalHPBFPruner{Source: hpbfHistory{1: proof1, 2: proof2}}, Repository: f.repo, Ciphertexts: f.repo, Topology: f.topology}
	query := mva.AttrRangeQuery{SiteID: d.SiteID, DevID: d.DeviceID, Type: d.Type, StartTS: d.TS, EndTS: d.TS}
	for _, epoch := range []uint64{2, 1} {
		result, err := a.Audit(context.Background(), Request{Epoch: epoch, Query: query, Tokens: tokens, UsePruning: true})
		if err != nil || !result.Verified || len(result.Proof.Selected) != 1 || result.Proof.Epoch != epoch {
			t.Fatalf("epoch %d audit=%+v err=%v", epoch, result.Metrics, err)
		}
		verified, err := VerifyAuditProof(context.Background(), result.Proof, checkpoints)
		if err != nil || !verified.Valid {
			t.Fatalf("epoch %d independent proof=%+v err=%v", epoch, verified, err)
		}
	}
	if _, err := a.Audit(context.Background(), Request{Epoch: 3, Query: query, Tokens: tokens, UsePruning: true}); err == nil {
		t.Fatal("accepted unanchored candidate")
	}
}

func TestAuditEmptyAndWrongEpoch(t *testing.T) {
	f := newFixture(t)
	query := mva.AttrRangeQuery{SiteID: "none", DevID: "none", Type: "none", StartTS: time.Unix(0, 0), EndTS: time.Unix(1, 0)}
	a := Auditor{Roots: fixedRoots{mpm.Roots{HMF: f.root}}, Resolver: fixedResolver{nil, 1}, Repository: f.repo, Ciphertexts: f.repo, Topology: f.topology}
	result, err := a.Audit(context.Background(), Request{Epoch: 1, Query: query})
	if err != nil || !result.Verified || len(result.Proof.Nodes) != 0 {
		t.Fatalf("empty result=%+v err=%v", result, err)
	}
	a.Resolver = fixedResolver{nil, 2}
	if _, err := a.Audit(context.Background(), Request{Epoch: 1, Query: query}); err == nil {
		t.Fatal("accepted wrong resolver epoch")
	}
}

func TestAuditIntegratesFinalizedMVAHPBFAndHMF(t *testing.T) {
	f := newFixture(t)
	index, err := mva.NewMVA(2, 3)
	if err != nil {
		t.Fatal(err)
	}
	filter, err := hpbf.NewHPBF(2, 2, 100, 0.001)
	if err != nil {
		t.Fatal(err)
	}
	mvaRecords := make([]mva.PendingRecord, 0, len(f.records))
	filterRecords := make([]hpbf.TokenRecord, 0, len(f.records))
	for _, record := range f.records {
		d := record.Descriptor
		mvaRecords = append(mvaRecords, mva.PendingRecord{LogID: record.LogID, RegionID: d.RegionID,
			SiteID: d.SiteID, DeviceID: d.DeviceID, Type: d.Type, TS: d.TS,
			Address: record.Address.MVA(), Locator: record.Locator})
		filterRecords = append(filterRecords, hpbf.TokenRecord{RegionID: d.RegionID, ShardID: record.Address.ShardID,
			SiteID: d.SiteID, DeviceID: d.DeviceID, Type: d.Type})
	}
	mvaRoot, err := index.PrepareCandidate(1, mvaRecords)
	if err != nil {
		t.Fatal(err)
	}
	if err := index.CommitCandidate(1); err != nil {
		t.Fatal(err)
	}
	hpbfRoot, err := filter.PrepareCandidate(1, filterRecords)
	if err != nil {
		t.Fatal(err)
	}
	if err := filter.CommitCandidate(1); err != nil {
		t.Fatal(err)
	}
	target := f.records[0].Descriptor
	site, _ := domain.Serialize(target.SiteID)
	siteDevice, _ := domain.Serialize(target.SiteID, target.DeviceID)
	full, _ := domain.Serialize(target.SiteID, target.DeviceID, target.Type)
	query := mva.AttrRangeQuery{SiteID: target.SiteID, DevID: target.DeviceID, Type: target.Type,
		StartTS: target.TS, EndTS: target.TS}
	a := Auditor{Roots: fixedRoots{mpm.Roots{MVA: mvaRoot, HMF: f.root, HPBF: hpbfRoot}},
		Resolver: CurrentMVAResolver{index}, Pruner: CurrentHPBFPruner{filter}, Repository: f.repo, Ciphertexts: f.repo, Topology: f.topology}
	result, err := a.Audit(context.Background(), Request{Epoch: 1, Query: query, Tokens: [3][]byte{site, siteDevice, full}, UsePruning: true})
	if err != nil || !result.Verified || len(result.Proof.Logs) != 1 || result.Proof.Logs[0].LogID != f.records[0].LogID {
		t.Fatalf("integrated audit=%+v err=%v", result, err)
	}
	checkpointBytes, err := domain.Serialize([]byte("CHECKPOINT"), uint64(1), mvaRoot[:], f.root[:], hpbfRoot[:])
	if err != nil {
		t.Fatal(err)
	}
	checkpoints := fixedCheckpoint{sha256.Sum256(checkpointBytes)}
	independent, err := VerifyAuditProof(context.Background(), result.Proof, checkpoints)
	if err != nil || !independent.Valid {
		t.Fatalf("independent full proof: %+v, %v", independent, err)
	}
	wrongEpoch := result.Proof
	wrongMVA := *wrongEpoch.MVA
	wrongMVA.Epoch++
	wrongEpoch.MVA = &wrongMVA
	invalidHPBF := result.Proof
	wrongHPBF := *invalidHPBF.HPBF
	wrongHPBF.Levels = slices.Clone(wrongHPBF.Levels)
	lastLevel := len(wrongHPBF.Levels) - 1
	wrongHPBF.Levels[lastLevel] = slices.Clone(wrongHPBF.Levels[lastLevel])
	wrongHPBF.Levels[lastLevel][0][0] ^= 1
	invalidHPBF.HPBF = &wrongHPBF
	invalidScope := result.Proof
	invalidScope.Tokens[0] = []byte("different site")
	malformed := result.Proof
	malformed.MVA = nil
	for _, tc := range []struct {
		name  string
		proof Proof
		want  error
	}{
		{"wrong epoch", wrongEpoch, ErrWrongEpoch},
		{"invalid HPBF", invalidHPBF, ErrInvalidHPBFProof},
		{"invalid scope", invalidScope, ErrInvalidQueryScope},
		{"malformed", malformed, ErrMalformedProof},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := VerifyAuditProof(context.Background(), tc.proof, checkpoints); !errors.Is(err, tc.want) {
				t.Fatalf("error=%v, want %v", err, tc.want)
			}
		})
	}
	encodedProof, err := EncodeProof(result.Proof)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		again, err := EncodeProof(result.Proof)
		if err != nil || !bytes.Equal(again, encodedProof) {
			t.Fatalf("proof encoding changed on repetition %d: %v", i, err)
		}
	}
	portableProof, err := DecodeProof(encodedProof)
	if err != nil {
		t.Fatal(err)
	}
	independent, err = VerifyAuditProof(context.Background(), portableProof, checkpoints)
	if err != nil || !independent.Valid {
		t.Fatalf("decoded proof failed without PHV state: %+v, %v", independent, err)
	}
	changedSelection := result.Proof
	changedSelection.Selected = slices.Clone(result.Proof.Selected)
	changedSelection.Selected[0].Address.LeafID++
	if _, err := VerifyAuditProof(context.Background(), changedSelection, checkpoints); err == nil {
		t.Fatal("accepted a selected address absent from the MVA proof")
	}
	if _, err := VerifyAuditProof(context.Background(), result.Proof, fixedCheckpoint{[32]byte{9}}); err == nil {
		t.Fatal("accepted proof against a different trusted checkpoint")
	}
	if _, err := a.Audit(context.Background(), Request{Epoch: 1, Query: query,
		Tokens: [3][]byte{site, siteDevice, []byte("other")}, UsePruning: true}); err == nil {
		t.Fatal("accepted HPBF tokens for a different MVA query")
	}
	idResult, err := a.Audit(context.Background(), Request{Epoch: 1, Query: mva.LogIDQuery{ID: f.records[0].LogID}})
	if err != nil || !idResult.Verified || len(idResult.Proof.Logs) != 1 ||
		idResult.Proof.Logs[0].Address != f.records[0].Address || !idResult.Proof.Selected[0].DescriptorFromLog {
		t.Fatalf("Log-ID audit failed: result=%+v err=%v", idResult, err)
	}
	independent, err = VerifyAuditProof(context.Background(), idResult.Proof, checkpoints)
	if err != nil || !independent.Valid {
		t.Fatalf("independent Log-ID proof: %+v, %v", independent, err)
	}
	noPruner := a
	noPruner.Pruner = nil
	withoutTokens, err := noPruner.Audit(context.Background(), Request{Epoch: 1, Query: mva.LogIDQuery{ID: f.records[0].LogID}, UsePruning: true})
	if err != nil || !withoutTokens.Verified || withoutTokens.Proof.HPBF != nil {
		t.Fatalf("tokenless query did not bypass HPBF: %+v, %v", withoutTokens.Metrics, err)
	}
	timeOnly, err := noPruner.Audit(context.Background(), Request{Epoch: 1, Query: mva.TimeRangeQuery{StartTS: time.Unix(6, 0), EndTS: time.Unix(8, 0)}, UsePruning: true})
	if err != nil || !timeOnly.Verified || timeOnly.Proof.HPBF != nil || len(timeOnly.Proof.Selected) != 3 {
		t.Fatalf("time-only audit failed or used HPBF: %+v, %v", timeOnly.Metrics, err)
	}
	independent, err = VerifyAuditProof(context.Background(), timeOnly.Proof, checkpoints)
	if err != nil || !independent.Valid {
		t.Fatalf("independent time-only proof: %+v, %v", independent, err)
	}
	timeBytes, err := EncodeProof(timeOnly.Proof)
	if err != nil {
		t.Fatal(err)
	}
	timeDecoded, err := DecodeProof(timeBytes)
	if err != nil {
		t.Fatal(err)
	}
	independent, err = VerifyAuditProof(context.Background(), timeDecoded, checkpoints)
	if err != nil || !independent.Valid {
		t.Fatalf("decoded time-only proof: %+v, %v", independent, err)
	}
	idBytes, err := EncodeProof(idResult.Proof)
	if err != nil {
		t.Fatal(err)
	}
	idDecoded, err := DecodeProof(idBytes)
	if err != nil {
		t.Fatal(err)
	}
	independent, err = VerifyAuditProof(context.Background(), idDecoded, checkpoints)
	if err != nil || !independent.Valid {
		t.Fatalf("decoded Log-ID proof: %+v, %v", independent, err)
	}
	siteOnly, err := a.Audit(context.Background(), Request{Epoch: 1, Query: mva.SiteQuery{SiteID: target.SiteID}, Tokens: [3][]byte{site}, UsePruning: true})
	if err != nil || !siteOnly.Verified || len(siteOnly.Proof.Selected) != len(f.records) {
		t.Fatalf("Site audit selected %d records: %v", len(siteOnly.Proof.Selected), err)
	}
	independent, err = VerifyAuditProof(context.Background(), siteOnly.Proof, checkpoints)
	if err != nil || !independent.Valid {
		t.Fatalf("independent Site proof: %+v, %v", independent, err)
	}
	pairResult, err := a.Audit(context.Background(), Request{Epoch: 1, Query: mva.SiteDeviceQuery{SiteID: target.SiteID, DevID: target.DeviceID}, Tokens: [3][]byte{site, siteDevice}, UsePruning: true})
	if err != nil || !pairResult.Verified || len(pairResult.Proof.Selected) != 1 {
		t.Fatalf("Site+Device audit selected %d records: %v", len(pairResult.Proof.Selected), err)
	}
	independent, err = VerifyAuditProof(context.Background(), pairResult.Proof, checkpoints)
	if err != nil || !independent.Valid {
		t.Fatalf("independent Site+Device proof: %+v, %v", independent, err)
	}
	emptyQuery := mva.AttrRangeQuery{SiteID: "absent", DevID: "device", Type: "alarm", StartTS: target.TS, EndTS: target.TS}
	emptyResult, err := a.Audit(context.Background(), Request{Epoch: 1, Query: emptyQuery})
	if err != nil || !emptyResult.Verified || len(emptyResult.Proof.Trees) != 0 {
		t.Fatalf("empty audit: %+v, %v", emptyResult, err)
	}
	independent, err = VerifyAuditProof(context.Background(), emptyResult.Proof, checkpoints)
	if err != nil || !independent.Valid {
		t.Fatalf("independent empty proof: %+v, %v", independent, err)
	}
	changedEmpty := emptyResult.Proof
	changedEmpty.Root[0] ^= 1
	if _, err := VerifyAuditProof(context.Background(), changedEmpty, checkpoints); err == nil {
		t.Fatal("empty proof accepted a mismatched HMF root")
	}
	// Independent verification still works after the producers and repository
	// are unavailable; all required evidence is in the decoded package.
	index, filter = nil, nil
	f.repo.nodes, f.repo.logs = nil, nil
	a = Auditor{}
	independent, err = VerifyAuditProof(context.Background(), portableProof, checkpoints)
	if err != nil || !independent.Valid {
		t.Fatalf("portable proof needed hidden state: %+v, %v", independent, err)
	}
}
