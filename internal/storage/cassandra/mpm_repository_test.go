package cassandra

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
	"github.com/SirojWongpitakroj/mva-phv/internal/mpm"
	"github.com/SirojWongpitakroj/mva-phv/internal/mva"
)

type repositoryWrite struct {
	statement string
	args      []any
}
type repositoryClient struct {
	writes       []repositoryWrite
	failOn       string
	active       *ActiveSegment
	reservations map[uuid.UUID]struct {
		key  SegmentKey
		leaf int64
	}
}

func (c *repositoryClient) Exec(_ context.Context, statement string, args ...any) error {
	if c.failOn != "" && strings.Contains(statement, c.failOn) {
		return errors.New("Cassandra unavailable")
	}
	c.writes = append(c.writes, repositoryWrite{statement, append([]any(nil), args...)})
	return nil
}
func (c *repositoryClient) ExecIfNotExists(_ context.Context, statement string, args ...any) (bool, error) {
	if c.failOn != "" && strings.Contains(statement, c.failOn) {
		return false, errors.New("Cassandra unavailable")
	}
	if c.reservations == nil {
		c.reservations = make(map[uuid.UUID]struct {
			key  SegmentKey
			leaf int64
		})
	}
	id := args[0].(uuid.UUID)
	if _, ok := c.reservations[id]; ok {
		return false, nil
	}
	c.reservations[id] = struct {
		key  SegmentKey
		leaf int64
	}{
		key: SegmentKey{RegionID: args[1].(string), ShardID: args[2].(int64), SegmentID: args[3].(int64)}, leaf: args[4].(int64)}
	return true, nil
}
func (c *repositoryClient) Query(_ context.Context, statement string, args ...any) (Rows, error) {
	if strings.Contains(statement, "FROM hmf_active_segments_by_shard") && c.active != nil {
		return newRows([]any{c.active.SegmentID, c.active.OpenedAtNS, c.active.LeafCount, c.active.NextSegmentID}), nil
	}
	if strings.Contains(statement, "FROM log_addresses_by_id") {
		value, ok := c.reservations[args[0].(uuid.UUID)]
		if ok {
			return newRows([]any{value.key.RegionID, value.key.ShardID, value.key.SegmentID, value.leaf}), nil
		}
	}
	return newRows(), nil
}

type repositorySource struct {
	evidence CandidateEvidence
	err      error
}

func (s repositorySource) CandidateEvidence(_ context.Context, _ mpm.Candidate) (CandidateEvidence, error) {
	return s.evidence, s.err
}
func countWrites(writes []repositoryWrite, table string) int {
	n := 0
	for _, write := range writes {
		if strings.Contains(write.statement, table) {
			n++
		}
	}
	return n
}

func TestMPMRepositoryPersistsAcceptedRecordAndWorkingState(t *testing.T) {
	client := &repositoryClient{}
	store, _ := NewStore(client)
	repo, err := NewMPMRepository(store, repositorySource{})
	if err != nil {
		t.Fatal(err)
	}
	when := time.Unix(100, 123).UTC()
	id := uuid.UUID{1}
	address := mpm.Address{RegionID: "r0", ShardID: 2, SegmentID: 3, LeafID: 0}
	record := mpm.Record{Log: domain.Log{LogID: id, RegionID: "r0", SiteID: "site", DevID: "dev", Type: "alert", TS: when,
		Digest: [32]byte{6}},
		Descriptor: mpm.Descriptor{RegionID: "r0", SiteID: "site", DeviceID: "dev", Type: "alert", TS: when},
		Address:    address, AcceptedAt: when, Locator: [32]byte{7}, HMFLeaf: [32]byte{8}}
	leaf := PagePayload{IsLeaf: true}
	hash, err := leaf.Hash("r0", 0)
	if err != nil {
		t.Fatal(err)
	}
	page := mva.Page{PageID: 0, RegionID: "r0", Hash: hash, IsLeaf: true}
	update := mva.LocatorUpdate{Pages: []mva.Page{page}, RootPageID: 0, RootHash: hash, NextPageID: 1, Height: 0, RecordCount: 1}
	mv := mpm.MVAUpdate{IDView: update, AttrView: update, WorkingEpoch: 1, TreeOrder: 4}
	hp := mpm.HPBFUpdate{RegionID: "r0", ShardID: 2, WorkingEpoch: 1, BitCount: 64, HashCount: 2, Words: []uint64{1}}
	if err := repo.PersistAccepted(context.Background(), record, mv, hp); err != nil {
		t.Fatal(err)
	}
	for table, want := range map[string]int{"mva_pages": 2, "mva_working_view_state": 2,
		"hpbf_working_shard_filters": 1, "hmf_active_segments_by_shard": 1} {
		if got := countWrites(client.writes, table); got != want {
			t.Fatalf("%s writes=%d, want %d", table, got, want)
		}
	}
	if countWrites(client.writes, "logs_by_segment") != 0 {
		t.Fatal("CLS attempted to store external CP ciphertext")
	}
	record.Log.Ciphertext = []byte{1}
	if err := repo.PersistAccepted(context.Background(), record, mv, hp); err == nil {
		t.Fatal("CLS accepted external CP ciphertext payload")
	}
	record.Log.Ciphertext = nil
	last := client.writes[len(client.writes)-1]
	if !strings.Contains(last.statement, "hmf_active_segments_by_shard") || last.args[5] != int64(4) {
		t.Fatal("active Segment recovery state is wrong")
	}
}

func TestMPMRepositoryPreservesOpeningTimeForLaterLeaf(t *testing.T) {
	segID, opened, count := int64(3), int64(100), int64(1)
	client := &repositoryClient{active: &ActiveSegment{RegionID: "r0", ShardID: 2, SegmentID: &segID,
		OpenedAtNS: &opened, LeafCount: &count, NextSegmentID: 4}}
	store, _ := NewStore(client)
	repo, _ := NewMPMRepository(store, repositorySource{})
	when := time.Unix(0, 200)
	record := mpm.Record{Log: domain.Log{LogID: uuid.UUID{1}, RegionID: "r0", SiteID: "site", DevID: "dev", Type: "alert", TS: when},
		Descriptor: mpm.Descriptor{RegionID: "r0", SiteID: "site", DeviceID: "dev", Type: "alert", TS: when},
		Address:    mpm.Address{RegionID: "r0", ShardID: 2, SegmentID: 3, LeafID: 1}, AcceptedAt: when}
	update := mva.LocatorUpdate{RootPageID: 0, NextPageID: 1, RecordCount: 2}
	mv := mpm.MVAUpdate{IDView: update, AttrView: update, WorkingEpoch: 1, TreeOrder: 4}
	hp := mpm.HPBFUpdate{RegionID: "r0", ShardID: 2, WorkingEpoch: 1, BitCount: 64, HashCount: 1, Words: []uint64{1}}
	if err := repo.PersistAccepted(context.Background(), record, mv, hp); err != nil {
		t.Fatal(err)
	}
	last := client.writes[len(client.writes)-1]
	if got := last.args[3].(int64); got != opened {
		t.Fatalf("opened_at_ns=%d, want %d", got, opened)
	}
}

func TestMPMRepositorySealedEvidenceBeforeMetadataAndActiveClear(t *testing.T) {
	segID, opened, count := int64(3), int64(100), int64(2)
	client := &repositoryClient{active: &ActiveSegment{RegionID: "r0", ShardID: 2, SegmentID: &segID, OpenedAtNS: &opened, LeafCount: &count, NextSegmentID: 4}}
	store, _ := NewStore(client)
	repo, _ := NewMPMRepository(store, repositorySource{})
	segment := mpm.Segment{ID: merkle.TreeID{Type: merkle.TreeSegment, RegionID: "r0", ShardID: 2, SegmentID: 3},
		Root: [32]byte{9}, LeafCount: 2, Height: 1, MaxLeaves: 10,
		OpenedAt: time.Unix(0, 100), SealedAt: time.Unix(0, 200)}
	nodes := []merkle.MerkleNode{{Level: 0, Index: 0, Hash: [32]byte{1}}, {Level: 0, Index: 1, Hash: [32]byte{2}}, {Level: 1, Index: 0, Hash: [32]byte{3}}}
	if err := repo.PersistSealed(context.Background(), segment, nodes); err != nil {
		t.Fatal(err)
	}
	if len(client.writes) != 5 || !strings.Contains(client.writes[0].statement, "hmf_segment_nodes") ||
		!strings.Contains(client.writes[1].statement, "hmf_segment_nodes") ||
		!strings.Contains(client.writes[2].statement, "hmf_segment_nodes") ||
		!strings.Contains(client.writes[3].statement, "hmf_segments_by_shard") ||
		!strings.Contains(client.writes[4].statement, "UPDATE hmf_active_segments_by_shard") {
		t.Fatalf("wrong seal write order: %+v", client.writes)
	}
	client.writes = nil
	client.failOn = "hmf_segment_nodes"
	if err := repo.PersistSealed(context.Background(), segment, nodes); err == nil || len(client.writes) != 0 {
		t.Fatal("node failure wrote sealed metadata")
	}
}

func TestMPMRepositoryDoesNotClearNewerActiveSegment(t *testing.T) {
	newID, opened, count := int64(4), int64(300), int64(1)
	client := &repositoryClient{active: &ActiveSegment{RegionID: "r0", ShardID: 2, SegmentID: &newID,
		OpenedAtNS: &opened, LeafCount: &count, NextSegmentID: 5}}
	store, _ := NewStore(client)
	repo, _ := NewMPMRepository(store, repositorySource{})
	segment := mpm.Segment{ID: merkle.TreeID{Type: merkle.TreeSegment, RegionID: "r0", ShardID: 2, SegmentID: 3},
		Root: [32]byte{9}, LeafCount: 1, Height: 0, MaxLeaves: 10,
		OpenedAt: time.Unix(0, 100), SealedAt: time.Unix(0, 200)}
	if err := repo.PersistSealed(context.Background(), segment, []merkle.MerkleNode{{Level: 0, Index: 0, Hash: [32]byte{1}}}); err != nil {
		t.Fatal(err)
	}
	for _, write := range client.writes {
		if strings.Contains(write.statement, "UPDATE hmf_active_segments_by_shard") {
			t.Fatal("newer active Segment was cleared")
		}
	}
}

func TestMPMRepositoryCandidateWritesEvidenceBeforeRoots(t *testing.T) {
	client := &repositoryClient{}
	store, _ := NewStore(client)
	root := mpm.Roots{MVA: [32]byte{1}, HMF: [32]byte{2}, HPBF: [32]byte{3}}
	candidate := mpm.Candidate{Epoch: 1, Roots: root}
	e := int64(1)
	evidence := CandidateEvidence{
		HMFGlobal: GlobalState{Scope: "GLOBAL", Epoch: e, Root: root.HMF, RegionCount: 1, TreeHeight: 0},
		MVAViews: []ViewState{{RegionID: "r0", View: "id", Epoch: e, RootHash: [32]byte{4}, TreeOrder: 4},
			{RegionID: "r0", View: "attribute", Epoch: e, RootHash: [32]byte{5}, TreeOrder: 4}},
		MVARegions:        []MVARegionCommitment{{Epoch: e, RegionIndex: 0, RegionID: "r0", IDRoot: [32]byte{4}, AttrRoot: [32]byte{5}, RegionRoot: [32]byte{6}}},
		MVAGlobalNodes:    []EpochNode{{Epoch: e, MerkleNodeRecord: MerkleNodeRecord{Level: 0, Index: 0, Hash: [32]byte{6}}}},
		HPBFShardFilters:  []FilterRecord{{RegionID: "r0", ShardID: 0, Epoch: e, BitCount: 64, HashCount: 1, Bits: FilterBits([]uint64{1})}},
		HPBFShards:        []HPBFShardCommitment{{Epoch: e, RegionID: "r0", ShardID: 0, ShardIndex: 0, FilterVersionEpoch: e, Commitment: [32]byte{7}}},
		HPBFRegionFilters: []FilterRecord{{RegionID: "r0", Epoch: e, BitCount: 64, HashCount: 1, Bits: FilterBits([]uint64{1})}},
		HPBFRegions:       []HPBFRegionRoot{{Epoch: e, RegionIndex: 0, RegionID: "r0", Root: [32]byte{8}}},
		HPBFGlobalNodes:   []EpochNode{{Epoch: e, MerkleNodeRecord: MerkleNodeRecord{Level: 0, Index: 0, Hash: [32]byte{8}}}},
	}
	repo, _ := NewMPMRepository(store, repositorySource{evidence: evidence})
	if err := repo.PersistCandidate(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if len(client.writes) < 3 {
		t.Fatal("missing root writes")
	}
	last := client.writes[len(client.writes)-3:]
	for i, table := range []string{"hmf_global_state_by_epoch", "mva_epoch_roots", "hpbf_epoch_roots"} {
		if !strings.Contains(last[i].statement, table) {
			t.Fatalf("root %d was not written last: %s", i, last[i].statement)
		}
	}
	client.writes = nil
	evidence.HMFGlobal.Root = [32]byte{99}
	repo.source = repositorySource{evidence: evidence}
	if err := repo.PersistCandidate(context.Background(), candidate); err == nil || len(client.writes) != 0 {
		t.Fatal("mismatched candidate root was persisted")
	}
	client.writes = nil
	evidence.HMFGlobal.Root = root.HMF
	client.failOn = "hpbf_shard_commitments_by_epoch"
	repo.source = repositorySource{evidence: evidence}
	if err := repo.PersistCandidate(context.Background(), candidate); err == nil {
		t.Fatal("write failure hidden")
	}
	if countWrites(client.writes, "mva_epoch_roots") != 0 || countWrites(client.writes, "hmf_global_state_by_epoch") != 0 {
		t.Fatal("root written after evidence failure")
	}
}

func TestMPMRepositoryRejectsMissingEvidenceSource(t *testing.T) {
	store, _ := NewStore(&repositoryClient{})
	if _, err := NewMPMRepository(store, nil); err == nil {
		t.Fatal("repository accepted no candidate evidence source")
	}
	if _, err := NewMPMRepository(nil, repositorySource{}); err == nil {
		t.Fatal("repository accepted no Cassandra Store")
	}
	plainStore, _ := NewStore(&fakeClient{})
	if _, err := NewMPMRepository(plainStore, repositorySource{}); err == nil {
		t.Fatal("repository accepted Client without conditional writes")
	}
}

func TestLogIDReservationIsIdempotentAndRejectsDifferentAddress(t *testing.T) {
	client := &repositoryClient{}
	store, _ := NewStore(client)
	id := uuid.UUID{9}
	key := SegmentKey{RegionID: "r0", ShardID: 1, SegmentID: 2}
	ctx := context.Background()
	if err := store.ReserveLogID(ctx, id, key, 3); err != nil {
		t.Fatal(err)
	}
	if err := store.ReserveLogID(ctx, id, key, 3); err != nil {
		t.Fatalf("identical retry failed: %v", err)
	}
	if err := store.ReserveLogID(ctx, id, key, 4); !errors.Is(err, ErrLogIDConflict) {
		t.Fatalf("conflicting position accepted: %v", err)
	}
}
