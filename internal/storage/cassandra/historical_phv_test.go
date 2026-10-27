package cassandra

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
	"github.com/SirojWongpitakroj/mva-phv/internal/hpbf"
	"github.com/SirojWongpitakroj/mva-phv/internal/mva"
	"github.com/SirojWongpitakroj/mva-phv/internal/phv"
)

type historyQuery struct {
	contains string
	rows     *fakeRows
}
type historyClient struct {
	queries  []historyQuery
	position int
}

func (*historyClient) Exec(context.Context, string, ...any) error {
	return fmt.Errorf("unexpected write")
}
func (c *historyClient) Query(_ context.Context, statement string, _ ...any) (Rows, error) {
	if c.position >= len(c.queries) {
		return nil, fmt.Errorf("unexpected query: %s", statement)
	}
	q := c.queries[c.position]
	c.position++
	if !strings.Contains(statement, q.contains) {
		return nil, fmt.Errorf("query %d: want %q in %q", c.position, q.contains, statement)
	}
	return q.rows, nil
}

func TestHistoricalMVAPageUsesVersionedPositionAndDecodesValue(t *testing.T) {
	id := uuid.UUID{1}
	key, err := domain.Serialize("site", "device", "alarm", time.Unix(7, 0).UTC(), id)
	if err != nil {
		t.Fatal(err)
	}
	address, err := domain.Serialize("R0", "2", "3", "4")
	if err != nil {
		t.Fatal(err)
	}
	value := append(append(append([]byte(nil), key...), address...), make([]byte, 32)...)
	payload := PagePayload{IsLeaf: true, Keys: [][]byte{key}, Values: [][]byte{value}}
	data, err := EncodePagePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := payload.Hash("R0", 6)
	if err != nil {
		t.Fatal(err)
	}
	rows := newRows([]any{int64(4), true, (*int64)(nil), (*int64)(nil), (*int64)(nil), hash[:], data})
	store, client := testStore(t, rows)
	page, err := store.Page(context.Background(), 9, "R0", mva.ViewAttribute, 6)
	if err != nil || !page.IsLeaf || page.VersionEpoch != 4 || page.Hash != hash || len(page.Values) != 1 ||
		page.Values[0].RegionID != "R0" || page.Values[0].ShardID != "2" || page.Values[0].LeafID != "4" || page.Keys[0].LogID() != id {
		t.Fatalf("historical page=%+v err=%v", page, err)
	}
	if !strings.Contains(client.statement, "version_epoch<=? LIMIT 1") || !reflect.DeepEqual(client.args, []any{"R0", "attribute", int64(0), int64(6), int64(9)}) {
		t.Fatalf("historical page query=%s args=%#v", client.statement, client.args)
	}
}

func TestHPBFHistoricalLevelsRejectMissingOrDuplicateNodes(t *testing.T) {
	leaves := [][32]byte{{1}, {2}}
	good := []EpochNode{{MerkleNodeRecord: MerkleNodeRecord{Level: 1, Index: 0, Hash: [32]byte{3}}}}
	levels, err := historicalLevels(leaves, good)
	if err != nil || len(levels) != 2 || levels[1][0][0] != 3 {
		t.Fatalf("levels=%+v err=%v", levels, err)
	}
	duplicate := append(append([]EpochNode(nil), good...), good[0])
	if _, err := historicalLevels(leaves, duplicate); err == nil {
		t.Fatal("accepted duplicate HPBF internal node")
	}
	missing := []EpochNode{{MerkleNodeRecord: MerkleNodeRecord{Level: 1, Index: 1, Hash: [32]byte{3}}}}
	if _, err := historicalLevels(leaves, missing); err == nil {
		t.Fatal("accepted missing HPBF internal node")
	}
}

func TestHistoricalHPBFLoaderReadsEpochManifestAndFilterVersion(t *testing.T) {
	tree, err := hpbf.NewHPBF(1, 1, 100, 0.001)
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.AddToken("0", 0, "site", "device", "alarm"); err != nil {
		t.Fatal(err)
	}
	shards, regions, global, err := tree.Commitment(0)
	if err != nil {
		t.Fatal(err)
	}
	m, k, bits := shards[0].BloomFilter.Snapshot()
	regionM, regionK, regionBits := regions[0].BloomFilter.Snapshot()
	client := &historyClient{queries: []historyQuery{
		{"hpbf_region_roots_by_epoch", newRows([]any{int64(0), "0", regions[0].RootHash[:]})},
		{"hpbf_region_filters_by_epoch", newRows([]any{int64(regionM), int64(regionK), FilterBits(regionBits)})},
		{"hpbf_shard_commitments_by_epoch", newRows([]any{int64(0), int64(0), int64(0), shards[0].Commitment[:]})},
		{"hpbf_shard_filter_versions", newRows([]any{int64(m), int64(k), FilterBits(bits)})},
		{"hpbf_region_nodes_by_epoch", newRows()},
		{"hpbf_global_nodes_by_epoch", newRows()},
	}}
	store, err := NewStore(client)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := store.LoadHPBFProof(context.Background(), 0)
	if err != nil || client.position != len(client.queries) || len(proof.Regions) != 1 || len(proof.Regions[0].Shards) != 1 || proof.Epoch != 0 {
		t.Fatalf("historical HPBF proof=%+v reads=%d err=%v", proof, client.position, err)
	}
	site, _ := domain.Serialize("site")
	pair, _ := domain.Serialize("site", "device")
	full, _ := domain.Serialize("site", "device", "alarm")
	pruned, err := (phv.HistoricalHPBFPruner{Source: hpbfProofValue{proof}}).Prune(context.Background(), 0, [3][]byte{site, pair, full}, global.RootHash)
	if err != nil || len(pruned.Shards) != 1 {
		t.Fatalf("loaded HPBF proof failed authentication: %+v, %v", pruned.Shards, err)
	}
}

type hpbfProofValue struct{ proof hpbf.HPBFProof }

func (v hpbfProofValue) LoadHPBFProof(context.Context, uint64) (hpbf.HPBFProof, error) {
	return v.proof, nil
}
