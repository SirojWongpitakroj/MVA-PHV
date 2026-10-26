package cassandra

import (
	"context"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"
	"uuid"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

type fakeClient struct {
	statement string
	args      []any
	rows      *fakeRows
	execErr   error
}

func (f *fakeClient) Exec(_ context.Context, statement string, args ...any) error {
	f.statement, f.args = statement, args
	return f.execErr
}

func (f *fakeClient) Query(_ context.Context, statement string, args ...any) (Rows, error) {
	f.statement, f.args = statement, args
	return f.rows, nil
}

type fakeRows struct {
	data   [][]any
	index  int
	closed bool
}

func newRows(data ...[]any) *fakeRows { return &fakeRows{data: data, index: -1} }

func (r *fakeRows) Next() bool {
	r.index++
	return r.index < len(r.data)
}

func (r *fakeRows) Scan(dest ...any) error {
	if len(dest) != len(r.data[r.index]) {
		return errors.New("wrong scan width")
	}
	for i, target := range dest {
		out := reflect.ValueOf(target).Elem()
		if r.data[r.index][i] == nil {
			out.SetZero()
			continue
		}
		value := reflect.ValueOf(r.data[r.index][i])
		if !value.Type().AssignableTo(out.Type()) {
			return errors.New("wrong scan type")
		}
		out.Set(value)
	}
	return nil
}

func (r *fakeRows) Err() error   { return nil }
func (r *fakeRows) Close() error { r.closed = true; return nil }

func testStore(t *testing.T, rows *fakeRows) (*Store, *fakeClient) {
	t.Helper()
	client := &fakeClient{rows: rows}
	store, err := NewStore(client)
	if err != nil {
		t.Fatal(err)
	}
	return store, client
}

func TestHierarchyNodeAsOfQueryAndParse(t *testing.T) {
	hash := make([]byte, 32)
	hash[0] = 42
	rows := newRows([]any{int64(7), hash})
	store, client := testStore(t, rows)
	node, err := store.GetHierarchyNodeAt(context.Background(), "SHARD", "R0", 2, 1, 8193, 10)
	if err != nil {
		t.Fatal(err)
	}
	if node.VersionEpoch != 7 || node.Index != 8193 || node.Hash[0] != 42 || !rows.closed {
		t.Fatalf("unexpected decoded node: %+v", node)
	}
	if !strings.Contains(client.statement, "node_index=? AND version_epoch<=? LIMIT 1") {
		t.Fatalf("query does not select latest eligible version: %s", client.statement)
	}
	wantArgs := []any{"SHARD", "R0", int64(2), int32(1), int64(2), int64(8193), int64(10)}
	if !reflect.DeepEqual(client.args, wantArgs) {
		t.Fatalf("args = %#v, want %#v", client.args, wantArgs)
	}
}

func TestPageAsOfQueryParsesNullableLinksAndCopiesData(t *testing.T) {
	var id uuid.UUID
	id[0] = 7
	key, err := domain.Serialize(id)
	if err != nil {
		t.Fatal(err)
	}
	address, err := domain.Serialize("R0", "2", "3", "4")
	if err != nil {
		t.Fatal(err)
	}
	value := append(append(blob(key), address...), make([]byte, 32)...)
	payload := PagePayload{IsLeaf: true, Keys: [][]byte{key}, Values: [][]byte{value}}
	data, err := EncodePagePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := payload.Hash("R0", 513)
	if err != nil {
		t.Fatal(err)
	}
	parent, next := int64(3), int64(9)
	rows := newRows([]any{int64(4), true, &parent, nil, &next, hash[:], data})
	store, client := testStore(t, rows)
	page, err := store.GetPageAt(context.Background(), "R0", "id", 513, 8)
	if err != nil {
		t.Fatal(err)
	}
	data[0] = 99 // Parsed blobs must not retain cursor-owned memory.
	if page.VersionEpoch != 4 || page.PrevPageID != nil || page.ParentPageID == nil ||
		*page.ParentPageID != 3 || page.NextPageID == nil || *page.NextPageID != 9 || page.Data[0] != 1 {
		t.Fatalf("unexpected decoded page: %+v", page)
	}
	wantArgs := []any{"R0", "id", int64(2), int64(513), int64(8)}
	if !reflect.DeepEqual(client.args, wantArgs) || !strings.Contains(client.statement, "version_epoch<=? LIMIT 1") {
		t.Fatalf("query/args = %s / %#v", client.statement, client.args)
	}
}

func TestPagePayloadRejectsUnauthenticatedLeafKey(t *testing.T) {
	var id uuid.UUID
	id[0] = 3
	key, _ := domain.Serialize(id)
	addr, _ := domain.Serialize("R0", "1", "2", "3")
	value := append(append(blob(key), addr...), make([]byte, 32)...)
	payload := PagePayload{IsLeaf: true, Keys: [][]byte{blob(key)}, Values: [][]byte{value}}
	hash, err := payload.Hash("R0", 0)
	if err != nil {
		t.Fatal(err)
	}
	payload.Keys[0][0] ^= 0xff // Leaf hash commits to Values, so check key/value agreement.
	data, err := EncodePagePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (PageVersion{RegionID: "R0", View: "id", PageID: 0, IsLeaf: true, Hash: hash, Data: data}).DecodePageData(); err == nil {
		t.Fatal("accepted a leaf key inconsistent with its authenticated value")
	}
}

func TestInternalPagePayloadRoundTripAndHash(t *testing.T) {
	var id uuid.UUID
	id[0] = 5
	key, _ := domain.Serialize(id)
	payload := PagePayload{
		Keys:     [][]byte{key},
		Values:   [][]byte{},
		Children: []PageChild{{PageID: 1, Hash: [32]byte{1}}, {PageID: 2, Hash: [32]byte{2}}},
	}
	data, err := EncodePagePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := payload.Hash("R0", 3)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := (PageVersion{RegionID: "R0", View: "id", PageID: 3, Hash: hash, Data: data}).DecodePageData()
	if err != nil || !reflect.DeepEqual(decoded, payload) {
		t.Fatalf("decoded internal page = %#v, err = %v", decoded, err)
	}
	if _, err := DecodePagePayload(data[:len(data)-1]); err == nil {
		t.Fatal("accepted truncated internal page")
	}
}

func TestAttributePagePayloadParsesTimestampKey(t *testing.T) {
	var id uuid.UUID
	id[0] = 8
	key, err := domain.Serialize("site", "device", "type", time.Unix(0, 123456789).UTC(), id)
	if err != nil {
		t.Fatal(err)
	}
	address, err := domain.Serialize("R1", "2", "3", "4")
	if err != nil {
		t.Fatal(err)
	}
	value := append(append(blob(key), address...), make([]byte, 32)...)
	payload := PagePayload{IsLeaf: true, Keys: [][]byte{key}, Values: [][]byte{value}}
	data, err := EncodePagePayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := payload.Hash("R1", 12)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (PageVersion{RegionID: "R1", View: "attribute", PageID: 12, IsLeaf: true, Hash: hash, Data: data}).DecodePageData(); err != nil {
		t.Fatal(err)
	}
}

func TestShardFilterVersionAndBitParsing(t *testing.T) {
	bits := FilterBits([]uint64{0x1234, 1})
	rows := newRows([]any{int64(6), int64(65), int64(3), bits})
	store, client := testStore(t, rows)
	filter, err := store.GetShardFilterAt(context.Background(), "R0", 4, 9)
	if err != nil {
		t.Fatal(err)
	}
	words, err := filter.Words()
	if err != nil {
		t.Fatal(err)
	}
	if filter.Epoch != 6 || !reflect.DeepEqual(words, []uint64{0x1234, 1}) {
		t.Fatalf("filter = %+v; words = %v", filter, words)
	}
	if !reflect.DeepEqual(client.args, []any{"R0", int64(4), int64(9)}) {
		t.Fatalf("wrong bound args: %#v", client.args)
	}
	if err := (FilterRecord{BitCount: 65, HashCount: 3, Bits: FilterBits([]uint64{1, 2})}).Validate(); err == nil {
		t.Fatal("accepted a set bit outside m")
	}
}

func TestMalformedHashAndMissingRow(t *testing.T) {
	store, _ := testStore(t, newRows([]any{[]byte{1}}))
	if _, err := store.GetMVARoot(context.Background(), 1); err == nil || !strings.Contains(err.Error(), "want 32") {
		t.Fatalf("bad root error = %v", err)
	}
	store, _ = testStore(t, newRows())
	if _, err := store.GetHPBFRoot(context.Background(), 1); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing root error = %v", err)
	}
}

func TestInvalidEpochAndBoundWrites(t *testing.T) {
	store, client := testStore(t, nil)
	if _, err := store.GetMVARoot(context.Background(), uint64(math.MaxInt64)+1); err == nil {
		t.Fatal("accepted epoch outside CQL bigint")
	}
	root := [32]byte{9}
	if err := store.PutMVARoot(context.Background(), 5, root); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(client.statement, "VALUES (?,?)") ||
		!reflect.DeepEqual(client.args[0], int64(5)) ||
		!reflect.DeepEqual(client.args[1], root[:]) {
		t.Fatalf("root write = %s / %#v", client.statement, client.args)
	}
}

func TestFrontierCodecRoundTripAndRejectsTruncation(t *testing.T) {
	nodes := []merkle.MerkleNode{
		{Level: 0, Index: 3, Hash: [32]byte{1}},
		{Level: 2, Index: 0, Hash: [32]byte{2}},
	}
	encoded, err := EncodeFrontier(nodes)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeFrontier(encoded)
	if err != nil || !reflect.DeepEqual(decoded, nodes) {
		t.Fatalf("decoded = %#v, err = %v", decoded, err)
	}
	if _, err := DecodeFrontier(encoded[:len(encoded)-1]); err == nil {
		t.Fatal("accepted truncated frontier")
	}
	empty, err := EncodeFrontier(nil)
	if err != nil {
		t.Fatal(err)
	}
	if decoded, err := DecodeFrontier(empty); err != nil || len(decoded) != 0 {
		t.Fatalf("empty frontier = %v, %v", decoded, err)
	}
}

func TestNullableActiveSegmentAndGlobalSentinel(t *testing.T) {
	rows := newRows([]any{nil, nil, nil, int64(11)})
	store, _ := testStore(t, rows)
	active, err := store.GetActiveSegment(context.Background(), "R0", 2)
	if err != nil {
		t.Fatal(err)
	}
	if active.SegmentID != nil || active.OpenedAtNS != nil || active.LeafCount != nil || active.NextSegmentID != 11 {
		t.Fatalf("unexpected active state: %+v", active)
	}
	store, client := testStore(t, nil)
	if err := store.PutHierarchyNode(context.Background(), HierarchyNode{
		Kind: "GLOBAL", MerkleNodeRecord: MerkleNodeRecord{Level: 0, Index: 0}, VersionEpoch: 7,
	}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(client.args[:3], []any{"GLOBAL", "", int64(-1)}) {
		t.Fatalf("global tree ID args = %#v", client.args[:3])
	}
}
