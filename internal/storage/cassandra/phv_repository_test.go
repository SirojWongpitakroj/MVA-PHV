package cassandra

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
	"github.com/SirojWongpitakroj/mva-phv/internal/phv"
)

func TestPHVReadsOnlyPlannedSegmentPosition(t *testing.T) {
	hash := make([]byte, 32)
	hash[0] = 17
	rows := newRows([]any{hash})
	store, client := testStore(t, rows)
	id := merkle.TreeID{Type: merkle.TreeSegment, RegionID: "R", ShardID: 2, SegmentID: 5}
	key := phv.NodeKey{Tree: id, Level: 1, Index: 3}
	nodes, err := store.FetchNodes(context.Background(), 8, id, []phv.NodeKey{key})
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].Key != key || nodes[0].Hash[0] != 17 || !rows.closed {
		t.Fatalf("nodes=%+v", nodes)
	}
	if !strings.Contains(client.statement, "seg_id=? AND level=? AND node_index=?") {
		t.Fatalf("query is not position-specific: %s", client.statement)
	}
	want := []any{"R", int64(2), int64(5), int32(1), int64(3)}
	if !reflect.DeepEqual(client.args, want) {
		t.Fatalf("args=%#v want=%#v", client.args, want)
	}
}

func TestPHVNodePartitionMatchesCQLClustering(t *testing.T) {
	store, _ := testStore(t, newRows())
	segment := merkle.TreeID{Type: merkle.TreeSegment, RegionID: "R", ShardID: 2, SegmentID: 4}
	a, err := store.NodePartition(phv.NodeKey{Tree: segment, Level: 0, Index: 1})
	if err != nil {
		t.Fatal(err)
	}
	b, err := store.NodePartition(phv.NodeKey{Tree: segment, Level: 4, Index: 100})
	if err != nil || a != b {
		t.Fatalf("Segment nodes split across partitions: %q %q %v", a, b, err)
	}
	shard := merkle.TreeID{Type: merkle.TreeShard, RegionID: "R", ShardID: 2}
	a, err = store.NodePartition(phv.NodeKey{Tree: shard, Level: 1, Index: 4095})
	if err != nil {
		t.Fatal(err)
	}
	b, err = store.NodePartition(phv.NodeKey{Tree: shard, Level: 1, Index: 4096})
	if err != nil || a == b {
		t.Fatalf("different buckets merged: %q %q %v", a, b, err)
	}
	c, err := store.NodePartition(phv.NodeKey{Tree: shard, Level: 2, Index: 4095})
	if err != nil || a == c {
		t.Fatalf("different levels merged: %q %q %v", a, c, err)
	}
}
