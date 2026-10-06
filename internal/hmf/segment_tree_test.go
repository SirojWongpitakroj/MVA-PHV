package hmf

import (
	"encoding/hex"
	"testing"
	"uuid"
)

func TestSegmentAppendHashesLeaf(t *testing.T) {
	logID := uuid.UUID{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	var h [32]byte
	for i := range h {
		h[i] = byte(i + 32)
	}
	const want = "25b6d429614fc7931e03a66b98cf48399dd0ddde80a92e905a1e2a3c4028f0ce"

	tree := NewSegmentTree("region", 1, 1, 2)
	if err := tree.Append(logID, h); err != nil {
		t.Fatal(err)
	}
	updates, err := tree.Seal()
	if err != nil {
		t.Fatal(err)
	}
	if len(updates) != 1 {
		t.Fatalf("got %d nodes, want one leaf", len(updates))
	}
	if got := hex.EncodeToString(updates[0].Hash[:]); got != want {
		t.Fatalf("leaf hash = %s, want %s", got, want)
	}
	if tree.Root != updates[0].Hash {
		t.Fatal("single-leaf root differs from its leaf hash")
	}
}
