package hmf

import (
	"crypto/sha256"
	"fmt"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

// InternalHash applies the HMF domain tag for one hierarchy level. PHV uses
// this read-only helper when contracting a proof frontier.
func InternalHash(kind merkle.TreeType, left, right [32]byte) ([32]byte, error) {
	var tag string
	switch kind {
	case merkle.TreeSegment:
		tag = "SEGINT"
	case merkle.TreeShard:
		tag = "SHARDINT"
	case merkle.TreeRegion:
		tag = "REGINT"
	case merkle.TreeGlobal:
		tag = "GLOBALINT"
	default:
		return [32]byte{}, fmt.Errorf("HMF internal hash: unsupported tree type %q", kind)
	}
	var node merkle.MerkleNode
	if err := node.ComputeInternalHash(tag, left, right); err != nil {
		return [32]byte{}, err
	}
	return node.Hash, nil
}

// RootHash computes the existing HMF tree wrapper without mutating a tree.
// PHV uses it after reconstructing a Merkle top value from a multiproof.
func RootHash(id merkle.TreeID, leafCount int64, top [32]byte) ([32]byte, error) {
	if leafCount <= 0 {
		return [32]byte{}, fmt.Errorf("HMF root: empty tree")
	}
	var fields []any
	switch id.Type {
	case merkle.TreeSegment:
		if id.RegionID == "" || id.ShardID < 0 || id.SegmentID < 0 {
			return [32]byte{}, fmt.Errorf("HMF root: invalid Segment ID")
		}
		fields = []any{string(id.Type), id.RegionID, uint64(id.ShardID), uint64(id.SegmentID)}
	case merkle.TreeShard:
		if id.RegionID == "" || id.ShardID < 0 {
			return [32]byte{}, fmt.Errorf("HMF root: invalid Shard ID")
		}
		fields = []any{string(id.Type), id.RegionID, uint64(id.ShardID)}
	case merkle.TreeRegion:
		if id.RegionID == "" {
			return [32]byte{}, fmt.Errorf("HMF root: invalid Region ID")
		}
		fields = []any{string(id.Type), id.RegionID}
	case merkle.TreeGlobal:
		fields = []any{string(id.Type)}
	default:
		return [32]byte{}, fmt.Errorf("HMF root: unsupported tree type %q", id.Type)
	}
	encodedID, err := domain.Serialize(fields...)
	if err != nil {
		return [32]byte{}, err
	}
	preimage, err := domain.Serialize([]byte("TREE"), encodedID, uint64(leafCount), top[:])
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(preimage), nil
}
