package cassandra

import (
	"encoding/binary"
	"fmt"
	"time"
)

// Record types mirror schema.cql. Hashes are fixed-size so malformed blobs are
// rejected when read. PageData and FrontierData use versioned codecs here;
// their byte fields stay available for a future driver adapter.

type SegmentKey struct {
	RegionID  string
	ShardID   int64
	SegmentID int64
}

type ActiveSegment struct {
	RegionID      string
	ShardID       int64
	SegmentID     *int64 // nil after sealing, until the next insertion.
	OpenedAtNS    *int64
	LeafCount     *int64
	NextSegmentID int64
}

type SealedSegment struct {
	SegmentKey
	Root           [32]byte
	LeafCount      int64
	TreeHeight     int32
	MaxLeaves      int32
	OpenedAtNS     int64
	SealedAtNS     int64
	FinalizedEpoch *int64
	PersistedAt    time.Time
}

type MerkleNodeRecord struct {
	Level int32
	Index int64
	Hash  [32]byte
}

type HierarchyNode struct {
	Kind     string // SHARD, REGION, GLOBAL.
	RegionID string
	ShardID  int64
	MerkleNodeRecord
	VersionEpoch int64
}

type ShardState struct {
	RegionID     string
	ShardID      int64
	Epoch        int64
	Root         [32]byte
	SegmentCount int64
	TreeHeight   int32
	FrontierData []byte
}

type RegionState struct {
	RegionID   string
	Epoch      int64
	Root       [32]byte
	ShardCount int64
	TreeHeight int32
}

type GlobalState struct {
	Scope       string
	Epoch       int64
	Root        [32]byte
	RegionCount int64
	TreeHeight  int32
}

type PageVersion struct {
	RegionID     string
	View         string // id or attribute.
	PageID       int64
	VersionEpoch int64
	IsLeaf       bool
	ParentPageID *int64
	PrevPageID   *int64
	NextPageID   *int64
	Hash         [32]byte
	Data         []byte
}

type ViewState struct {
	RegionID    string
	View        string
	Epoch       int64 // WorkingEpoch or finalized epoch, depending on table.
	RootPageID  int64
	RootHash    [32]byte
	TreeHeight  int32
	RecordCount int64
	NextPageID  int64
	TreeOrder   int32
}

type MVARegionCommitment struct {
	Epoch       int64
	RegionIndex int64
	RegionID    string
	IDRoot      [32]byte
	AttrRoot    [32]byte
	RegionRoot  [32]byte
}

type EpochNode struct {
	Epoch int64
	MerkleNodeRecord
}

// FilterRecord stores the BloomFilter word array as big-endian uint64 words.
// The CQL bit_count is the number of usable positions, not necessarily a
// multiple of 64; hash_count is the number of hash-derived positions.
type FilterRecord struct {
	RegionID  string
	ShardID   int64
	Epoch     int64 // WorkingEpoch or VersionEpoch, depending on table.
	BitCount  int64
	HashCount int64
	Bits      []byte
}

func (f FilterRecord) Validate() error {
	if f.BitCount <= 0 || f.HashCount <= 0 {
		return fmt.Errorf("cassandra: invalid Bloom filter m=%d k=%d", f.BitCount, f.HashCount)
	}
	words := (uint64(f.BitCount)-1)/64 + 1
	if uint64(len(f.Bits))/8 != words || len(f.Bits)%8 != 0 {
		return fmt.Errorf("cassandra: Bloom filter has %d bytes, want %d", len(f.Bits), words*8)
	}
	if rem := uint64(f.BitCount) % 64; rem != 0 {
		last := binary.BigEndian.Uint64(f.Bits[len(f.Bits)-8:])
		if last>>rem != 0 {
			return fmt.Errorf("cassandra: Bloom filter has bits set beyond m=%d", f.BitCount)
		}
	}
	return nil
}

func (f FilterRecord) Words() ([]uint64, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	words := make([]uint64, len(f.Bits)/8)
	for i := range words {
		words[i] = binary.BigEndian.Uint64(f.Bits[i*8:])
	}
	return words, nil
}

func FilterBits(words []uint64) []byte {
	data := make([]byte, len(words)*8)
	for i, word := range words {
		binary.BigEndian.PutUint64(data[i*8:], word)
	}
	return data
}

type HPBFShardCommitment struct {
	Epoch              int64
	RegionID           string
	ShardID            int64
	ShardIndex         int64
	FilterVersionEpoch int64
	Commitment         [32]byte
}

type HPBFRegionRoot struct {
	Epoch       int64
	RegionIndex int64
	RegionID    string
	Root        [32]byte
}
