package hpbf

import (
	"fmt"
	"math"

	"github.com/zeebo/xxh3"
)

type BloomFilter struct {
	bits []uint64
	m    uint64 // Number of usable bit positions.
	k    uint64 // Number of hash-derived positions per token.
}

func newBloomFilter(n int, p float64) (*BloomFilter, error) {
	if n <= 0 || math.IsNaN(p) || p <= 0 || p >= 1 {
		return nil, fmt.Errorf("bloom filter requires n > 0 and 0 < p < 1")
	}

	ln2 := math.Ln2
	mFloat := math.Ceil(-float64(n) * math.Log(p) / (ln2 * ln2))
	if math.IsInf(mFloat, 0) || mFloat >= float64(math.MaxInt) {
		return nil, fmt.Errorf("bloom filter bit count exceeds int range")
	}
	m := int(mFloat)
	k := max(1, int(math.Round(float64(m)/float64(n)*ln2)))

	return &BloomFilter{
		bits: make([]uint64, (m-1)/64+1),
		m:    uint64(m),
		k:    uint64(k),
	}, nil
}

func (bf *BloomFilter) Clone() *BloomFilter {
	return &BloomFilter{
		bits: append([]uint64(nil), bf.bits...),
		m:    bf.m,
		k:    bf.k,
	}
}

// Snapshot returns a detached filter encoding for evidence storage.
func (bf *BloomFilter) Snapshot() (m, k uint64, words []uint64) {
	if bf == nil {
		return 0, 0, nil
	}
	return bf.m, bf.k, append([]uint64(nil), bf.bits...)
}

func (bf *BloomFilter) positions(token []byte) []uint64 {
	h := xxh3.Hash128(token)

	h1 := h.Hi
	h2 := h.Lo

	pos := make([]uint64, bf.k)

	for i := uint64(0); i < bf.k; i++ {
		pos[i] = (h1 + i*h2) % bf.m
	}
	return pos
}

func (bf *BloomFilter) setBit(pos uint64) {
	bf.bits[pos/64] |= uint64(1) << (pos % 64)
}

func (bf *BloomFilter) getBit(pos uint64) bool {
	return bf.bits[pos/64]&(uint64(1)<<(pos%64)) != 0
}

func (bf *BloomFilter) Add(token []byte) {
	pos := bf.positions(token)

	for _, p := range pos {
		bf.setBit(p)
	}
}

func (bf *BloomFilter) Contains(token []byte) bool {
	for _, pos := range bf.positions(token) {
		if !bf.getBit(pos) {
			return false
		}
	}
	return true
}

// Merge adds every bit set in other to bf. Both filters must use the same
// bit length and number of hash positions.
func (bf *BloomFilter) Merge(other BloomFilter) error {
	if bf == nil {
		return fmt.Errorf("merge bloom filter: receiver is nil")
	}
	if bf.m != other.m || bf.k != other.k || len(bf.bits) != len(other.bits) {
		return fmt.Errorf("merge bloom filter: incompatible filters")
	}

	for i, word := range other.bits {
		bf.bits[i] |= word
	}
	return nil
}
