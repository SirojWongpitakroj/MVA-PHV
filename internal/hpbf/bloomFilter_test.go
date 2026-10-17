package hpbf

import (
	"math"
	"slices"
	"testing"
)

func TestNewBloomFilterSizing(t *testing.T) {
	for _, tc := range []struct {
		name  string
		n     int
		p     float64
		m, k  uint64
		words int
	}{
		{"single bit", 1, math.Nextafter(1, 0), 1, 1, 1},
		{"one token", 1, 0.5, 2, 1, 1},
		{"multiple words", 1000, 0.01, 9586, 7, 150},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bf, err := newBloomFilter(tc.n, tc.p)
			if err != nil {
				t.Fatal(err)
			}
			if bf.m != tc.m || bf.k != tc.k || len(bf.bits) != tc.words {
				t.Fatalf("m=%d, k=%d, words=%d; want %d, %d, %d", bf.m, bf.k, len(bf.bits), tc.m, tc.k, tc.words)
			}
			for _, word := range bf.bits {
				if word != 0 {
					t.Fatal("new filter has a set bit")
				}
			}
		})
	}

	bf, err := newBloomFilter(1, math.SmallestNonzeroFloat64)
	if err != nil || bf.m == 0 || bf.k == 0 || uint64(len(bf.bits)) != (bf.m-1)/64+1 {
		t.Fatalf("very small valid p: filter=%+v, err=%v", bf, err)
	}
}

func TestNewBloomFilterRejectsInvalidInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    int
		p    float64
	}{
		{"zero capacity", 0, 0.01},
		{"negative capacity", -1, 0.01},
		{"zero probability", 1, 0},
		{"negative probability", 1, -0.1},
		{"probability one", 1, 1},
		{"probability above one", 1, 1.1},
		{"NaN", 1, math.NaN()},
		{"positive infinity", 1, math.Inf(1)},
		{"negative infinity", 1, math.Inf(-1)},
		{"bit count overflow", math.MaxInt, 0.01},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bf, err := newBloomFilter(tc.n, tc.p)
			if err == nil || bf != nil {
				t.Fatalf("newBloomFilter(%d, %v) = %+v, %v; want nil and error", tc.n, tc.p, bf, err)
			}
		})
	}
}

func TestPositionsAreDeterministicAndInRange(t *testing.T) {
	bf, err := newBloomFilter(100, 0.01)
	if err != nil {
		t.Fatal(err)
	}
	first := bf.positions([]byte("token"))
	if len(first) != int(bf.k) || !slices.Equal(first, bf.positions([]byte("token"))) {
		t.Fatal("positions are not stable or have the wrong count")
	}
	for _, pos := range first {
		if pos >= bf.m {
			t.Fatalf("position %d outside %d-bit filter", pos, bf.m)
		}
	}
	if !slices.Equal(bf.positions(nil), bf.positions([]byte{})) {
		t.Fatal("nil and empty tokens have different positions")
	}
}

func TestSetBitAcrossWordBoundary(t *testing.T) {
	bf := &BloomFilter{bits: make([]uint64, 2), m: 128}
	for _, pos := range []uint64{0, 63, 64, 127} {
		bf.setBit(pos)
		if !bf.getBit(pos) {
			t.Fatalf("position %d was not set", pos)
		}
	}

	if want := uint64(1) | uint64(1)<<63; bf.bits[0] != want {
		t.Fatalf("first word = %064b, want %064b", bf.bits[0], want)
	}
	if want := uint64(1) | uint64(1)<<63; bf.bits[1] != want {
		t.Fatalf("second word = %064b, want %064b", bf.bits[1], want)
	}
	if bf.getBit(1) || bf.getBit(65) {
		t.Fatal("unset bit reported as set")
	}
}

func TestContains(t *testing.T) {
	bf, err := newBloomFilter(100, 0.01)
	if err != nil {
		t.Fatal(err)
	}
	token := []byte("example token")
	if bf.Contains(token) {
		t.Fatal("empty filter contains token")
	}

	bf.Add(token)
	if !bf.Contains(token) {
		t.Fatal("added token is missing")
	}

	pos := bf.positions(token)[0]
	bf.bits[pos/64] &^= uint64(1) << (pos % 64)
	if bf.Contains(token) {
		t.Fatal("token is present despite an unset position")
	}

	bf.Add(nil)
	if !bf.Contains([]byte{}) {
		t.Fatal("empty token was not found after adding nil token")
	}
	before := slices.Clone(bf.bits)
	bf.Add(nil)
	if !slices.Equal(before, bf.bits) {
		t.Fatal("adding the same token twice changed the bits")
	}
}

func TestMerge(t *testing.T) {
	left, err := newBloomFilter(100, 0.01)
	if err != nil {
		t.Fatal(err)
	}
	right, err := newBloomFilter(100, 0.01)
	if err != nil {
		t.Fatal(err)
	}
	left.Add([]byte("left"))
	right.Add([]byte("right"))
	rightBefore := slices.Clone(right.bits)

	want := make([]uint64, len(left.bits))
	for i := range want {
		want[i] = left.bits[i] | right.bits[i]
	}
	if err := left.Merge(*right); err != nil {
		t.Fatal(err)
	}
	for i, word := range left.bits {
		if word != want[i] {
			t.Fatalf("merged word %d = %064b, want %064b", i, word, want[i])
		}
	}
	if !left.Contains([]byte("left")) || !left.Contains([]byte("right")) {
		t.Fatal("merged filter is missing a token")
	}
	if !slices.Equal(right.bits, rightBefore) {
		t.Fatal("merge changed the source filter")
	}
	before := slices.Clone(left.bits)
	if err := left.Merge(*left); err != nil || !slices.Equal(left.bits, before) {
		t.Fatalf("self merge changed filter: %v", err)
	}
}

func TestMergeRejectsIncompatibleFilter(t *testing.T) {
	for _, tc := range []struct {
		name  string
		other BloomFilter
	}{
		{"different bit count", BloomFilter{bits: []uint64{2}, m: 63, k: 2}},
		{"different hash count", BloomFilter{bits: []uint64{2}, m: 64, k: 3}},
		{"different storage length", BloomFilter{bits: []uint64{2, 3}, m: 64, k: 2}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			left := BloomFilter{bits: []uint64{1}, m: 64, k: 2}
			if err := left.Merge(tc.other); err == nil {
				t.Fatal("expected incompatible filters to be rejected")
			}
			if left.bits[0] != 1 {
				t.Fatal("failed merge changed the receiver")
			}
		})
	}
	var nilFilter *BloomFilter
	if err := nilFilter.Merge(BloomFilter{}); err == nil {
		t.Fatal("nil receiver was accepted")
	}
}
