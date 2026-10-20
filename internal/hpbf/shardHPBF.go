package hpbf

import (
	"crypto/sha256"
	"fmt"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
)

type ShardHPBF struct {
	RegionID    string
	ShardID     int64
	bloomFilter *BloomFilter
	RootHash    [32]byte
}

func newShardHPBF(regionID string, shardID int64, n int, p float64) (*ShardHPBF, error) {
	bf, err := newBloomFilter(n, p)
	if err != nil {
		return nil, err
	}

	return &ShardHPBF{
		RegionID:    regionID,
		ShardID:     shardID,
		bloomFilter: bf,
	}, nil
}

// AddToken adds the site, site-device, and site-device-type tokens.
func (s *ShardHPBF) AddToken(siteID, devID, typ string) error {
	if s == nil || s.bloomFilter == nil {
		return fmt.Errorf("shard bloom filter is nil")
	}

	siteToken, err := domain.Serialize(siteID)
	if err != nil {
		return err
	}
	siteDevToken, err := domain.Serialize(siteID, devID)
	if err != nil {
		return err
	}
	siteDevTypeToken, err := domain.Serialize(siteID, devID, typ)
	if err != nil {
		return err
	}

	s.bloomFilter.Add(siteToken)
	s.bloomFilter.Add(siteDevToken)
	s.bloomFilter.Add(siteDevTypeToken)
	return nil
}

// Contains reports whether all three tokens for the given attributes may be present.
func (s *ShardHPBF) Contains(siteID, devID, typ string) (bool, error) {
	if s == nil || s.bloomFilter == nil {
		return false, fmt.Errorf("shard bloom filter is nil")
	}

	siteToken, err := domain.Serialize(siteID)
	if err != nil {
		return false, err
	}
	siteDevToken, err := domain.Serialize(siteID, devID)
	if err != nil {
		return false, err
	}
	siteDevTypeToken, err := domain.Serialize(siteID, devID, typ)
	if err != nil {
		return false, err
	}

	return s.bloomFilter.Contains(siteToken) &&
		s.bloomFilter.Contains(siteDevToken) &&
		s.bloomFilter.Contains(siteDevTypeToken), nil
}

// Commitment hashes the shard Bloom filter state for the given epoch.
func (s *ShardHPBF) Commitment(epoch uint64) ([32]byte, *BloomFilter, error) {
	if s == nil || s.bloomFilter == nil {
		return [32]byte{}, nil, fmt.Errorf("shard bloom filter is nil")
	}
	bf := s.bloomFilter
	if bf.m == 0 || bf.k == 0 || uint64(len(bf.bits)) != (bf.m-1)/64+1 {
		return [32]byte{}, nil, fmt.Errorf("shard bloom filter is invalid")
	}

	bfParts := make([]any, 0, 2+len(bf.bits))
	bfParts = append(bfParts, bf.m, bf.k)
	for _, word := range bf.bits {
		bfParts = append(bfParts, word)
	}
	encodedBF, err := domain.Serialize(bfParts...)
	if err != nil {
		return [32]byte{}, nil, err
	}
	encoded, err := domain.Serialize(
		[]byte("SHBF"), epoch, s.RegionID, uint64(s.ShardID), encodedBF,
	)
	if err != nil {
		return [32]byte{}, nil, err
	}
	s.RootHash = sha256.Sum256(encoded)
	return s.RootHash, bf, nil
}
