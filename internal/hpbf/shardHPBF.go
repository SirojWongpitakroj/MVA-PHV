package hpbf

import (
	"crypto/sha256"
	"fmt"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

type ShardHPBF struct {
	merkle.TreeID
	bloomFilter *BloomFilter
	RootHash    [32]byte
}

func newShardHPBF(regionID string, shardID int64, n int, p float64) (*ShardHPBF, error) {
	bf, err := newBloomFilter(n, p)
	if err != nil {
		return nil, err
	}

	return &ShardHPBF{
		TreeID: merkle.TreeID{
			Type:     merkle.TreeShard,
			RegionID: regionID,
			ShardID:  shardID,
		},
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

// Contains reports a possible match and returns the shard Bloom filter as proof.
func (s *ShardHPBF) Contains(siteID, devID, typ string) (bool, ShardHPBFProof, error) {
	if s == nil || s.bloomFilter == nil {
		return false, ShardHPBFProof{}, fmt.Errorf("shard bloom filter is nil")
	}

	siteToken, err := domain.Serialize(siteID)
	if err != nil {
		return false, ShardHPBFProof{}, err
	}
	siteDevToken, err := domain.Serialize(siteID, devID)
	if err != nil {
		return false, ShardHPBFProof{}, err
	}
	siteDevTypeToken, err := domain.Serialize(siteID, devID, typ)
	if err != nil {
		return false, ShardHPBFProof{}, err
	}

	contains := s.bloomFilter.Contains(siteToken) &&
		s.bloomFilter.Contains(siteDevToken) &&
		s.bloomFilter.Contains(siteDevTypeToken)
	if !contains {
		return false, ShardHPBFProof{}, nil
	}
	return true, ShardHPBFProof{
		TreeID:      s.TreeID,
		BloomFilter: *s.bloomFilter.Clone(),
	}, nil
}

// Commitment hashes the shard Bloom filter state for the given epoch.
func (s *ShardHPBF) Commitment(epoch, index uint64) (ShardHPBFPartition, error) {
	if s == nil || s.bloomFilter == nil {
		return ShardHPBFPartition{}, fmt.Errorf("shard bloom filter is nil")
	}
	bf := s.bloomFilter
	if bf.m == 0 || bf.k == 0 || uint64(len(bf.bits)) != (bf.m-1)/64+1 {
		return ShardHPBFPartition{}, fmt.Errorf("shard bloom filter is invalid")
	}

	bfParts := make([]any, 0, 2+len(bf.bits))
	bfParts = append(bfParts, bf.m, bf.k)
	for _, word := range bf.bits {
		bfParts = append(bfParts, word)
	}
	encodedBF, err := domain.Serialize(bfParts...)
	if err != nil {
		return ShardHPBFPartition{}, err
	}
	encoded, err := domain.Serialize(
		[]byte("SHBF"), epoch, s.TreeID.RegionID, uint64(s.TreeID.ShardID), encodedBF,
	)
	if err != nil {
		return ShardHPBFPartition{}, err
	}
	s.RootHash = sha256.Sum256(encoded)
	return ShardHPBFPartition{
		TreeID:      s.TreeID,
		BloomFilter: bf,
		Commitment:  s.RootHash,
		Epoch:       epoch,
		Index:       index,
	}, nil
}
