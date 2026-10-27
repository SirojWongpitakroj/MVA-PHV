package mpm

import (
	"crypto/sha256"
	"fmt"
	"uuid"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
)

// CanonicalLocator implements c_i = H(LOC || LogID || enc(X_i) || enc(A_i)).
// The fields use the repository's existing domain.Serialize encodings.
type CanonicalLocator struct{}

var _ LocatorCommitter = CanonicalLocator{}

func (CanonicalLocator) CommitLocator(id uuid.UUID, descriptor Descriptor, address Address) ([32]byte, error) {
	if id == (uuid.UUID{}) || descriptor.RegionID == "" || descriptor.SiteID == "" ||
		descriptor.DeviceID == "" || descriptor.Type == "" || descriptor.TS.IsZero() ||
		address.RegionID != descriptor.RegionID || address.ShardID < 0 ||
		address.SegmentID < 0 || address.LeafID < 0 {
		return [32]byte{}, fmt.Errorf("locator commitment: invalid descriptor or physical address")
	}
	encoded, err := domain.Serialize([]byte("LOC"), id,
		descriptor.RegionID, descriptor.SiteID, descriptor.DeviceID, descriptor.Type, descriptor.TS.UTC(),
		address.RegionID, uint64(address.ShardID), uint64(address.SegmentID), uint64(address.LeafID))
	if err != nil {
		return [32]byte{}, fmt.Errorf("locator commitment: %w", err)
	}
	return sha256.Sum256(encoded), nil
}
