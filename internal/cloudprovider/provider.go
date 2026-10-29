package cloudprovider

import (
	"context"
	"errors"
	"fmt"
	"uuid"
)

// Ciphertext is the external provider's opaque encrypted log. It carries no
// MVA, HPBF, HMF, checkpoint, descriptor, or physical-address evidence.
type Ciphertext struct {
	LogID      uuid.UUID
	Ciphertext []byte
	Nonce      []byte
	Tag        []byte
	AD         []byte
	Version    uint16 // Version 1 is the current AES-256-GCM encoding.
}

const EncryptionVersionAESGCM uint16 = 1

var ErrUnsupportedVersion = errors.New("cloud provider: unsupported encryption version")

// ValidateCiphertext checks retrieval metadata only. Authentication remains
// the auditor's job against the finalized checkpoint.
func ValidateCiphertext(value Ciphertext) error {
	if value.Version != EncryptionVersionAESGCM {
		return ErrUnsupportedVersion
	}
	if value.LogID == (uuid.UUID{}) || len(value.Nonce) != 12 || len(value.Tag) != 16 || len(value.AD) == 0 {
		return fmt.Errorf("cloud provider: malformed encrypted record")
	}
	return nil
}

// Region is a deployment routing hint, not an HMF address. LogID is the only
// record identifier understood by the external Cloud Provider.
type Writer interface {
	StoreCiphertext(ctx context.Context, region string, value Ciphertext) error
}

type Reader interface {
	GetCiphertexts(ctx context.Context, region string, ids []uuid.UUID) ([]Ciphertext, error)
}

type Provider interface {
	Writer
	Reader
}

var ErrConflict = errors.New("cloud provider: LogID already stores different ciphertext")

// Router lets deployment configuration choose an independent external backend
// for each logical Region without exposing HMF positions to that backend.
type Router struct{ regions map[string]Provider }

func NewRouter(regions map[string]Provider) (*Router, error) {
	if len(regions) == 0 {
		return nil, fmt.Errorf("cloud provider: no regions configured")
	}
	copyRegions := make(map[string]Provider, len(regions))
	for region, provider := range regions {
		if region == "" || provider == nil {
			return nil, fmt.Errorf("cloud provider: invalid region %q", region)
		}
		copyRegions[region] = provider
	}
	return &Router{regions: copyRegions}, nil
}

func (r *Router) provider(region string) (Provider, error) {
	if r == nil || r.regions[region] == nil {
		return nil, fmt.Errorf("cloud provider: no backend for region %q", region)
	}
	return r.regions[region], nil
}

func (r *Router) StoreCiphertext(ctx context.Context, region string, value Ciphertext) error {
	provider, err := r.provider(region)
	if err != nil {
		return err
	}
	return provider.StoreCiphertext(ctx, region, value)
}

func (r *Router) GetCiphertexts(ctx context.Context, region string, ids []uuid.UUID) ([]Ciphertext, error) {
	provider, err := r.provider(region)
	if err != nil {
		return nil, err
	}
	return provider.GetCiphertexts(ctx, region, ids)
}
