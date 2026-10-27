package canonicalize

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"uuid"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
	"github.com/SirojWongpitakroj/mva-phv/internal/mpm"
)

// AEADService encrypts accepted logs with a caller-managed AES-256 key.
// The key must be retained by the application so stored logs remain decryptable.
type AEADService struct {
	aead cipher.AEAD
	rand io.Reader
}

var _ mpm.Encryptor = (*AEADService)(nil)

func NewAEADService(key []byte) (*AEADService, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AEAD service: AES-256 key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &AEADService{aead: aead, rand: rand.Reader}, nil
}

func (s *AEADService) Encrypt(ctx context.Context, id uuid.UUID, descriptor mpm.Descriptor, plaintext []byte) (mpm.Encrypted, error) {
	if s == nil || s.aead == nil {
		return mpm.Encrypted{}, fmt.Errorf("AEAD service: not initialized")
	}
	if err := ctx.Err(); err != nil {
		return mpm.Encrypted{}, err
	}
	ad, err := domain.Serialize("MVA-PHV:LOG:V1", id, descriptor.RegionID,
		descriptor.SiteID, descriptor.DeviceID, descriptor.Type, descriptor.TS.UTC())
	if err != nil {
		return mpm.Encrypted{}, err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(s.rand, nonce); err != nil {
		return mpm.Encrypted{}, err
	}
	sealed := s.aead.Seal(nil, nonce, plaintext, ad)
	tagStart := len(sealed) - s.aead.Overhead()
	ciphertext := sealed[:tagStart]
	tag := sealed[tagStart:]
	// C_i is nonce || ciphertext || tag; the AEAD tag also authenticates AD.
	bytes := make([]byte, 0, len(nonce)+len(sealed))
	bytes = append(bytes, nonce...)
	bytes = append(bytes, sealed...)
	return mpm.Encrypted{Ciphertext: ciphertext, Nonce: nonce, Tag: tag,
		AD: ad, Digest: sha256.Sum256(bytes)}, nil
}
