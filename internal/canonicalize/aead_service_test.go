package canonicalize

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"slices"
	"testing"
	"time"
	"uuid"

	"github.com/SirojWongpitakroj/mva-phv/internal/mpm"
)

func TestAEADServiceBindsDescriptorAndDigest(t *testing.T) {
	key := make([]byte, 32)
	service, err := NewAEADService(key)
	if err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	id[15] = 1
	d := mpm.Descriptor{RegionID: "0", SiteID: "site", DeviceID: "device", Type: "type", TS: time.Unix(100, 0)}
	plain := []byte("accepted log")
	enc, err := service.Encrypt(context.Background(), id, d, plain)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	combined := append(slices.Clone(enc.Ciphertext), enc.Tag...)
	opened, err := gcm.Open(nil, enc.Nonce, combined, enc.AD)
	if err != nil || !slices.Equal(opened, plain) {
		t.Fatalf("decrypt: %v", err)
	}
	bytes := append(slices.Clone(enc.Nonce), combined...)
	if enc.Digest != sha256.Sum256(bytes) {
		t.Fatal("ciphertext digest did not bind nonce, ciphertext, and tag")
	}
	changed := d
	changed.DeviceID = "other"
	second, err := service.Encrypt(context.Background(), id, changed, plain)
	if err != nil {
		t.Fatal(err)
	}
	if slices.Equal(enc.AD, second.AD) {
		t.Fatal("associated data did not bind descriptor")
	}
}
