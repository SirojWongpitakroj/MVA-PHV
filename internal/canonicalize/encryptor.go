// Package canonicalize provides canonicalization and encryption for audit logs.
package canonicalize

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
)

func (r *DatasetReader) encrypt(logBytes []byte) error {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, aesGCM.NonceSize())

	//generate nonce
	_, err = rand.Read(nonce)
	if err != nil {
		return err
	}

	//construct AD
	ad, err := domain.Serialize(
		"MVA-PHV:LOG:V1",
		r.CurrLog.LogID,
		r.CurrLog.RegionID,
		r.CurrLog.SiteID,
		r.CurrLog.DevID,
		r.CurrLog.Type,
		r.CurrLog.TS.UTC(),
	)
	if err != nil {
		return err
	}

	encrypted := aesGCM.Seal(nil, nonce, logBytes, []byte(ad))

	tagSize := aesGCM.Overhead()

	r.CurrLog.Ciphertext = encrypted[:len(encrypted)-tagSize]
	r.CurrLog.Tag = encrypted[len(encrypted)-tagSize:]

	return nil
}
