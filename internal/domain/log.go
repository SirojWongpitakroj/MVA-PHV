package domain

import (
	"time"
	"uuid"
)

type Log struct {
	LogID uuid.UUID

	RegionID string
	SiteID   string
	DevID    string
	Type     string
	TS       time.Time

	Ciphertext []byte
	Tag        []byte
	Nonce      []byte
	Digest     [32]byte
	AD         []byte
}
