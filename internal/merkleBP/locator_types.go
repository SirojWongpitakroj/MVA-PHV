package merkleBP

import (
	"bytes"
	"fmt"
	"time"
	"uuid"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
)

// tree struct

// Key
type idKey struct {
	ID uuid.UUID //LogID
}

func (idKey) isLogViewKey() bool { return true }

func (k idKey) LogID() uuid.UUID {
	return k.ID
}

func (k idKey) Compare(other LocatorKey) int {
	return k.ID.Compare(other.LogID())
}

// Less reports whether key sorts before other.
func (key idKey) Less(other LocatorKey) bool {
	return key.Compare(other) < 0
}

func (k idKey) Serialize() ([]byte, error) {
	return domain.Serialize(
		k.ID,
	)
}

type attrKey struct {
	SiteID string
	DevID  string
	Type   string
	TS     time.Time
	ID     uuid.UUID
}

func (attrKey) isLogViewKey() bool { return false }

func (k attrKey) LogID() uuid.UUID {
	return k.ID
}

func (k attrKey) Compare(other LocatorKey) int {
	o, ok := other.(attrKey)
	if !ok {
		// Different key types should normally never be compared.
		// Handle according to your design.
		return 1
	}

	if k.SiteID != o.SiteID {
		if k.SiteID < o.SiteID {
			return -1
		}
		return 1
	}

	if k.DevID != o.DevID {
		if k.DevID < o.DevID {
			return -1
		}
		return 1
	}

	if k.Type != o.Type {
		if k.Type < o.Type {
			return -1
		}
		return 1
	}

	if !k.TS.Equal(o.TS) {
		if k.TS.Before(o.TS) {
			return -1
		}
		return 1
	}

	return k.ID.Compare(o.ID)
}

// Less reports whether key sorts before other.
func (key attrKey) Less(other LocatorKey) bool {
	return key.Compare(other) < 0
}

func (k attrKey) Serialize() ([]byte, error) {
	return domain.Serialize(
		k.SiteID,
		k.DevID,
		k.Type,
		k.TS,
		k.ID,
	)
}

type LocatorKey interface {
	LogID() uuid.UUID
	isLogViewKey() bool
	Compare(other LocatorKey) int
	Serialize() ([]byte, error)
}

// A_i
type PhysicalAddress struct {
	RegionID  string
	ShardID   string
	SegmentID string
	LeafID    string
}

// Value
type LocatorValue struct {
	LocatorKey
	PhysicalAddress
	LeafHash [32]byte
}

func (v LocatorValue) Serialize() ([]byte, error) {
	var buf bytes.Buffer

	switch k := v.LocatorKey.(type) {
	case idKey:
		encoded, err := domain.Serialize(k.ID)
		if err != nil {
			return nil, err
		}
		buf.Write(encoded)

	case attrKey:
		encoded, err := domain.Serialize(
			k.SiteID,
			k.DevID,
			k.Type,
			k.TS,
			k.ID,
		)
		if err != nil {
			return nil, err
		}
		buf.Write(encoded)

	default:
		return nil, fmt.Errorf(
			"unsupported LocatorKey type: %T",
			v.LocatorKey,
		)
	}

	encodedPhyAddr, err := domain.Serialize(
		v.RegionID,
		v.ShardID,
		v.SegmentID,
		v.LeafID,
	)
	if err != nil {
		return nil, err
	}
	buf.Write(encodedPhyAddr)

	buf.Write(v.LeafHash[:])

	return buf.Bytes(), nil
}

// LocatorQuery describes one continuous range in the ALL key order. The
// first four fields are exact matches and the time interval is half-open.
type LocatorQuery struct {
	TenantID  string
	ServiceID string
	LogType   string
	RegionID  string
	StartTime time.Time
	EndTime   time.Time
}

// LocatorEntry an object sent by the auditor
type LocatorEntry struct {
	PageID int64
	Key    LocatorKey
	Value  LocatorValue
}

type LocatorTree struct {
	RootPageID int64
	NextPageID int64
	RootHash   [32]byte
	RootPage   *Page

	Height    int
	LeafCount int64

	Order int //m: max children per internal page
}

// LocatorUpdate contains the final ALL state changed by one insertion.
type LocatorUpdate struct {
	Pages []Page

	RootPageID  int64
	RootHash    [32]byte
	NextPageID  int64
	Height      int
	RecordCount int64
}
