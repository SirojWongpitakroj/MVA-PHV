package mva

import (
	"bytes"
	"fmt"
	"strings"
	"time"
	"uuid"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
)

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

// LocatorQuery compares a search request with stored locator keys. Stored
// keys also satisfy this interface, allowing exact ID and attribute lookups.
type LocatorQuery interface {
	isLogViewKey() bool
	Compare(LocatorKey) int
}

// LogIDQuery selects one record through the finalized Log-ID view.
type LogIDQuery struct{ ID uuid.UUID }

func (LogIDQuery) isLogViewKey() bool             { return true }
func (q LogIDQuery) Compare(other LocatorKey) int { return q.ID.Compare(other.LogID()) }

// SiteQuery and SiteDeviceQuery select the complete authenticated attribute
// prefix. Time-limited queries require AttrRangeQuery's full attribute key.
type SiteQuery struct{ SiteID string }

func (SiteQuery) isLogViewKey() bool { return false }
func (q SiteQuery) Compare(other LocatorKey) int {
	k, ok := other.(attrKey)
	if !ok {
		return 1
	}
	return strings.Compare(q.SiteID, k.SiteID)
}

type SiteDeviceQuery struct{ SiteID, DevID string }

func (SiteDeviceQuery) isLogViewKey() bool { return false }
func (q SiteDeviceQuery) Compare(other LocatorKey) int {
	k, ok := other.(attrKey)
	if !ok {
		return 1
	}
	if order := strings.Compare(q.SiteID, k.SiteID); order != 0 {
		return order
	}
	return strings.Compare(q.DevID, k.DevID)
}

// TimeRangeQuery is a correctness path when no attribute prefix is supplied.
// The existing attribute tree is not time-ordered globally, so MVA must scan
// every authenticated attribute leaf for this query.
type TimeRangeQuery struct{ StartTS, EndTS time.Time }

func (TimeRangeQuery) isLogViewKey() bool { return false }
func (TimeRangeQuery) Compare(other LocatorKey) int {
	if _, ok := other.(attrKey); ok {
		return 0
	}
	return 1
}

func Matches(query LocatorQuery, key LocatorKey) bool {
	if q, ok := query.(TimeRangeQuery); ok {
		stored, ok := key.(attrKey)
		return ok && !stored.TS.Before(q.StartTS) && !stored.TS.After(q.EndTS)
	}
	return query != nil && query.Compare(key) == 0
}

func isTimeOnly(query LocatorQuery) bool { _, ok := query.(TimeRangeQuery); return ok }

// AttrRangeQuery selects one attribute prefix within an inclusive time range.
type AttrRangeQuery struct {
	SiteID  string
	DevID   string
	Type    string
	StartTS time.Time
	EndTS   time.Time
}

func (AttrRangeQuery) isLogViewKey() bool { return false }

// Compare returns zero for every stored key in the requested range.
func (q AttrRangeQuery) Compare(other LocatorKey) int {
	key, ok := other.(attrKey)
	if !ok {
		return 1
	}
	if order := strings.Compare(q.SiteID, key.SiteID); order != 0 {
		return order
	}
	if order := strings.Compare(q.DevID, key.DevID); order != 0 {
		return order
	}
	if order := strings.Compare(q.Type, key.Type); order != 0 {
		return order
	}
	if q.StartTS.After(key.TS) {
		return 1
	}
	if q.EndTS.Before(key.TS) {
		return -1
	}
	return 0
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
	LeafHash [32]byte //c_i; MPM will have to pass in this
}

// DecodeStoredKey and DecodeStoredValue reconstruct the existing canonical
// page encoding used by historical evidence repositories.
func DecodeStoredKey(view ViewType, data []byte) (LocatorKey, error) {
	switch view {
	case ViewID:
		var id uuid.UUID
		if err := domain.Deserialize(data, &id); err != nil {
			return nil, err
		}
		return idKey{ID: id}, nil
	case ViewAttribute:
		var key attrKey
		if err := domain.Deserialize(data, &key.SiteID, &key.DevID, &key.Type, &key.TS, &key.ID); err != nil {
			return nil, err
		}
		return key, nil
	default:
		return nil, fmt.Errorf("decode MVA key: invalid view %q", view)
	}
}

func DecodeStoredValue(view ViewType, keyBytes, valueBytes []byte) (*LocatorValue, error) {
	key, err := DecodeStoredKey(view, keyBytes)
	if err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(valueBytes, keyBytes) {
		return nil, fmt.Errorf("decode MVA value: key mismatch")
	}
	value := &LocatorValue{LocatorKey: key}
	var commitment []byte
	if err := domain.Deserialize(valueBytes[len(keyBytes):], &value.RegionID, &value.ShardID, &value.SegmentID, &value.LeafID, &commitment); err != nil {
		return nil, err
	}
	if len(commitment) != 32 {
		return nil, fmt.Errorf("decode MVA value: invalid locator commitment length")
	}
	copy(value.LeafHash[:], commitment)
	return value, nil
}

func (v LocatorValue) Serialize() ([]byte, error) {
	var buf bytes.Buffer

	//Key
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

	//A_i
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

	//c_i
	buf.Write(v.LeafHash[:])

	return buf.Bytes(), nil
}

// LocatorEntry an object sent by the auditor
type LocatorEntry struct {
	LocatorKey
}

type LocatorTree struct {
	RootPageID int64
	NextPageID int64
	RootHash   [32]byte
	RootPage   *Page
	ViewType   string

	Height    int
	LeafCount int64

	Order int //m: max children per internal page
}

// LocatorUpdate contains the final merkleB+ state changed by one insertion.
type LocatorUpdate struct {
	Pages []Page

	RootPageID  int64
	RootHash    [32]byte
	NextPageID  int64
	Height      int
	RecordCount int64
}

// Page struct
type Page struct {
	PageID   int64
	Hash     [32]byte
	RegionID string

	IsLeaf bool
	Keys   []LocatorKey

	Parent       *Page
	ParentPageID *int64

	//used by leaf pages
	Values []*LocatorValue
	Prev   *Page
	Next   *Page

	//used by internal pages
	Children []*Page
}

type PageProof struct {
	PageID int64
	IsLeaf bool

	Keys []LocatorKey

	// leaf only
	Values []*LocatorValue

	// internal only
	ChildHashes [][32]byte

	// child that auditor should replace with
	// the hash reconstructed from lower level
	PathChildIndicdex []int
}
