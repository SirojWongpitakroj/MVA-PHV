package cassandra

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"time"
	"uuid"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
)

// PageChild stores the address and authenticated hash of an internal child.
// The MVA page hash commits to Hash, while PageID is needed to fetch the child.
type PageChild struct {
	PageID int64
	Hash   [32]byte
}

// PagePayload is the versioned encoding of mva.Page's ordered contents.
// Keys are LocatorKey.Serialize bytes and Values are LocatorValue.Serialize
// bytes; their concrete Go key types remain owned by the mva package.
type PagePayload struct {
	IsLeaf   bool
	Keys     [][]byte
	Values   [][]byte
	Children []PageChild
}

const pagePayloadVersion byte = 1

func (p PagePayload) validate() error {
	if len(p.Keys) > math.MaxUint32 || len(p.Values) > math.MaxUint32 || len(p.Children) > math.MaxUint32 {
		return fmt.Errorf("cassandra: MVA page has too many entries")
	}
	if p.IsLeaf {
		if len(p.Keys) != len(p.Values) || len(p.Children) != 0 {
			return fmt.Errorf("cassandra: invalid leaf page contents")
		}
	} else if len(p.Values) != 0 || len(p.Children) != len(p.Keys)+1 {
		return fmt.Errorf("cassandra: invalid internal page contents")
	}
	for _, child := range p.Children {
		if child.PageID < 0 {
			return fmt.Errorf("cassandra: negative child page ID")
		}
	}
	return nil
}

// EncodePagePayload gives page_data a deterministic, driver-independent format.
// Format: version byte, leaf byte, then three BE32-counted sequences of keys,
// values, and children. Each key/value is BE32-length-prefixed; each child is
// BE64 PageID followed by its 32-byte hash.
func EncodePagePayload(p PagePayload) ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	buf.WriteByte(pagePayloadVersion)
	if p.IsLeaf {
		buf.WriteByte(1)
	} else {
		buf.WriteByte(0)
	}
	for _, sequence := range [][][]byte{p.Keys, p.Values} {
		if err := binary.Write(&buf, binary.BigEndian, uint32(len(sequence))); err != nil {
			return nil, err
		}
		for _, item := range sequence {
			if len(item) > math.MaxUint32 {
				return nil, fmt.Errorf("cassandra: MVA page item too large")
			}
			if err := binary.Write(&buf, binary.BigEndian, uint32(len(item))); err != nil {
				return nil, err
			}
			buf.Write(item)
		}
	}
	if err := binary.Write(&buf, binary.BigEndian, uint32(len(p.Children))); err != nil {
		return nil, err
	}
	for _, child := range p.Children {
		if err := binary.Write(&buf, binary.BigEndian, child.PageID); err != nil {
			return nil, err
		}
		buf.Write(child.Hash[:])
	}
	return buf.Bytes(), nil
}

func DecodePagePayload(data []byte) (p PagePayload, err error) {
	reader := bytes.NewReader(data)
	version, err := reader.ReadByte()
	if err != nil || version != pagePayloadVersion {
		return p, fmt.Errorf("cassandra: invalid MVA page data version")
	}
	leaf, err := reader.ReadByte()
	if err != nil || leaf > 1 {
		return p, fmt.Errorf("cassandra: invalid MVA page kind")
	}
	p.IsLeaf = leaf == 1
	readSequence := func() ([][]byte, error) {
		var count uint32
		if err := binary.Read(reader, binary.BigEndian, &count); err != nil {
			return nil, err
		}
		if uint64(count) > uint64(reader.Len()/4) {
			return nil, fmt.Errorf("cassandra: truncated MVA page entries")
		}
		items := make([][]byte, int(count))
		for i := range items {
			var length uint32
			if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
				return nil, err
			}
			if uint64(length) > uint64(reader.Len()) {
				return nil, fmt.Errorf("cassandra: truncated MVA page item")
			}
			items[i] = make([]byte, int(length))
			if _, err := io.ReadFull(reader, items[i]); err != nil {
				return nil, err
			}
		}
		return items, nil
	}
	if p.Keys, err = readSequence(); err != nil {
		return p, err
	}
	if p.Values, err = readSequence(); err != nil {
		return p, err
	}
	var childCount uint32
	if err := binary.Read(reader, binary.BigEndian, &childCount); err != nil {
		return p, err
	}
	if uint64(childCount) > uint64(reader.Len()/40) {
		return p, fmt.Errorf("cassandra: truncated MVA page children")
	}
	p.Children = make([]PageChild, int(childCount))
	for i := range p.Children {
		if err := binary.Read(reader, binary.BigEndian, &p.Children[i].PageID); err != nil {
			return p, err
		}
		if _, err := io.ReadFull(reader, p.Children[i].Hash[:]); err != nil {
			return p, err
		}
	}
	if reader.Len() != 0 {
		return p, fmt.Errorf("cassandra: trailing MVA page data")
	}
	return p, p.validate()
}

// Hash reproduces the current MVALEAF/MVAINT page hash from encoded entries.
// The page ID and RID are included exactly as in mva.Page serialization.
func (p PagePayload) Hash(rid string, pageID int64) ([32]byte, error) {
	if err := p.validate(); err != nil {
		return [32]byte{}, err
	}
	if pageID < 0 {
		return [32]byte{}, fmt.Errorf("cassandra: negative MVA page ID")
	}
	encodedRID, err := domain.Serialize(rid)
	if err != nil {
		return [32]byte{}, err
	}
	var buf bytes.Buffer
	if p.IsLeaf {
		buf.WriteString("MVALEAF")
	} else {
		buf.WriteString("MVAINT")
	}
	buf.Write(encodedRID)
	if err := binary.Write(&buf, binary.BigEndian, pageID); err != nil {
		return [32]byte{}, err
	}
	if p.IsLeaf {
		for _, value := range p.Values {
			buf.Write(value)
		}
	} else {
		for i, key := range p.Keys {
			buf.Write(p.Children[i].Hash[:])
			buf.Write(key)
		}
		buf.Write(p.Children[len(p.Children)-1].Hash[:])
	}
	return sha256.Sum256(buf.Bytes()), nil
}

func validateLocatorKey(view string, key []byte) error {
	switch view {
	case "id":
		var id uuid.UUID
		return domain.Deserialize(key, &id)
	case "attribute":
		var site, device, typ string
		var ts time.Time
		var id uuid.UUID
		return domain.Deserialize(key, &site, &device, &typ, &ts, &id)
	default:
		return fmt.Errorf("cassandra: invalid MVA view %q", view)
	}
}

// DecodePageData rejects a malformed payload or a hash that does not match the
// page key and serialized contents. It does not authenticate the page's place
// in a historical root; the caller must verify the Merkle path separately.
func (r PageVersion) DecodePageData() (PagePayload, error) {
	if err := validView(r.View); err != nil {
		return PagePayload{}, err
	}
	p, err := DecodePagePayload(r.Data)
	if err != nil {
		return p, err
	}
	if p.IsLeaf != r.IsLeaf {
		return p, fmt.Errorf("cassandra: MVA page kind does not match row")
	}
	for i, key := range p.Keys {
		if err := validateLocatorKey(r.View, key); err != nil {
			return p, fmt.Errorf("cassandra: invalid MVA key %d: %w", i, err)
		}
	}
	if p.IsLeaf {
		for i, key := range p.Keys {
			value := p.Values[i]
			if !bytes.HasPrefix(value, key) {
				return p, fmt.Errorf("cassandra: MVA leaf key %d does not match its value", i)
			}
			var region, shard, segment, leaf string
			var commitment []byte
			if err := domain.Deserialize(value[len(key):], &region, &shard, &segment, &leaf, &commitment); err != nil {
				return p, fmt.Errorf("cassandra: invalid MVA leaf value %d: %w", i, err)
			}
			if region != r.RegionID || len(commitment) != 32 {
				return p, fmt.Errorf("cassandra: invalid MVA leaf value %d address or commitment", i)
			}
		}
	}
	hash, err := p.Hash(r.RegionID, r.PageID)
	if err != nil {
		return p, err
	}
	if hash != r.Hash {
		return p, fmt.Errorf("cassandra: MVA page content hash mismatch")
	}
	return p, nil
}
