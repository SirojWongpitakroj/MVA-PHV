package merkleBP

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
)

//TODO

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
	Values []LocatorValue
	Next   *Page

	//used by internal pages
	Children []*Page
}

// Boolean Search
func (page *Page) findKeyIdx(currKey LocatorKey) int {
	return sort.Search(len(page.Keys), func(i int) bool {
		return currKey.Compare(page.Keys[i]) < 0
	})
}

func (page *Page) serializeLeaf() ([]byte, error) {
	var buf bytes.Buffer

	buf.WriteString("MVALEAF")

	// RID
	encodedRID, err := domain.Serialize(page.RegionID)
	if err != nil {
		return nil, err
	}
	buf.Write(encodedRID)

	// v
	if err := binary.Write(
		&buf,
		binary.BigEndian,
		page.PageID,
	); err != nil {
		return nil, err
	}

	// enc(E1, ..., Em)
	for _, entry := range page.Values {
		encodedEntry, err := entry.Serialize()
		if err != nil {
			return nil, err
		}
		buf.Write(encodedEntry)
	}

	return buf.Bytes(), nil
}

func (page *Page) leafHash() ([32]byte, error) {
	encoded, err := page.serializeLeaf()
	if err != nil {
		return [32]byte{}, err
	}

	return sha256.Sum256(encoded), nil
}

func (page *Page) serializeInternal() ([]byte, error) {
	var buf bytes.Buffer

	// Domain separator
	buf.WriteString("MVAINT")

	// RID
	encodedRID, err := domain.Serialize(page.RegionID)
	if err != nil {
		return nil, err
	}
	buf.Write(encodedRID)

	// v
	if err := binary.Write(
		&buf,
		binary.BigEndian,
		page.PageID,
	); err != nil {
		return nil, err
	}

	// Internal page with m separator keys must have m+1 children
	if len(page.Children) != len(page.Keys)+1 {
		return nil, fmt.Errorf(
			"invalid internal page: %d keys but %d children",
			len(page.Keys),
			len(page.Children),
		)
	}

	// enc(h0, K1, h1, K2, ..., Km, hm)
	for i, key := range page.Keys {
		childHash := page.Children[i].Hash
		buf.Write(childHash[:])

		encodedKey, err := key.Serialize()
		if err != nil {
			return nil, err
		}
		buf.Write(encodedKey)
	}

	// Final child hm
	lastHash := page.Children[len(page.Children)-1].Hash
	buf.Write(lastHash[:])

	return buf.Bytes(), nil
}

func (page *Page) internalHash() ([32]byte, error) {
	encoded, err := page.serializeInternal()
	if err != nil {
		return [32]byte{}, err
	}

	return sha256.Sum256(encoded), nil
}
