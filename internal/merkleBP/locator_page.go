package merkleBP

import "sort"

//TODO

// Page struct
type Page struct {
	PageID int64
	Hash   [32]byte

	IsLeaf bool
	Keys   []LocatorKey

	Parent       *Page
	ParentPageID *int64

	//used by leaf pages
	Values []*LocatorValue
	Next   *Page

	//used by internal pages
	Children []*Page
}

// func (page *Page) concatEncKeys(prefix []byte) []byte {
// 	for _, key := range page.Keys {
// 		prefix = append(prefix, encodeKey(key)...)
// 	}
// 	return prefix
// }

// func (page *Page) concatEncChild(prefix []byte) []byte {
// 	for _, child := range page.Children {
// 		prefix = append(prefix, child.Hash[:]...)
// 	}
// 	return prefix
// }

func (page *Page) findKeyIdx(currKey LocatorKey) int {
	return sort.Search(len(page.Keys), func(i int) bool {
		return currKey.Compare(page.Keys[i]) < 0
	})
}

// func (page *Page) leafHash() [32]byte {
// 	var encoded bytes.Buffer
// 	encoded.WriteString("LEAF")
// 	binary.Write(&encoded, binary.BigEndian, page.PageID)
// 	if page.Next == nil {
// 		encoded.WriteByte(0)
// 	} else {
// 		encoded.WriteByte(1)
// 		binary.Write(&encoded, binary.BigEndian, page.Next.PageID)
// 	}
// 	for index, key := range page.Keys {
// 		encoded.Write(encodeKey(key))
// 		encoded.Write(encodeValue(page.Values[index]))
// 	}
// 	return sha256.Sum256(encoded.Bytes())
// }

// func (page *Page) internalHash() [32]byte {
// 	concatInternal := []byte("INTERNAL")
// 	concatInternal = page.concatEncKeys(concatInternal)
// 	concatInternal = page.concatEncChild(concatInternal)
// 	return sha256.Sum256(concatInternal)
// }
