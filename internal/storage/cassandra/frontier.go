package cassandra

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

// FrontierData format: version byte 1, BE32 node count, then ordered records
// of BE32 level, BE64 index, and 32 hash bytes. An empty frontier is valid.
const frontierVersion byte = 1
const frontierNodeBytes = 4 + 8 + 32

func EncodeFrontier(nodes []merkle.MerkleNode) ([]byte, error) {
	if uint64(len(nodes)) > math.MaxUint32 {
		return nil, fmt.Errorf("cassandra: too many frontier nodes")
	}
	data := make([]byte, 5+len(nodes)*frontierNodeBytes)
	data[0] = frontierVersion
	binary.BigEndian.PutUint32(data[1:5], uint32(len(nodes)))
	for i, node := range nodes {
		if node.Level < 0 || node.Level > math.MaxInt32 || node.Index < 0 {
			return nil, fmt.Errorf("cassandra: invalid frontier node %d", i)
		}
		offset := 5 + i*frontierNodeBytes
		binary.BigEndian.PutUint32(data[offset:], uint32(node.Level))
		binary.BigEndian.PutUint64(data[offset+4:], uint64(node.Index))
		copy(data[offset+12:offset+frontierNodeBytes], node.Hash[:])
	}
	return data, nil
}

func DecodeFrontier(data []byte) ([]merkle.MerkleNode, error) {
	if len(data) < 5 || data[0] != frontierVersion {
		return nil, fmt.Errorf("cassandra: invalid frontier encoding version")
	}
	count := uint64(binary.BigEndian.Uint32(data[1:5]))
	if count != uint64(len(data)-5)/frontierNodeBytes || (len(data)-5)%frontierNodeBytes != 0 {
		return nil, fmt.Errorf("cassandra: frontier length does not match node count")
	}
	nodes := make([]merkle.MerkleNode, int(count))
	for i := range nodes {
		offset := 5 + i*frontierNodeBytes
		level := binary.BigEndian.Uint32(data[offset:])
		index := binary.BigEndian.Uint64(data[offset+4:])
		if level > math.MaxInt32 || index > math.MaxInt64 {
			return nil, fmt.Errorf("cassandra: frontier node %d exceeds Go bounds", i)
		}
		nodes[i].Level = int(level)
		nodes[i].Index = int64(index)
		copy(nodes[i].Hash[:], data[offset+12:offset+frontierNodeBytes])
	}
	return nodes, nil
}
