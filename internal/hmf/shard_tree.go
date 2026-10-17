// Package hmf implements hierarchical Merkle trees.
package hmf

import (
	"crypto/sha256"
	"fmt"

	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

type ShardTree struct {
	*merkle.MerkleTree
	frontiers []merkle.MerkleNode
}

func (tree *ShardTree) popFrontier() (merkle.MerkleNode, error) {
	frontierLen := len(tree.frontiers)
	if frontierLen == 0 {
		return merkle.MerkleNode{},
			fmt.Errorf("pop frontier node: do not have MerkleNode to pop")
	}

	poppedNode := tree.frontiers[frontierLen-1]
	tree.frontiers = tree.frontiers[:frontierLen-1]
	return poppedNode, nil
}

// Main function

func NewShardTree(regionID string, shardID int64) *ShardTree {
	tree := ShardTree{
		MerkleTree: &merkle.MerkleTree{
			TreeID: merkle.TreeID{
				Type:     merkle.TreeShard,
				RegionID: regionID,
				ShardID:  shardID,
			},
		},
		frontiers: make([]merkle.MerkleNode, 0),
	}
	return &tree
}

// Frontiers returns a copy of the current append frontier for persistence.
func (tree *ShardTree) Frontiers() []merkle.MerkleNode {
	return append([]merkle.MerkleNode(nil), tree.frontiers...)
}

// get node to update and get new frontierNode
func (tree *ShardTree) mergeFrontier(segmentHash [32]byte) ([]merkle.MerkleNode, error) {
	currNode := merkle.MerkleNode{
		Level: 0,
		Index: tree.LeafCount,
		Hash:  segmentHash,
	}

	updates := []merkle.MerkleNode{currNode}

	for len(tree.frontiers) > 0 &&
		tree.frontiers[len(tree.frontiers)-1].Level == currNode.Level {

		left, err := tree.popFrontier()
		if err != nil {
			return nil, err
		}

		rightHash := currNode.Hash
		currNode = merkle.MerkleNode{
			Level: currNode.Level + 1,
			Index: currNode.Index / 2,
		}
		if err := currNode.ComputeInternalHash("SHARDINT", left.Hash, rightHash); err != nil {
			return nil, err
		}
		updates = append(updates, currNode)
	}
	tree.frontiers = append(tree.frontiers, currNode)

	return updates, nil
}

func (tree *ShardTree) materializeRootPath(updates []merkle.MerkleNode) ([]merkle.MerkleNode, merkle.MerkleNode, error) {
	if len(tree.frontiers) <= 0 {
		return updates, merkle.MerkleNode{}, fmt.Errorf("update shard root path error: no node in frontier")
	}
	if len(tree.frontiers) <= 1 {
		return updates, tree.frontiers[0], nil
	}

	right := tree.frontiers[len(tree.frontiers)-1]
	for i := len(tree.frontiers) - 2; i >= 0; i-- {
		left := tree.frontiers[i]
		//recusively promote
		for right.Level < left.Level {
			right = merkle.MerkleNode{
				Level: right.Level + 1,
				Index: right.Index / 2,
				Hash:  right.Hash, // promotion: unchanged
			}
			updates = append(updates, right)
		}

		//append HashPair of Peak
		rightHash := right.Hash
		right = merkle.MerkleNode{
			Level: left.Level + 1,
			Index: left.Index / 2,
		}
		if err := right.ComputeInternalHash("SHARDINT", left.Hash, rightHash); err != nil {
			return updates, merkle.MerkleNode{}, err
		}
		updates = append(updates, right)
	}

	return updates, right, nil
}

func (tree *ShardTree) Append(segmentHash [32]byte) ([]merkle.MerkleNode, error) {
	updates, err := tree.mergeFrontier(segmentHash)
	if err != nil {
		return updates, err
	}

	updates, shardRoot, err := tree.materializeRootPath(updates)
	if err != nil {
		return updates, err
	}

	encodedID, err := domain.Serialize(
		string(tree.TreeID.Type), tree.TreeID.RegionID, uint64(tree.TreeID.ShardID),
	)
	if err != nil {
		return updates, err
	}
	encodedRoot, err := domain.Serialize(
		[]byte("TREE"), encodedID, uint64(tree.LeafCount+1), shardRoot.Hash[:],
	)
	if err != nil {
		return updates, err
	}
	tree.Root = sha256.Sum256(encodedRoot)
	tree.LeafCount++
	tree.Height = shardRoot.Level
	return updates, nil
}
