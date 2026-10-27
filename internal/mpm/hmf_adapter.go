package mpm

import (
	"fmt"
	"time"

	"github.com/SirojWongpitakroj/mva-phv/internal/hmf"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

// HMFAdapter connects MPM's two-stage physical address protocol to HMF.
type HMFAdapter struct{ Tree *hmf.HMF }

var _ HMF = (*HMFAdapter)(nil)

type hmfReservation struct {
	tree        *hmf.HMF
	reservation *hmf.Reservation
}

func (r *hmfReservation) Address() Address {
	a := r.reservation.Address()
	return Address{RegionID: a.RegionID, ShardID: a.ShardID, SegmentID: a.SegmentID, LeafID: a.LeafID}
}
func (r *hmfReservation) Commit(leaf [32]byte, now time.Time) error {
	return r.tree.CommitReservation(r.reservation, leaf, now)
}
func (r *hmfReservation) Abort() error { return r.tree.AbortReservation(r.reservation) }

func (a *HMFAdapter) SelectShard(rid, site, device string) (int64, error) {
	if a == nil || a.Tree == nil {
		return 0, fmt.Errorf("MPM HMF adapter: nil tree")
	}
	return a.Tree.SelectShard(rid, site, device)
}
func (a *HMFAdapter) Reserve(rid, site, device string, now time.Time) (Reservation, error) {
	if a == nil || a.Tree == nil {
		return nil, fmt.Errorf("MPM HMF adapter: nil tree")
	}
	r, err := a.Tree.ReserveAddress(rid, site, device, now)
	if err != nil {
		return nil, err
	}
	return &hmfReservation{tree: a.Tree, reservation: r}, nil
}
func (a *HMFAdapter) SealExpired(now time.Time) error {
	if a == nil || a.Tree == nil {
		return fmt.Errorf("MPM HMF adapter: nil tree")
	}
	_, err := a.Tree.SealExpired(now)
	return err
}
func (a *HMFAdapter) PendingSegments() []Segment {
	if a == nil || a.Tree == nil {
		return nil
	}
	trees := a.Tree.PendingSegments()
	segments := make([]Segment, 0, len(trees))
	for _, tree := range trees {
		if tree == nil || tree.MerkleTree == nil {
			continue
		}
		segments = append(segments, Segment{ID: tree.TreeID, Root: tree.Root, LeafCount: tree.LeafCount,
			Height: tree.Height, MaxLeaves: tree.MaxLeaves, OpenedAt: tree.OpenedAt, SealedAt: tree.SealedAt})
	}
	return segments
}
func (a *HMFAdapter) PendingSegmentNodes(id merkle.TreeID) ([]merkle.MerkleNode, error) {
	return a.Tree.PendingSegmentNodes(id)
}
func (a *HMFAdapter) AcknowledgeSegmentPersisted(id merkle.TreeID) error {
	return a.Tree.AcknowledgeSegmentPersisted(id)
}
func (a *HMFAdapter) PrepareFinalization(epoch uint64) error {
	return a.Tree.PrepareFinalization(epoch)
}
func (a *HMFAdapter) Commitment() ([32]byte, error) { return a.Tree.Commitment() }
func (a *HMFAdapter) ValidateFinalization(epoch uint64) error {
	return a.Tree.ValidateFinalization(epoch)
}
func (a *HMFAdapter) CommitFinalization(epoch uint64) error { return a.Tree.CommitFinalization(epoch) }
