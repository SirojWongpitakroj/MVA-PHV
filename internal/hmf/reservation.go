package hmf

import (
	"fmt"
	"time"

	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

// Address is the physical position committed by one HMF leaf.
type Address struct {
	RegionID  string
	ShardID   int64
	SegmentID int64
	LeafID    int64
}

// Reservation has one terminal action: CommitReservation or AbortReservation.
// Its fields are private so callers cannot change the reserved position.
type Reservation struct {
	h        *HMF
	id       uint64
	address  Address
	openedAt time.Time
}

func (r *Reservation) Address() Address {
	if r == nil {
		return Address{}
	}
	return r.address
}
func (r *Reservation) OpenedAt() time.Time {
	if r == nil {
		return time.Time{}
	}
	return r.openedAt
}

// ReserveAddress chooses a configured Shard, seals an expired active Segment,
// and holds the next position exclusively until commit or abort. Other Shards
// can still ingest while this reservation is open.
func (h *HMF) ReserveAddress(rid, siteID, devID string, now time.Time) (*Reservation, error) {
	if h == nil {
		return nil, fmt.Errorf("reserve HMF address: HMF is nil")
	}
	if now.IsZero() {
		return nil, fmt.Errorf("reserve HMF address: timestamp is zero")
	}
	sid, err := h.SelectShard(rid, siteID, devID)
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	key := shardTreeID(rid, sid)
	if h.reservations[key] != nil {
		return nil, fmt.Errorf("reserve HMF address: Shard %q/%d is busy", rid, sid)
	}
	region := h.Working.Regions[rid]
	if region == nil || region.Shards[sid] == nil {
		return nil, fmt.Errorf("reserve HMF address: unknown Shard %q/%d", rid, sid)
	}
	shard := region.Shards[sid]
	if shard.Active != nil && now.Sub(shard.OpenedAt) >= h.SealInterval {
		if _, err := h.sealSegment(rid, sid, shard.Active.TreeID.SegmentID, now); err != nil {
			return nil, err
		}
	}
	if shard.Active == nil {
		segment := NewSegmentTree(rid, sid, shard.nextSegID, h.MaxSegmentSize)
		segment.OpenedAt = now
		shard.nextSegID++
		shard.Active = segment
		shard.OpenedAt = now
		h.activeShards[key] = struct{}{}
	}
	if shard.Active.LeafCount >= int64(h.MaxSegmentSize) {
		return nil, fmt.Errorf("reserve HMF address: active Segment is full")
	}
	h.nextReservation++
	r := &Reservation{h: h, id: h.nextReservation,
		address:  Address{RegionID: rid, ShardID: sid, SegmentID: shard.Active.TreeID.SegmentID, LeafID: shard.Active.LeafCount},
		openedAt: shard.OpenedAt}
	h.reservations[key] = r
	return r, nil
}

func (h *HMF) reservationShard(r *Reservation) (*HMFWorkingShard, merkle.TreeID, error) {
	if h == nil || r == nil || r.h != h {
		return nil, merkle.TreeID{}, fmt.Errorf("HMF reservation: wrong owner")
	}
	a := r.address
	key := shardTreeID(a.RegionID, a.ShardID)
	if h.reservations[key] != r {
		return nil, key, fmt.Errorf("HMF reservation: already completed or replaced")
	}
	region := h.Working.Regions[a.RegionID]
	if region == nil || region.Shards[a.ShardID] == nil {
		return nil, key, fmt.Errorf("HMF reservation: Shard no longer exists")
	}
	shard := region.Shards[a.ShardID]
	if shard.Active == nil || shard.Active.TreeID.SegmentID != a.SegmentID || shard.Active.LeafCount != a.LeafID {
		return nil, key, fmt.Errorf("HMF reservation: physical position changed")
	}
	return shard, key, nil
}

// CommitReservation appends d_i at precisely the reserved leaf. Once it
// returns successfully the reservation cannot be reused.
func (h *HMF) CommitReservation(r *Reservation, leaf [32]byte, now time.Time) error {
	if h == nil {
		return fmt.Errorf("commit HMF reservation: HMF is nil")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	shard, key, err := h.reservationShard(r)
	if err != nil {
		return err
	}
	if err := shard.Active.AppendCommitment(leaf); err != nil {
		return err
	}
	delete(h.reservations, key)
	if shard.Active.LeafCount >= int64(h.MaxSegmentSize) || now.Sub(shard.OpenedAt) >= h.SealInterval {
		if _, err := h.sealSegment(r.address.RegionID, r.address.ShardID, r.address.SegmentID, now); err != nil {
			return err
		}
	}
	return nil
}

// AbortReservation releases an unused position. A just-created empty Segment
// is removed so its ID and LeafID can be reused without leaving a gap.
func (h *HMF) AbortReservation(r *Reservation) error {
	if h == nil {
		return fmt.Errorf("abort HMF reservation: HMF is nil")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	shard, key, err := h.reservationShard(r)
	if err != nil {
		return err
	}
	delete(h.reservations, key)
	if shard.Active.LeafCount == 0 {
		shard.Active = nil
		shard.OpenedAt = time.Time{}
		shard.nextSegID--
		delete(h.activeShards, key)
	}
	return nil
}
