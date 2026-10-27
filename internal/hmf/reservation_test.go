package hmf

import (
	"testing"
	"time"
)

func TestReservationAddressBeforeCommitAndAbort(t *testing.T) {
	h, err := NewHMF(1, 1, 2, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100, 0)
	r, err := h.ReserveAddress("0", "site", "dev", now)
	if err != nil {
		t.Fatal(err)
	}
	a := r.Address()
	if a.RegionID != "0" || a.ShardID != 0 || a.SegmentID != 0 || a.LeafID != 0 {
		t.Fatalf("wrong address: %+v", a)
	}
	if _, err := h.ReserveAddress("0", "site", "dev", now); err == nil {
		t.Fatal("double reservation accepted")
	}
	if len(h.PendingSegments()) != 0 {
		t.Fatal("uncommitted leaf entered pending")
	}
	if err := h.AbortReservation(r); err != nil {
		t.Fatal(err)
	}
	if err := h.AbortReservation(r); err == nil {
		t.Fatal("reservation aborted twice")
	}
	r, err = h.ReserveAddress("0", "site", "dev", now)
	if err != nil {
		t.Fatal(err)
	}
	if r.Address() != a {
		t.Fatalf("aborted address was not reused: %+v", r.Address())
	}
	if err := h.CommitReservation(r, [32]byte{1}, now); err != nil {
		t.Fatal(err)
	}
	if err := h.CommitReservation(r, [32]byte{1}, now); err == nil {
		t.Fatal("reservation committed twice")
	}
	r, err = h.ReserveAddress("0", "site", "dev", now)
	if err != nil {
		t.Fatal(err)
	}
	if r.Address().LeafID != 1 {
		t.Fatal("LeafID did not advance")
	}
	if err := h.CommitReservation(r, [32]byte{2}, now); err != nil {
		t.Fatal(err)
	}
	if len(h.PendingSegments()) != 1 || h.PendingSegments()[0].LeafCount != 2 {
		t.Fatal("full Segment did not seal")
	}
	if _, err := h.ReserveAddress("0", "site", "dev", now); err != nil {
		t.Fatal("next Segment not opened lazily: ", err)
	}
}

func TestReservationHoldsPositionAcrossExpiryScan(t *testing.T) {
	h, err := NewHMF(1, 1, 5, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Unix(100, 0)
	r, err := h.ReserveAddress("0", "site", "dev", start)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.SealExpired(start.Add(2 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(h.PendingSegments()) != 0 {
		t.Fatal("reserved Segment sealed before commit")
	}
	if err := h.CommitReservation(r, [32]byte{3}, start.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(h.PendingSegments()) != 1 {
		t.Fatal("expired Segment not sealed after commit")
	}
}
