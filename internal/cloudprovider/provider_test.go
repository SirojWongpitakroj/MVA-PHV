package cloudprovider

import (
	"context"
	"errors"
	"slices"
	"testing"
	"uuid"
)

func sample(id byte) Ciphertext {
	return Ciphertext{LogID: uuid.UUID{id}, Ciphertext: []byte{id + 10}, Nonce: make([]byte, 12), Tag: make([]byte, 16), AD: []byte{1}}
}

func TestMemoryStoresOnlyRequestedLogIDs(t *testing.T) {
	ctx := context.Background()
	cp := NewMemory()
	for _, id := range []byte{1, 2, 3} {
		if err := cp.StoreCiphertext(ctx, "Singapore", sample(id)); err != nil {
			t.Fatal(err)
		}
	}
	if err := cp.StoreCiphertext(ctx, "Singapore", sample(1)); err != nil {
		t.Fatalf("idempotent store: %v", err)
	}
	changed := sample(1)
	changed.Ciphertext[0]++
	if err := cp.StoreCiphertext(ctx, "Singapore", changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting write: %v", err)
	}
	got, err := cp.GetCiphertexts(ctx, "Singapore", []uuid.UUID{sample(3).LogID, sample(1).LogID})
	if err != nil || len(got) != 2 || got[0].LogID != sample(3).LogID || got[1].LogID != sample(1).LogID {
		t.Fatalf("exact lookup: %+v, %v", got, err)
	}
	got[0].Ciphertext[0] = 0
	again, err := cp.GetCiphertexts(ctx, "Singapore", []uuid.UUID{sample(3).LogID})
	if err != nil || !slices.Equal(again[0].Ciphertext, sample(3).Ciphertext) {
		t.Fatal("provider bytes were aliased")
	}
	missing, err := cp.GetCiphertexts(ctx, "Singapore", []uuid.UUID{sample(9).LogID})
	if err != nil || len(missing) != 0 {
		t.Fatalf("missing ID: %+v, %v", missing, err)
	}
	wrongRegion, err := cp.GetCiphertexts(ctx, "Tokyo", []uuid.UUID{sample(1).LogID})
	if err != nil || len(wrongRegion) != 0 {
		t.Fatalf("cross-region leak: %+v, %v", wrongRegion, err)
	}
}

func TestRouterUsesConfiguredLogicalRegion(t *testing.T) {
	ctx := context.Background()
	singapore, tokyo := NewMemory(), NewMemory()
	router, err := NewRouter(map[string]Provider{"Singapore": singapore, "Tokyo": tokyo})
	if err != nil {
		t.Fatal(err)
	}
	if err := router.StoreCiphertext(ctx, "Tokyo", sample(4)); err != nil {
		t.Fatal(err)
	}
	if records, _ := singapore.GetCiphertexts(ctx, "Tokyo", []uuid.UUID{sample(4).LogID}); len(records) != 0 {
		t.Fatal("routed to wrong provider")
	}
	if records, err := router.GetCiphertexts(ctx, "Tokyo", []uuid.UUID{sample(4).LogID}); err != nil || len(records) != 1 {
		t.Fatalf("routed lookup: %+v, %v", records, err)
	}
	if _, err := router.GetCiphertexts(ctx, "unconfigured", []uuid.UUID{sample(4).LogID}); err == nil {
		t.Fatal("accepted unknown region")
	}
}

func TestMemoryRejectsMalformedMetadata(t *testing.T) {
	value := sample(5)
	value.Nonce = nil
	if err := NewMemory().StoreCiphertext(context.Background(), "R", value); err == nil {
		t.Fatal("accepted missing nonce")
	}
}
