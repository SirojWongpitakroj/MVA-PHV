package domain

import (
	"bytes"
	"testing"
	"time"
	"uuid"
)

func TestDeserializeRoundTrip(t *testing.T) {
	id := uuid.UUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	number := uint64(0xfedcba9876543210)
	when := time.Unix(1_700_000_000, 123_456_789).UTC()
	payload := []byte{0, 1, 2, 255}
	encoded, err := Serialize("log", number, id, when, payload)
	if err != nil {
		t.Fatal(err)
	}

	var gotName string
	var gotNumber uint64
	var gotID uuid.UUID
	var gotWhen time.Time
	var gotPayload []byte
	if err := Deserialize(encoded, &gotName, &gotNumber, &gotID, &gotWhen, &gotPayload); err != nil {
		t.Fatal(err)
	}
	if gotName != "log" || gotNumber != number || gotID != id || !gotWhen.Equal(when) || !bytes.Equal(gotPayload, payload) {
		t.Fatalf("round trip mismatch: name=%q number=%d id=%v time=%v payload=%v", gotName, gotNumber, gotID, gotWhen, gotPayload)
	}
}

func TestSerializeDeserializeBoundaryValues(t *testing.T) {
	for _, tc := range []struct {
		name    string
		number  uint64
		when    time.Time
		payload []byte
	}{
		{"zero and empty", 0, time.Unix(0, 0).UTC(), nil},
		{"maximum and pre-epoch", ^uint64(0), time.Unix(-1, 1).UTC(), []byte{0, 255}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var id uuid.UUID
			encoded, err := Serialize("", tc.number, id, tc.when, tc.payload)
			if err != nil {
				t.Fatal(err)
			}
			var name string
			var number uint64
			var gotID uuid.UUID
			var when time.Time
			var payload []byte
			if err := Deserialize(encoded, &name, &number, &gotID, &when, &payload); err != nil {
				t.Fatal(err)
			}
			if name != "" || number != tc.number || gotID != id || !when.Equal(tc.when) || !bytes.Equal(payload, tc.payload) {
				t.Fatalf("round trip mismatch: name=%q number=%d id=%v time=%v payload=%v", name, number, gotID, when, payload)
			}
		})
	}
}

func TestDeserializeFixedLengthBytesBetweenStrings(t *testing.T) {
	encoded, err := Serialize("before", []byte{1, 2, 3}, "after")
	if err != nil {
		t.Fatal(err)
	}

	var before, after string
	middle := make([]byte, 3)
	if err := Deserialize(encoded, &before, &middle, &after); err != nil {
		t.Fatal(err)
	}
	if before != "before" || !bytes.Equal(middle, []byte{1, 2, 3}) || after != "after" {
		t.Fatalf("decoded values: %q, %v, %q", before, middle, after)
	}
}

func TestDeserializeRejectsInvalidInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		dest []any
	}{
		{"short string length", []byte{0, 0}, []any{new(string)}},
		{"short string value", []byte{0, 0, 0, 2, 'x'}, []any{new(string)}},
		{"short UUID", []byte{1, 2, 3}, []any{new(uuid.UUID)}},
		{"short uint64", []byte{1, 2, 3}, []any{new(uint64)}},
		{"short time", []byte{1, 2, 3}, []any{new(time.Time)}},
		{"trailing bytes", []byte{1}, nil},
		{"unsupported destination", nil, []any{new(int)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := Deserialize(tc.data, tc.dest...); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
