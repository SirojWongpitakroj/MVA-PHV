package phv

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
	"uuid"

	"github.com/SirojWongpitakroj/mva-phv/internal/cloudprovider"
	"github.com/SirojWongpitakroj/mva-phv/internal/mpm"
	"github.com/SirojWongpitakroj/mva-phv/internal/mva"
)

type faultCP struct {
	base      cloudprovider.Reader
	mode      string
	calls     int
	requested []uuid.UUID
}

func (cp *faultCP) GetCiphertexts(ctx context.Context, region string, ids []uuid.UUID) ([]cloudprovider.Ciphertext, error) {
	cp.calls++
	cp.requested = append(cp.requested, ids...)
	if cp.mode == "unavailable" {
		return nil, errors.New("CP unavailable")
	}
	values, err := cp.base.GetCiphertexts(ctx, region, ids)
	if err != nil {
		return nil, err
	}
	switch cp.mode {
	case "missing":
		return nil, nil
	case "duplicate":
		if len(values) > 0 {
			values = append(values, values[0])
		}
	case "unexpected":
		values = append(values, cloudprovider.Ciphertext{LogID: uuid.UUID{99}})
	case "malformed":
		if len(values) > 0 {
			values[0].Nonce = nil
		}
	case "version":
		if len(values) > 0 {
			values[0].Version++
		}
	case "changed":
		if len(values) > 0 {
			values[0].Ciphertext[0] ^= 0xff
		}
	case "nonce":
		if len(values) > 0 {
			values[0].Nonce[0] ^= 0xff
		}
	}
	return values, nil
}

func TestExternalCPCiphertextValidationAfterMVA(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want error
	}{
		{"missing", ErrMissingEvidence},
		{"duplicate", ErrDuplicateEvidence},
		{"unexpected", ErrUnexpectedEvidence},
		{"malformed", ErrEvidence},
		{"version", cloudprovider.ErrUnsupportedVersion},
		{"unavailable", ErrRepositoryFailure},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			f := newFixture(t)
			selected := f.records[0]
			cp := &faultCP{base: f.repo, mode: tc.mode}
			a := Auditor{Roots: fixedRoots{mpm.Roots{HMF: f.root}}, Resolver: fixedResolver{[]SelectedRecord{selected}, 1}, Repository: f.repo, Ciphertexts: cp, Topology: f.topology}
			query := mva.AttrRangeQuery{SiteID: selected.Descriptor.SiteID, DevID: selected.Descriptor.DeviceID, Type: selected.Descriptor.Type, StartTS: selected.Descriptor.TS, EndTS: selected.Descriptor.TS}
			result, err := a.Audit(context.Background(), Request{Epoch: 1, Query: query})
			if !errors.Is(err, tc.want) || !result.Unresolved || cp.calls != 1 || len(cp.requested) != 1 || cp.requested[0] != selected.LogID {
				t.Fatalf("CP result err=%v unresolved=%v calls=%d ids=%v", err, result.Unresolved, cp.calls, cp.requested)
			}
		})
	}
}

func TestAlteredCPCiphertextIsCryptographicMismatch(t *testing.T) {
	for _, mode := range []string{"changed", "nonce"} {
		t.Run(mode, func(t *testing.T) {
			f := newFixture(t)
			selected := f.records[0]
			cp := &faultCP{base: f.repo, mode: mode}
			a := Auditor{Roots: fixedRoots{mpm.Roots{HMF: f.root}}, Resolver: fixedResolver{[]SelectedRecord{selected}, 1}, Repository: f.repo, Ciphertexts: cp, Topology: f.topology}
			query := mva.AttrRangeQuery{SiteID: selected.Descriptor.SiteID, DevID: selected.Descriptor.DeviceID, Type: selected.Descriptor.Type, StartTS: selected.Descriptor.TS, EndTS: selected.Descriptor.TS}
			result, err := a.Audit(context.Background(), Request{Epoch: 1, Query: query})
			if err != nil || result.Verified || result.Unresolved || !errors.Is(result.IntegrityError, ErrHMFRootMismatch) {
				t.Fatalf("modified CP %s err=%v result=%+v", mode, err, result)
			}
		})
	}
}

func TestUnfinalizedEpochNeverContactsCP(t *testing.T) {
	f := newFixture(t)
	cp := &faultCP{base: f.repo}
	a := Auditor{Roots: fixedRoots{mpm.Roots{HMF: f.root}}, Resolver: fixedResolver{f.records[:1], 2}, Repository: f.repo, Ciphertexts: cp, Topology: f.topology}
	selected := f.records[0]
	query := mva.AttrRangeQuery{SiteID: selected.Descriptor.SiteID, DevID: selected.Descriptor.DeviceID, Type: selected.Descriptor.Type, StartTS: selected.Descriptor.TS, EndTS: selected.Descriptor.TS}
	if _, err := a.Audit(context.Background(), Request{Epoch: 1, Query: query}); !errors.Is(err, ErrWrongEpoch) || cp.calls != 0 {
		t.Fatalf("CP contacted before authenticated scope: %v, %d", err, cp.calls)
	}
}

type measuringCP struct {
	mu                       sync.Mutex
	calls, active, maxActive int
	requested                map[uuid.UUID]int
}

func (cp *measuringCP) GetCiphertexts(ctx context.Context, _ string, ids []uuid.UUID) ([]cloudprovider.Ciphertext, error) {
	cp.mu.Lock()
	cp.calls++
	cp.active++
	if cp.active > cp.maxActive {
		cp.maxActive = cp.active
	}
	for _, id := range ids {
		cp.requested[id]++
	}
	cp.mu.Unlock()
	defer func() { cp.mu.Lock(); cp.active--; cp.mu.Unlock() }()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(15 * time.Millisecond):
	}
	values := make([]cloudprovider.Ciphertext, len(ids))
	for i, id := range ids {
		values[i] = cloudprovider.Ciphertext{LogID: id, Ciphertext: []byte{1}, Nonce: make([]byte, 12), Tag: make([]byte, 16), AD: []byte{1}, Version: cloudprovider.EncryptionVersionAESGCM}
	}
	return values, nil
}

func TestCPBatchesLogIDsWithBoundedConcurrency(t *testing.T) {
	cp := &measuringCP{requested: make(map[uuid.UUID]int)}
	a := Auditor{Ciphertexts: cp, Workers: 2}
	selected := make([]SelectedRecord, 260)
	for i := range selected {
		var id uuid.UUID
		id[0], id[1] = byte(i>>8), byte(i)
		selected[i] = SelectedRecord{LogID: id, Descriptor: mpm.Descriptor{RegionID: "R"}, Address: mpm.Address{RegionID: "R"}}
	}
	// The all-zero UUID is invalid, so make the first ID nonzero too.
	selected[0].LogID[15] = 1
	logs, calls, err := a.fetchCiphertexts(context.Background(), selected)
	if err != nil || calls != 3 || cp.calls != 3 || cp.maxActive != 2 || len(logs) != len(selected) || len(cp.requested) != len(selected) {
		t.Fatalf("batching logs=%d calls=%d CP calls=%d max=%d unique=%d err=%v", len(logs), calls, cp.calls, cp.maxActive, len(cp.requested), err)
	}
	for _, count := range cp.requested {
		if count != 1 {
			t.Fatal("LogID requested more than once")
		}
	}
}
