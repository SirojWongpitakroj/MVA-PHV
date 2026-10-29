package mpm

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
	"uuid"

	"github.com/SirojWongpitakroj/mva-phv/internal/cloudprovider"
)

type observedEncryptor struct {
	h      *testHMF
	called bool
	id     uuid.UUID
	desc   Descriptor
}

func (e *observedEncryptor) Encrypt(ctx context.Context, id uuid.UUID, desc Descriptor, plain []byte) (Encrypted, error) {
	if id == (uuid.UUID{}) || desc.RegionID == "" || desc.SiteID == "" || desc.DeviceID == "" || desc.Type == "" || desc.TS.IsZero() ||
		len(e.h.reserved) != 1 || len(e.h.inserted) != 0 {
		return Encrypted{}, errors.New("encryption preceded identity, descriptor, or HMF reservation")
	}
	e.called, e.id, e.desc = true, id, desc
	return (testEncrypt{}).Encrypt(ctx, id, desc, plain)
}

type observedLocator struct {
	encrypt *observedEncryptor
	called  bool
}

func (l *observedLocator) CommitLocator(id uuid.UUID, desc Descriptor, address Address) ([32]byte, error) {
	if !l.encrypt.called || id != l.encrypt.id || desc != l.encrypt.desc || address.RegionID != desc.RegionID {
		return [32]byte{}, errors.New("locator did not use pre-encryption identity, descriptor, and reserved address")
	}
	l.called = true
	return (testLocator{}).CommitLocator(id, desc, address)
}

type observedCP struct {
	h     *testHMF
	v     *testMVA
	b     *testHPBF
	e     *testEvidence
	l     *observedLocator
	calls int
	id    uuid.UUID
}

func (cp *observedCP) StoreCiphertext(_ context.Context, region string, value cloudprovider.Ciphertext) error {
	if !cp.l.called || region != cp.l.encrypt.desc.RegionID || value.LogID != cp.l.encrypt.id ||
		len(value.Nonce) != 12 || len(value.Tag) != 16 || len(value.AD) == 0 || value.Version != cloudprovider.EncryptionVersionAESGCM ||
		len(cp.h.reserved) != 1 || len(cp.h.inserted) != 0 || len(cp.v.received) != 0 ||
		len(cp.b.received) != 0 || len(cp.e.accepted) != 0 {
		return errors.New("CP write occurred before commitments or after authenticated updates")
	}
	cp.calls++
	cp.id = value.LogID
	return nil
}

type observedCLS struct {
	EvidenceRepository
	cp *observedCP
}

func (cls observedCLS) PersistAccepted(ctx context.Context, record Record, mv MVAUpdate, hp HPBFUpdate) error {
	if cls.cp.calls != 1 || record.Log.LogID != cls.cp.id ||
		len(record.Log.Ciphertext)+len(record.Log.Nonce)+len(record.Log.Tag)+len(record.Log.AD) != 0 ||
		len(cls.cp.v.received) != 1 || len(cls.cp.b.received) != 1 || len(cls.cp.h.inserted) != 1 {
		return fmt.Errorf("CLS received ciphertext or missed a coordinated authenticated update")
	}
	return cls.EvidenceRepository.PersistAccepted(ctx, record, mv, hp)
}

func TestIngestionDependenciesAcrossEncryptorCPAndCLS(t *testing.T) {
	r := newRig(t, 2)
	encrypt := &observedEncryptor{h: r.h}
	locator := &observedLocator{encrypt: encrypt}
	cp := &observedCP{h: r.h, v: r.v, b: r.b, e: r.e, l: locator}
	r.manager.opts.Encryptor = encrypt
	r.manager.opts.Locator = locator
	r.manager.opts.Ciphertexts = cp
	r.manager.opts.Evidence = observedCLS{EvidenceRepository: r.e, cp: cp}
	receipt, err := r.manager.Ingest(context.Background(), input("P3_LIT01"), time.Unix(200, 0))
	if err != nil || !encrypt.called || !locator.called || cp.calls != 1 || cp.id != receipt.LogID ||
		len(r.e.accepted) != 1 || r.e.accepted[0].Address != receipt.Address || r.h.inserted[0].Leaf != receipt.HMFLeaf {
		t.Fatalf("ingestion dependency order failed: receipt=%+v err=%v", receipt, err)
	}
}

type countingCP struct{ writes int }

func (cp *countingCP) StoreCiphertext(context.Context, string, cloudprovider.Ciphertext) error {
	cp.writes++
	return nil
}

type countingLocator struct{ calls int }

func (l *countingLocator) CommitLocator(uuid.UUID, Descriptor, Address) ([32]byte, error) {
	l.calls++
	return [32]byte{}, nil
}

func TestEncryptionFailureNeverContactsCPOrAuthenticatedState(t *testing.T) {
	r := newRig(t, 1)
	cp := &countingCP{}
	locator := &countingLocator{}
	r.manager.opts.Ciphertexts = cp
	r.manager.opts.Encryptor = unavailableEncryptor{}
	r.manager.opts.Locator = locator
	receipt, err := r.manager.Ingest(context.Background(), input("P3_LIT01"), time.Unix(200, 0))
	if err == nil || receipt != (Receipt{}) || cp.writes != 0 || locator.calls != 0 || len(r.h.reserved) != 0 ||
		len(r.h.inserted) != 0 || len(r.v.received) != 0 || len(r.b.received) != 0 || len(r.e.accepted) != 0 {
		t.Fatalf("encryption failure leaked state: %+v, %v", receipt, err)
	}
}

func TestCLSFailureLeavesCPObjectButNoFinalizedRecord(t *testing.T) {
	r := newRig(t, 1)
	cp := cloudprovider.NewMemory()
	r.manager.opts.Ciphertexts = cp
	r.e.failAccepted = true
	receipt, err := r.manager.Ingest(context.Background(), input("P3_LIT01"), time.Unix(200, 0))
	if err == nil || receipt.LogID == (uuid.UUID{}) {
		t.Fatalf("CLS failure was not reported with partial address: %+v, %v", receipt, err)
	}
	values, err := cp.GetCiphertexts(context.Background(), receipt.Address.RegionID, []uuid.UUID{receipt.LogID})
	if err != nil || len(values) != 1 {
		t.Fatalf("CP object disappeared after CLS failure: %+v, %v", values, err)
	}
	if _, err := r.manager.PrepareFinalization(context.Background(), 1); !errors.Is(err, ErrIncompleteWorkingState) {
		t.Fatalf("partial CLS state became a candidate: %v", err)
	}
	if len(r.c.roots) != 0 || len(r.e.accepted) != 0 {
		t.Fatal("failed CLS write reached checkpoint or became accepted")
	}
}
