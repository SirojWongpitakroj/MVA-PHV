package system

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"slices"
	"testing"
	"time"
	"uuid"

	"github.com/SirojWongpitakroj/mva-phv/internal/cloudprovider"
	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
	"github.com/SirojWongpitakroj/mva-phv/internal/hmf"
	"github.com/SirojWongpitakroj/mva-phv/internal/hpbf"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
	"github.com/SirojWongpitakroj/mva-phv/internal/mpm"
	"github.com/SirojWongpitakroj/mva-phv/internal/mva"
	"github.com/SirojWongpitakroj/mva-phv/internal/phv"
)

func industrialLog() mpm.Input {
	return mpm.Input{RegionID: "0", SiteID: "P3", DeviceID: "P3_LIT01", Type: "LevelReading",
		TS: time.Date(2026, 10, 28, 10, 15, 0, 0, time.UTC), Plaintext: []byte(`{"level_cm":142.5,"status":"normal"}`)}
}

func TestIndustrialLogIngestionBindsCPMVAHPBFAndHMF(t *testing.T) {
	config := testConfig()
	config.MaxSegmentSize = 1 // Sealing makes the exact HMF leaf available as immutable CLS evidence.
	s, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	input := industrialLog()
	receipt, err := s.Ingest(ctx, input, input.TS.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.LogID == (uuid.UUID{}) || receipt.Address.RegionID != input.RegionID ||
		receipt.Address.SegmentID != 0 || receipt.Address.LeafID != 0 {
		t.Fatalf("invalid identity/address: %+v", receipt)
	}
	wantShard, err := s.evidence.hmf.SelectShard(input.RegionID, input.SiteID, input.DeviceID)
	if err != nil || receipt.Address.ShardID != wantShard {
		t.Fatalf("wrong deterministic shard: %+v, %v", receipt.Address, err)
	}

	// CP can retrieve by LogID alone. It does not receive the HMF address or any proof state.
	values, err := s.ciphertexts.GetCiphertexts(ctx, input.RegionID, []uuid.UUID{receipt.LogID})
	if err != nil || len(values) != 1 || values[0].LogID != receipt.LogID {
		t.Fatalf("CP lookup: %+v, %v", values, err)
	}
	cp := values[0]
	if bytes.Equal(cp.Ciphertext, input.Plaintext) || bytes.Contains(cp.Ciphertext, input.Plaintext) ||
		len(cp.Nonce) != 12 || len(cp.Tag) != 16 {
		t.Fatal("CP did not receive a valid ciphertext-only AEAD record")
	}
	desc := mpm.Descriptor{RegionID: input.RegionID, SiteID: input.SiteID, DeviceID: input.DeviceID, Type: input.Type, TS: input.TS}
	wantAD, err := domain.Serialize("MVA-PHV:LOG:V1", receipt.LogID, desc.RegionID, desc.SiteID, desc.DeviceID, desc.Type, desc.TS.UTC())
	if err != nil || !bytes.Equal(cp.AD, wantAD) {
		t.Fatalf("AEAD associated data differs from accepted descriptor: %v", err)
	}
	block, err := aes.NewCipher(config.EncryptionKey)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	sealed := append(slices.Clone(cp.Ciphertext), cp.Tag...)
	opened, err := aead.Open(nil, cp.Nonce, sealed, cp.AD)
	if err != nil || !bytes.Equal(opened, input.Plaintext) {
		t.Fatalf("AEAD cannot recover accepted plaintext: %v", err)
	}
	wrongAD := slices.Clone(cp.AD)
	wrongAD[len(wrongAD)-1] ^= 1
	if _, err := aead.Open(nil, cp.Nonce, sealed, wrongAD); err == nil {
		t.Fatal("AEAD accepted altered associated data")
	}

	locator, err := (mpm.CanonicalLocator{}).CommitLocator(receipt.LogID, desc, receipt.Address)
	if err != nil || locator != receipt.Locator {
		t.Fatalf("locator does not bind LogID, X, and A: %v", err)
	}
	content := append(append(slices.Clone(cp.Nonce), cp.Ciphertext...), cp.Tag...)
	digest := sha256.Sum256(content)
	encodedLeaf, err := domain.Serialize([]byte("LOG"), receipt.LogID, locator[:], digest[:])
	if err != nil {
		t.Fatal(err)
	}
	leaf := sha256.Sum256(encodedLeaf)
	if leaf != receipt.HMFLeaf {
		t.Fatal("HMF commitment does not bind CP ciphertext")
	}
	segment := merkle.TreeID{Type: merkle.TreeSegment, RegionID: receipt.Address.RegionID, ShardID: receipt.Address.ShardID, SegmentID: receipt.Address.SegmentID}
	storedLeaf, ok := s.evidence.segmentNode[phv.NodeKey{Tree: segment, Level: 0, Index: receipt.Address.LeafID}]
	if !ok || storedLeaf.Hash != leaf || len(s.evidence.segments) != 1 {
		t.Fatal("CLS sealed evidence has a different HMF leaf or Segment")
	}
	if s.evidence.logIDs[receipt.LogID] != receipt.Address {
		t.Fatal("CLS address metadata differs from CP LogID and HMF placement")
	}
	if len(s.evidence.addresses) != 1 || len(s.manager.PendingSegments()) != 1 {
		t.Fatal("ingestion did not create one pending authenticated Segment")
	}

	// The correct Region-Shard filter contains the three protocol tokens.
	filter := s.auditor.Pruner.(phv.CurrentHPBFPruner).Tree
	_, bits, hashes, words, err := filter.WorkingShardFilter(receipt.Address.RegionID, receipt.Address.ShardID)
	if err != nil {
		t.Fatal(err)
	}
	bf, err := hpbf.RestoreBloomFilter(bits, hashes, words)
	if err != nil {
		t.Fatal(err)
	}
	for _, fields := range [][]string{{desc.SiteID}, {desc.SiteID, desc.DeviceID}, {desc.SiteID, desc.DeviceID, desc.Type}} {
		args := make([]any, len(fields))
		for i, field := range fields {
			args[i] = field
		}
		token, err := domain.Serialize(args...)
		if err != nil || !bf.Contains(token) {
			t.Fatalf("missing HPBF token %v: %v", fields, err)
		}
	}

	if _, err := s.PrepareFinalization(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitFinalization(ctx, 1); err != nil {
		t.Fatal(err)
	}
	byID, err := s.Audit(ctx, phv.Request{Epoch: 1, Query: mva.LogIDQuery{ID: receipt.LogID}})
	if err != nil || !byID.Verified || len(byID.Proof.Selected) != 1 || byID.Proof.Selected[0].Address != receipt.Address ||
		byID.Proof.Selected[0].Locator != locator || len(byID.Proof.Logs) != 1 || byID.Proof.Logs[0].LogID != receipt.LogID {
		t.Fatalf("Log-ID MVA/HMF/CP audit did not bind the record: verified=%v err=%v", byID.Verified, err)
	}
	query := mva.AttrRangeQuery{SiteID: desc.SiteID, DevID: desc.DeviceID, Type: desc.Type, StartTS: desc.TS, EndTS: desc.TS}
	byAttr, err := s.Audit(ctx, phv.Request{Epoch: 1, Query: query, UsePruning: true})
	if err != nil || !byAttr.Verified || byAttr.Proof.HPBF == nil || len(byAttr.Proof.Selected) != 1 ||
		byAttr.Proof.Selected[0].LogID != receipt.LogID || byAttr.Proof.Selected[0].Address != receipt.Address ||
		byAttr.Proof.Selected[0].Descriptor != desc || byAttr.Proof.Selected[0].Locator != locator {
		t.Fatalf("attribute MVA/HPBF/HMF/CP audit disagrees: verified=%v err=%v", byAttr.Verified, err)
	}
	verified, err := s.VerifyProof(ctx, byAttr.Proof)
	if err != nil || !verified.Valid {
		t.Fatalf("detached proof failed: %+v, %v", verified, err)
	}
	// The reference HMF implementation still owns its hashing rules.
	if root, err := hmf.RootHash(segment, 1, leaf); err != nil || root != s.evidence.segments[segment].Root {
		t.Fatalf("sealed Segment root mismatch: %v", err)
	}
}

func TestRepeatedSourceLogGetsUniqueIDsAndNoTimestampBloomToken(t *testing.T) {
	config := testConfig()
	config.MaxSegmentSize = 3
	s, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	input := industrialLog()
	first, err := s.Ingest(context.Background(), input, input.TS)
	if err != nil {
		t.Fatal(err)
	}
	// Current admission policy assigns a fresh LogID to each call, even when
	// the source payload and descriptor are identical.
	filter := s.auditor.Pruner.(phv.CurrentHPBFPruner).Tree
	_, _, _, before, err := filter.WorkingShardFilter(first.Address.RegionID, first.Address.ShardID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Ingest(context.Background(), input, input.TS.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	input.TS = input.TS.Add(time.Minute)
	third, err := s.Ingest(context.Background(), input, input.TS.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if first.LogID == second.LogID || second.LogID == third.LogID || first.LogID == third.LogID ||
		first.Address.LeafID != 0 || second.Address.LeafID != 1 || third.Address.LeafID != 2 {
		t.Fatal("repeated source admissions lost unique identity or order")
	}
	for _, id := range []uuid.UUID{first.LogID, second.LogID, third.LogID} {
		values, err := s.ciphertexts.GetCiphertexts(context.Background(), "0", []uuid.UUID{id})
		if err != nil || len(values) != 1 || values[0].LogID != id {
			t.Fatalf("missing distinct CP object %s: %v", id, err)
		}
	}
	_, _, _, after, err := filter.WorkingShardFilter(third.Address.RegionID, third.Address.ShardID)
	if err != nil || !slices.Equal(before, after) {
		t.Fatal("HPBF changed for identical Site/Device/Type with a different timestamp or LogID")
	}
}

// A malicious CP may return C_2 under LogID_1. MVA still selects LogID_1;
// the auditor must reject the substituted ciphertext against its HMF root.
type substitutedCP struct {
	base                cloudprovider.Reader
	target, replacement uuid.UUID
}

func (cp substitutedCP) GetCiphertexts(ctx context.Context, region string, ids []uuid.UUID) ([]cloudprovider.Ciphertext, error) {
	values, err := cp.base.GetCiphertexts(ctx, region, ids)
	if err != nil {
		return nil, err
	}
	replacement, err := cp.base.GetCiphertexts(ctx, region, []uuid.UUID{cp.replacement})
	if err != nil {
		return nil, err
	}
	for i := range values {
		if values[i].LogID == cp.target && len(replacement) == 1 {
			values[i].Ciphertext = replacement[0].Ciphertext
			values[i].Nonce = replacement[0].Nonce
			values[i].Tag = replacement[0].Tag
		}
	}
	return values, nil
}

func TestWrongCiphertextUnderValidLogIDFailsFinalizedAudit(t *testing.T) {
	config := testConfig()
	s, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	input := industrialLog()
	first, err := s.Ingest(context.Background(), input, input.TS)
	if err != nil {
		t.Fatal(err)
	}
	input.Plaintext = []byte(`{"level_cm":999.0}`)
	input.TS = input.TS.Add(time.Second)
	second, err := s.Ingest(context.Background(), input, input.TS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareFinalization(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitFinalization(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	s.auditor.Ciphertexts = substitutedCP{base: s.ciphertexts, target: first.LogID, replacement: second.LogID}
	result, err := s.Audit(context.Background(), phv.Request{Epoch: 1, Query: mva.LogIDQuery{ID: first.LogID}})
	if err != nil || result.Verified || result.Unresolved {
		t.Fatalf("substituted ciphertext was accepted or misclassified: verified=%v unresolved=%v err=%v", result.Verified, result.Unresolved, err)
	}
}

func TestLocatorAndLeafCommitmentsRejectChangedInputs(t *testing.T) {
	s, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	input := industrialLog()
	receipt, err := s.Ingest(context.Background(), input, input.TS)
	if err != nil {
		t.Fatal(err)
	}
	desc := mpm.Descriptor{RegionID: input.RegionID, SiteID: input.SiteID, DeviceID: input.DeviceID, Type: input.Type, TS: input.TS}
	locator := mpm.CanonicalLocator{}
	for name, change := range map[string]func(*uuid.UUID, *mpm.Descriptor, *mpm.Address){
		"LogID":     func(id *uuid.UUID, _ *mpm.Descriptor, _ *mpm.Address) { id[0] ^= 1 },
		"Region":    func(_ *uuid.UUID, d *mpm.Descriptor, a *mpm.Address) { d.RegionID, a.RegionID = "1", "1" },
		"Site":      func(_ *uuid.UUID, d *mpm.Descriptor, _ *mpm.Address) { d.SiteID = "P4" },
		"Device":    func(_ *uuid.UUID, d *mpm.Descriptor, _ *mpm.Address) { d.DeviceID = "P3_LIT02" },
		"Type":      func(_ *uuid.UUID, d *mpm.Descriptor, _ *mpm.Address) { d.Type = "Alarm" },
		"Timestamp": func(_ *uuid.UUID, d *mpm.Descriptor, _ *mpm.Address) { d.TS = d.TS.Add(time.Second) },
		"RID":       func(_ *uuid.UUID, _ *mpm.Descriptor, a *mpm.Address) { a.RegionID = "1" },
		"SID":       func(_ *uuid.UUID, _ *mpm.Descriptor, a *mpm.Address) { a.ShardID++ },
		"SegID":     func(_ *uuid.UUID, _ *mpm.Descriptor, a *mpm.Address) { a.SegmentID++ },
		"LeafID":    func(_ *uuid.UUID, _ *mpm.Descriptor, a *mpm.Address) { a.LeafID++ },
	} {
		t.Run(name, func(t *testing.T) {
			id, changedDesc, changedAddr := receipt.LogID, desc, receipt.Address
			change(&id, &changedDesc, &changedAddr)
			changed, err := locator.CommitLocator(id, changedDesc, changedAddr)
			if err == nil && changed == receipt.Locator {
				t.Fatal("changed authenticated field preserved locator commitment")
			}
		})
	}
	values, err := s.ciphertexts.GetCiphertexts(context.Background(), input.RegionID, []uuid.UUID{receipt.LogID})
	if err != nil || len(values) != 1 {
		t.Fatal(err)
	}
	cp := values[0]
	wrongID := receipt.LogID
	wrongID[0] ^= 1
	wrongLocator, err := locator.CommitLocator(wrongID, desc, receipt.Address)
	if err != nil || wrongLocator == receipt.Locator {
		t.Fatalf("changed LogID preserved locator: %v", err)
	}
	originalContent := append(append(slices.Clone(cp.Nonce), cp.Ciphertext...), cp.Tag...)
	originalDigest := sha256.Sum256(originalContent)
	wrongEncoding, err := domain.Serialize([]byte("LOG"), wrongID, wrongLocator[:], originalDigest[:])
	if err != nil || sha256.Sum256(wrongEncoding) == receipt.HMFLeaf {
		t.Fatalf("changed LogID preserved HMF commitment: %v", err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*cloudprovider.Ciphertext)
	}{
		{"ciphertext", func(c *cloudprovider.Ciphertext) { c.Ciphertext[0] ^= 1 }},
		{"nonce", func(c *cloudprovider.Ciphertext) { c.Nonce[0] ^= 1 }},
		{"tag", func(c *cloudprovider.Ciphertext) { c.Tag[0] ^= 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := cloudprovider.Ciphertext{LogID: cp.LogID, Ciphertext: slices.Clone(cp.Ciphertext), Nonce: slices.Clone(cp.Nonce), Tag: slices.Clone(cp.Tag), AD: slices.Clone(cp.AD), Version: cp.Version}
			tc.mutate(&changed)
			content := append(append(slices.Clone(changed.Nonce), changed.Ciphertext...), changed.Tag...)
			digest := sha256.Sum256(content)
			encoded, err := domain.Serialize([]byte("LOG"), receipt.LogID, receipt.Locator[:], digest[:])
			if err != nil || sha256.Sum256(encoded) == receipt.HMFLeaf {
				t.Fatalf("changed CP data preserved HMF leaf: %v", err)
			}
		})
	}
}
