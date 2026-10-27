package system

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/SirojWongpitakroj/mva-phv/internal/canonicalize"
	"github.com/SirojWongpitakroj/mva-phv/internal/hmf"
	"github.com/SirojWongpitakroj/mva-phv/internal/hpbf"
	"github.com/SirojWongpitakroj/mva-phv/internal/mpm"
	"github.com/SirojWongpitakroj/mva-phv/internal/mva"
	"github.com/SirojWongpitakroj/mva-phv/internal/phv"
)

// Config describes one fresh, in-memory system. Region IDs are "0" through
// NumRegions-1, matching the current MVA and HPBF constructors.
type Config struct {
	NumRegions      int
	ShardsPerRegion int
	MaxSegmentSize  int
	SealInterval    time.Duration
	MVAOrder        int
	FilterItems     int
	FalsePositive   float64
	EncryptionKey   []byte
	AuditWorkers    int
}

// System is the composition root. MPM alone changes authenticated state;
// PHV reads only finalized state through its interfaces.
type System struct {
	manager     *mpm.Manager
	auditor     *phv.Auditor
	evidence    *MemoryEvidence
	checkpoints *MemoryCheckpoints
}

// New creates all components for a fresh process. Its in-memory evidence and
// checkpoints are intentionally ephemeral; they do not provide restart recovery.
func New(config Config) (*System, error) {
	if config.NumRegions <= 0 || config.ShardsPerRegion <= 0 || config.MaxSegmentSize <= 0 ||
		config.SealInterval <= 0 || config.MVAOrder < 3 || config.FilterItems <= 0 ||
		config.FalsePositive <= 0 || config.FalsePositive >= 1 || len(config.EncryptionKey) != 32 ||
		config.AuditWorkers < 0 {
		return nil, fmt.Errorf("new system: invalid region, shard, segment, MVA, HPBF, key, or worker configuration")
	}
	h, err := hmf.NewHMF(config.NumRegions, config.ShardsPerRegion, config.MaxSegmentSize, config.SealInterval)
	if err != nil {
		return nil, fmt.Errorf("new system HMF: %w", err)
	}
	m, err := mva.NewMVA(config.NumRegions, config.MVAOrder)
	if err != nil {
		return nil, fmt.Errorf("new system MVA: %w", err)
	}
	p, err := hpbf.NewHPBF(config.NumRegions, config.ShardsPerRegion, config.FilterItems, config.FalsePositive)
	if err != nil {
		return nil, fmt.Errorf("new system HPBF: %w", err)
	}
	encryptor, err := canonicalize.NewAEADService(config.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("new system encryptor: %w", err)
	}
	evidence, err := newMemoryEvidence(config.NumRegions, config.ShardsPerRegion, h)
	if err != nil {
		return nil, fmt.Errorf("new system evidence: %w", err)
	}
	checkpoints := NewMemoryCheckpoints()
	manager, err := mpm.New(mpm.Options{
		HMF: &mpm.HMFAdapter{Tree: h}, MVA: &mpm.MVAAdapter{Tree: m},
		HPBF: &mpm.HPBFAdapter{Tree: p}, Encryptor: encryptor,
		Locator: mpm.CanonicalLocator{}, Evidence: evidence, Checkpoints: checkpoints,
	})
	if err != nil {
		return nil, fmt.Errorf("new system MPM: %w", err)
	}
	regions := make([]string, config.NumRegions)
	for i := range regions {
		regions[i] = strconv.Itoa(i)
	}
	auditor := &phv.Auditor{
		Roots:  phv.CurrentRoots{Manager: manager, Checkpoints: checkpoints},
		Pruner: phv.CurrentHPBFPruner{Tree: p}, Resolver: phv.CurrentMVAResolver{Tree: m},
		Repository: evidence, Topology: phv.Topology{RegionIDs: regions, ShardsPerRegion: config.ShardsPerRegion},
		Workers: config.AuditWorkers,
	}
	return &System{manager: manager, auditor: auditor, evidence: evidence, checkpoints: checkpoints}, nil
}

func (s *System) Ingest(ctx context.Context, input mpm.Input, now time.Time) (mpm.Receipt, error) {
	if s == nil || s.manager == nil {
		return mpm.Receipt{}, fmt.Errorf("system: not initialized")
	}
	return s.manager.Ingest(ctx, input, now)
}

func (s *System) SealExpired(ctx context.Context, now time.Time) error {
	if s == nil || s.manager == nil {
		return fmt.Errorf("system: not initialized")
	}
	return s.manager.SealExpired(ctx, now)
}

func (s *System) PrepareFinalization(ctx context.Context, epoch uint64) (mpm.Candidate, error) {
	if s == nil || s.manager == nil {
		return mpm.Candidate{}, fmt.Errorf("system: not initialized")
	}
	return s.manager.PrepareFinalization(ctx, epoch)
}

func (s *System) CommitFinalization(ctx context.Context, epoch uint64) ([32]byte, error) {
	if s == nil || s.manager == nil {
		return [32]byte{}, fmt.Errorf("system: not initialized")
	}
	return s.manager.CommitFinalization(ctx, epoch)
}

func (s *System) Finalized() (uint64, mpm.Roots) {
	if s == nil || s.manager == nil {
		return 0, mpm.Roots{}
	}
	return s.manager.Finalized()
}

func (s *System) Audit(ctx context.Context, request phv.Request) (phv.Result, error) {
	if s == nil || s.auditor == nil {
		return phv.Result{}, fmt.Errorf("system: not initialized")
	}
	return s.auditor.Audit(ctx, request)
}

// VerifyProof checks a detached audit package against this process's trusted
// in-memory checkpoint store, without consulting live component state.
func (s *System) VerifyProof(ctx context.Context, proof phv.Proof) (phv.Verification, error) {
	if s == nil || s.checkpoints == nil {
		return phv.Verification{}, fmt.Errorf("system: not initialized")
	}
	return phv.VerifyAuditProof(ctx, proof, s.checkpoints)
}

var _ mpm.EvidenceRepository = (*MemoryEvidence)(nil)
var _ phv.Repository = (*MemoryEvidence)(nil)
var _ mpm.CheckpointStore = (*MemoryCheckpoints)(nil)
