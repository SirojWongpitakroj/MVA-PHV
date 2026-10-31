package system

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"

	"github.com/SirojWongpitakroj/mva-phv/internal/canonicalize"
	"github.com/SirojWongpitakroj/mva-phv/internal/cloudprovider"
	"github.com/SirojWongpitakroj/mva-phv/internal/hmf"
	"github.com/SirojWongpitakroj/mva-phv/internal/hpbf"
	"github.com/SirojWongpitakroj/mva-phv/internal/mpm"
	"github.com/SirojWongpitakroj/mva-phv/internal/mva"
	"github.com/SirojWongpitakroj/mva-phv/internal/phv"
	"github.com/SirojWongpitakroj/mva-phv/internal/storage/cassandra"
)

// Config describes one fresh system. Region IDs are "0" through
// NumRegions-1, matching the current MVA and HPBF constructors.
type Config struct {
	NumRegions      int
	SiteRegions     mpm.SiteRegionStore  // Required for durable multi-region deployments.
	DeviceShards    mpm.DeviceShardStore // Required for durable sticky Shard placement.
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
	evidence    mpm.EvidenceRepository
	ciphertexts cloudprovider.Provider
	checkpoints mpm.CheckpointStore
	trusted     mpm.CheckpointStore
}

type evidencePorts struct {
	writes   mpm.EvidenceRepository
	reads    phv.Repository
	roots    phv.TrustedRoots
	pruner   phv.Pruner
	resolver phv.Resolver
}

type evidenceWiring func(*hmf.HMF, *mva.MVA, *hpbf.HPBF) (evidencePorts, error)

// NewWithStorage uses Cassandra for CLS evidence and an independent trusted
// checkpoint store. This constructor is for a fresh deployment; restoring an
// existing finalized epoch still requires component recovery support.
func NewWithStorage(config Config, ciphertexts cloudprovider.Provider, cls *cassandra.Store, checkpoints mpm.CheckpointStore) (*System, error) {
	if cls == nil || checkpoints == nil {
		return nil, fmt.Errorf("new system: CLS and checkpoint store are required")
	}
	if config.NumRegions > 1 && config.SiteRegions == nil {
		return nil, fmt.Errorf("new system: persistent multi-region deployment requires a durable site-region store")
	}
	if config.ShardsPerRegion > 1 && config.DeviceShards == nil {
		return nil, fmt.Errorf("new system: persistent multi-Shard deployment requires a durable device-Shard store")
	}
	return newSystem(config, ciphertexts, checkpoints, func(h *hmf.HMF, m *mva.MVA, p *hpbf.HPBF) (evidencePorts, error) {
		source := &cassandra.ComponentEvidenceSource{Store: cls, HMF: h, MVA: m, HPBF: p}
		writes, err := cassandra.NewMPMRepository(cls, source)
		if err != nil {
			return evidencePorts{}, fmt.Errorf("new system CLS: %w", err)
		}
		return evidencePorts{writes: writes, reads: cls,
			roots:    phv.CheckpointRoots{Evidence: cls, Checkpoints: checkpoints},
			pruner:   phv.HistoricalHPBFPruner{Source: cls},
			resolver: phv.HistoricalMVAResolver{Reader: cls}}, nil
	})
}

func newSystem(config Config, ciphertexts cloudprovider.Provider, checkpoints mpm.CheckpointStore, wire evidenceWiring) (*System, error) {
	if config.NumRegions <= 0 || config.ShardsPerRegion <= 0 || config.MaxSegmentSize <= 0 ||
		config.SealInterval <= 0 || config.MVAOrder < 3 || config.FilterItems <= 0 ||
		config.FalsePositive <= 0 || config.FalsePositive >= 1 || len(config.EncryptionKey) != 32 ||
		config.AuditWorkers < 0 {
		return nil, fmt.Errorf("new system: invalid region, shard, segment, MVA, HPBF, key, or worker configuration")
	}
	if ciphertexts == nil || checkpoints == nil || wire == nil {
		return nil, fmt.Errorf("new system: ciphertext provider, checkpoint store, and evidence wiring are required")
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
	ports, err := wire(h, m, p)
	if err != nil {
		return nil, err
	}
	if ports.writes == nil || ports.reads == nil || ports.pruner == nil || ports.resolver == nil {
		return nil, fmt.Errorf("new system: incomplete evidence wiring")
	}
	regions := make([]string, config.NumRegions)
	for i := range regions {
		regions[i] = strconv.Itoa(i)
	}
	siteRegions := config.SiteRegions
	if siteRegions == nil {
		siteRegions = mpm.NewMemorySiteRegions()
	}
	deviceShards := config.DeviceShards
	if deviceShards == nil {
		deviceShards = mpm.NewMemoryDeviceShards()
	}
	manager, err := mpm.New(mpm.Options{
		Regions: regions, SiteRegions: siteRegions, ShardsPerRegion: config.ShardsPerRegion, DeviceShards: deviceShards,
		HMF: &mpm.HMFAdapter{Tree: h}, MVA: &mpm.MVAAdapter{Tree: m},
		HPBF: &mpm.HPBFAdapter{Tree: p}, Encryptor: encryptor,
		Locator: mpm.CanonicalLocator{}, Evidence: ports.writes, Ciphertexts: ciphertexts, Checkpoints: checkpoints,
	})
	if err != nil {
		return nil, fmt.Errorf("new system MPM: %w", err)
	}
	if ports.roots == nil {
		ports.roots = phv.CurrentRoots{Manager: manager, Checkpoints: checkpoints}
	}
	auditor := &phv.Auditor{
		Roots:  ports.roots,
		Pruner: ports.pruner, Resolver: ports.resolver,
		Repository: ports.reads, Ciphertexts: ciphertexts, Topology: phv.Topology{RegionIDs: regions, ShardsPerRegion: config.ShardsPerRegion},
		Workers: config.AuditWorkers,
	}
	return &System{manager: manager, auditor: auditor, evidence: ports.writes, ciphertexts: ciphertexts, checkpoints: checkpoints, trusted: checkpoints}, nil
}

func (s *System) Ingest(ctx context.Context, input mpm.Input, now time.Time) (mpm.Receipt, error) {
	if s == nil || s.manager == nil {
		return mpm.Receipt{}, fmt.Errorf("system: not initialized")
	}
	return s.manager.Ingest(ctx, input, now)
}

// IngestCanonical sends one dataset observation to MPM. Value and Label stay
// in the encrypted plaintext; MPM derives placement only from identity fields.
func (s *System) IngestCanonical(ctx context.Context, event canonicalize.CanonicalRecord, now time.Time) (mpm.Receipt, error) {
	if event.Dataset == "" || event.Site == "" || event.Device == "" || event.Type == "" ||
		event.Timestamp.IsZero() || event.Value == "" || (event.Label != "normal" && event.Label != "attack") {
		return mpm.Receipt{}, fmt.Errorf("system: invalid canonical record")
	}
	plaintext, err := json.Marshal(event)
	if err != nil {
		return mpm.Receipt{}, fmt.Errorf("system: encode canonical record: %w", err)
	}
	return s.Ingest(ctx, mpm.Input{Dataset: event.Dataset, SiteID: event.Site,
		DeviceID: event.Device, Type: event.Type, TS: event.Timestamp, Plaintext: plaintext}, now)
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

// VerifyProof checks a detached audit package against the trusted checkpoint
// store, without consulting live component state.
func (s *System) VerifyProof(ctx context.Context, proof phv.Proof) (phv.Verification, error) {
	if s == nil || s.trusted == nil {
		return phv.Verification{}, fmt.Errorf("system: not initialized")
	}
	return phv.VerifyAuditProof(ctx, proof, s.trusted)
}
