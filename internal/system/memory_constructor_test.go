package system

import (
	"fmt"

	"github.com/SirojWongpitakroj/mva-phv/internal/cloudprovider"
	"github.com/SirojWongpitakroj/mva-phv/internal/hmf"
	"github.com/SirojWongpitakroj/mva-phv/internal/hpbf"
	"github.com/SirojWongpitakroj/mva-phv/internal/mpm"
	"github.com/SirojWongpitakroj/mva-phv/internal/mva"
	"github.com/SirojWongpitakroj/mva-phv/internal/phv"
)

// New is available only to tests in this package. Production construction
// requires Cassandra evidence through NewWithStorage.
func New(config Config) (*System, error) {
	return NewWithProvider(config, cloudprovider.NewMemory())
}

func NewWithProvider(config Config, ciphertexts cloudprovider.Provider) (*System, error) {
	checkpoints := NewMemoryCheckpoints()
	return newSystem(config, ciphertexts, checkpoints, func(h *hmf.HMF, m *mva.MVA, p *hpbf.HPBF) (evidencePorts, error) {
		memory, err := newMemoryEvidence(config.NumRegions, config.ShardsPerRegion, h)
		if err != nil {
			return evidencePorts{}, fmt.Errorf("new test system evidence: %w", err)
		}
		return evidencePorts{writes: memory, reads: memory,
			pruner:   phv.CurrentHPBFPruner{Tree: p},
			resolver: phv.CurrentMVAResolver{Tree: m}}, nil
	})
}

func memoryEvidence(s *System) *MemoryEvidence {
	return s.evidence.(*MemoryEvidence)
}

func memoryCheckpoints(s *System) *MemoryCheckpoints {
	return s.checkpoints.(*MemoryCheckpoints)
}

var _ mpm.EvidenceRepository = (*MemoryEvidence)(nil)
var _ phv.Repository = (*MemoryEvidence)(nil)
var _ mpm.CheckpointStore = (*MemoryCheckpoints)(nil)
