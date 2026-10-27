package mva

import (
	"fmt"

	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

// IngestRecord updates both working locator views for one bound record.
func (m *MVA) IngestRecord(record PendingRecord) (LocatorUpdate, LocatorUpdate, error) {
	if record.Address.RegionID != record.RegionID {
		return LocatorUpdate{}, LocatorUpdate{}, fmt.Errorf("ingest MVA record: physical Region differs")
	}
	key := attrKey{SiteID: record.SiteID, DevID: record.DeviceID, Type: record.Type, TS: record.TS, ID: record.LogID}
	return m.IngestLog([]merkle.TreeID{{Type: merkle.TreeRegion, RegionID: record.RegionID}}, key, record.Address, record.Locator)
}

// WorkingMetadata identifies the recovery generation and B+ tree order.
func (m *MVA) WorkingMetadata() (uint64, int, error) {
	if m == nil {
		return 0, 0, fmt.Errorf("MVA working metadata: MVA is nil")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.Regions) == 0 || m.Regions[0] == nil || m.Regions[0].IDView == nil {
		return 0, 0, fmt.Errorf("MVA working metadata: no configured views")
	}
	epoch := m.Epoch + 1
	if m.Candidate != nil && m.Candidate.Epoch >= epoch {
		epoch = m.Candidate.Epoch + 1
	}
	return epoch, m.Regions[0].IDView.Order, nil
}

// PrepareCandidate starts from the previous authoritative snapshot and adds
// only the sealed records captured by MPM. Working may contain newer logs.
func (m *MVA) PrepareCandidate(epoch uint64, sealed []PendingRecord) ([32]byte, error) {
	if m == nil {
		return [32]byte{}, fmt.Errorf("prepare MVA candidate: MVA is nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Candidate != nil {
		if m.Candidate.Epoch != epoch {
			return [32]byte{}, fmt.Errorf("prepare MVA candidate: epoch %d is pending", m.Candidate.Epoch)
		}
		return m.Candidate.Root, nil
	}
	if epoch <= m.Epoch {
		return [32]byte{}, fmt.Errorf("prepare MVA candidate: epoch %d is not newer than %d", epoch, m.Epoch)
	}
	if len(m.Regions) == 0 || m.Regions[0] == nil || m.Regions[0].IDView == nil {
		return [32]byte{}, fmt.Errorf("prepare MVA candidate: no configured views")
	}
	order := m.Regions[0].IDView.Order
	copyTree, err := NewMVA(len(m.Regions), order)
	if err != nil {
		return [32]byte{}, err
	}
	copyTree.Epoch = epoch
	if m.Finalized != nil {
		for i, region := range copyTree.Regions {
			previous := m.Finalized.Regions[region.TreeID.RegionID]
			if previous == nil || previous.IDView == nil || previous.AttrView == nil {
				return [32]byte{}, fmt.Errorf("prepare MVA candidate: missing finalized Region %q", region.TreeID.RegionID)
			}
			region.IDView = cloneLocatorTree(previous.IDView)
			region.AttrView = cloneLocatorTree(previous.AttrView)
			region.Root = previous.Root
			if m.Regions[i].TreeID.RegionID != region.TreeID.RegionID {
				return [32]byte{}, fmt.Errorf("prepare MVA candidate: Region order changed")
			}
		}
	}
	for _, record := range sealed {
		if _, _, err := copyTree.IngestRecord(record); err != nil {
			return [32]byte{}, fmt.Errorf("prepare MVA candidate: %w", err)
		}
	}
	root, err := copyTree.Commitment()
	if err != nil {
		return [32]byte{}, err
	}
	m.Candidate = copyTree.Finalized
	return root, nil
}

// CandidateSnapshot returns the prepared immutable snapshot for persistence.
func (m *MVA) CandidateSnapshot(epoch uint64) (*MVASnapshot, error) {
	if m == nil {
		return nil, fmt.Errorf("MVA candidate snapshot: MVA is nil")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.Candidate == nil || m.Candidate.Epoch != epoch {
		return nil, fmt.Errorf("MVA candidate snapshot: no candidate for epoch %d", epoch)
	}
	return m.Candidate, nil
}

// CommitCandidate publishes the previously prepared snapshot after anchoring.
// MPM must be the only caller allowed to promote coordinated components.
func (m *MVA) ValidateCandidate(epoch uint64) error {
	if m == nil {
		return fmt.Errorf("validate MVA candidate: MVA is nil")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.Candidate == nil || m.Candidate.Epoch != epoch {
		return fmt.Errorf("validate MVA candidate: no candidate for epoch %d", epoch)
	}
	return nil
}

func (m *MVA) CommitCandidate(epoch uint64) error {
	if m == nil {
		return fmt.Errorf("commit MVA candidate: MVA is nil")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.Candidate == nil || m.Candidate.Epoch != epoch {
		return fmt.Errorf("commit MVA candidate: no candidate for epoch %d", epoch)
	}
	m.Finalized = m.Candidate
	m.Root = m.Candidate.Root
	m.Levels = cloneHashLevels(m.Candidate.Levels)
	m.Epoch = epoch
	for _, region := range m.Regions {
		region.mu.Lock()
		region.Finalized = m.Candidate.Regions[region.TreeID.RegionID]
		region.mu.Unlock()
	}
	m.Candidate = nil
	return nil
}
