package cassandra

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
	"github.com/SirojWongpitakroj/mva-phv/internal/mpm"
	"github.com/SirojWongpitakroj/mva-phv/internal/mva"
)

// RegionNode identifies the Region whose HPBF proof node is being written.
type RegionNode struct {
	RegionID string
	Node     EpochNode
}

// CandidateEvidence is the storage-ready authentication evidence produced by
// prepared HMF, MVA, and HPBF adapters. Unchanged HMF nodes and MVA pages are
// omitted; their earlier versions remain valid for this candidate's epoch.
type CandidateEvidence struct {
	HMFNodes          []HierarchyNode
	HMFShards         []ShardState
	HMFRegions        []RegionState
	HMFGlobal         GlobalState
	MVAPages          []PageVersion
	MVAViews          []ViewState
	MVARegions        []MVARegionCommitment
	MVAGlobalNodes    []EpochNode
	HPBFShardFilters  []FilterRecord
	HPBFShards        []HPBFShardCommitment
	HPBFRegionFilters []FilterRecord
	HPBFRegionNodes   []RegionNode
	HPBFRegions       []HPBFRegionRoot
	HPBFGlobalNodes   []EpochNode
}

// CandidateEvidenceSource exports only the prepared, sealed-record candidate.
// It must never read live Working state while producing this bundle.
type CandidateEvidenceSource interface {
	CandidateEvidence(ctx context.Context, candidate mpm.Candidate) (CandidateEvidence, error)
}

// MPMRepository adapts MPM's persistence port to the existing bound CQL Store.
// The caller supplies a Store backed by a Cassandra Client and an evidence
// source backed by staged component candidates. It does not publish checkpoints.
type MPMRepository struct {
	store  *Store
	source CandidateEvidenceSource
}

var _ mpm.EvidenceRepository = (*MPMRepository)(nil)

func NewMPMRepository(store *Store, source CandidateEvidenceSource) (*MPMRepository, error) {
	if store == nil || store.client == nil || source == nil {
		return nil, fmt.Errorf("cassandra MPM repository: store and candidate evidence source are required")
	}
	if _, ok := store.client.(ConditionalClient); !ok {
		return nil, fmt.Errorf("cassandra MPM repository: Client needs conditional LogID writes")
	}
	return &MPMRepository{store: store, source: source}, nil
}

func checkedEpoch(epoch uint64) (int64, error) { return signedEpoch(epoch) }

func checkedCount(value uint64, name string) (int64, error) {
	if value > math.MaxInt64 {
		return 0, fmt.Errorf("cassandra MPM repository: %s exceeds CQL bigint", name)
	}
	return int64(value), nil
}

func pageLink(page *mva.Page) *int64 {
	if page == nil {
		return nil
	}
	id := page.PageID
	return &id
}

func pageVersion(page mva.Page, view string, epoch int64) (PageVersion, error) {
	if page.PageID < 0 || page.RegionID == "" {
		return PageVersion{}, fmt.Errorf("cassandra MPM repository: invalid MVA page address")
	}
	if err := validView(view); err != nil {
		return PageVersion{}, err
	}
	payload := PagePayload{IsLeaf: page.IsLeaf}
	for _, key := range page.Keys {
		if key == nil {
			return PageVersion{}, fmt.Errorf("cassandra MPM repository: nil MVA key")
		}
		encoded, err := key.Serialize()
		if err != nil {
			return PageVersion{}, err
		}
		payload.Keys = append(payload.Keys, encoded)
	}
	if page.IsLeaf {
		for _, value := range page.Values {
			if value == nil {
				return PageVersion{}, fmt.Errorf("cassandra MPM repository: nil MVA value")
			}
			encoded, err := value.Serialize()
			if err != nil {
				return PageVersion{}, err
			}
			payload.Values = append(payload.Values, encoded)
		}
	} else {
		for _, child := range page.Children {
			if child == nil {
				return PageVersion{}, fmt.Errorf("cassandra MPM repository: nil MVA child")
			}
			payload.Children = append(payload.Children, PageChild{PageID: child.PageID, Hash: child.Hash})
		}
	}
	data, err := EncodePagePayload(payload)
	if err != nil {
		return PageVersion{}, err
	}
	row := PageVersion{RegionID: page.RegionID, View: view, PageID: page.PageID, VersionEpoch: epoch,
		IsLeaf: page.IsLeaf, ParentPageID: page.ParentPageID, PrevPageID: pageLink(page.Prev),
		NextPageID: pageLink(page.Next), Hash: page.Hash, Data: data}
	if row.ParentPageID == nil {
		row.ParentPageID = pageLink(page.Parent)
	}
	if _, err := row.DecodePageData(); err != nil {
		return PageVersion{}, err
	}
	return row, nil
}

func workingView(regionID, view string, update mva.LocatorUpdate, epoch int64, order int) (ViewState, error) {
	if order <= 0 || order > math.MaxInt32 || update.Height < 0 || update.Height > math.MaxInt32 {
		return ViewState{}, fmt.Errorf("cassandra MPM repository: invalid MVA working view metadata")
	}
	return ViewState{RegionID: regionID, View: view, Epoch: epoch, RootPageID: update.RootPageID,
		RootHash: update.RootHash, TreeHeight: int32(update.Height), RecordCount: update.RecordCount,
		NextPageID: update.NextPageID, TreeOrder: int32(order)}, nil
}

func (r *MPMRepository) PersistAccepted(ctx context.Context, record mpm.Record, mv mpm.MVAUpdate, hp mpm.HPBFUpdate) error {
	if r == nil || r.store == nil {
		return fmt.Errorf("cassandra MPM repository: nil repository")
	}
	a := record.Address
	if a.RegionID == "" || a.ShardID < 0 || a.SegmentID < 0 || a.LeafID < 0 || record.AcceptedAt.IsZero() ||
		record.Log.LogID == ([16]byte{}) || record.Log.RegionID != a.RegionID ||
		record.Descriptor.RegionID != a.RegionID || record.Log.TS.IsZero() || record.Descriptor.TS.IsZero() ||
		!record.Log.TS.Equal(record.Descriptor.TS) || record.Log.SiteID != record.Descriptor.SiteID ||
		record.Log.DevID != record.Descriptor.DeviceID || record.Log.Type != record.Descriptor.Type {
		return fmt.Errorf("cassandra MPM repository: invalid accepted record")
	}
	me, err := checkedEpoch(mv.WorkingEpoch)
	if err != nil {
		return err
	}
	he, err := checkedEpoch(hp.WorkingEpoch)
	if err != nil {
		return err
	}
	if me != he {
		return fmt.Errorf("cassandra MPM repository: MVA and HPBF working epochs differ")
	}
	if hp.RegionID != a.RegionID || hp.ShardID != a.ShardID {
		return fmt.Errorf("cassandra MPM repository: HPBF update has different Shard")
	}
	bitCount, err := checkedCount(hp.BitCount, "Bloom bit count")
	if err != nil {
		return err
	}
	hashCount, err := checkedCount(hp.HashCount, "Bloom hash count")
	if err != nil {
		return err
	}
	filter := FilterRecord{RegionID: a.RegionID, ShardID: a.ShardID, Epoch: he, BitCount: bitCount,
		HashCount: hashCount, Bits: FilterBits(hp.Words)}
	if err := filter.Validate(); err != nil {
		return err
	}
	views := []struct {
		name   string
		update mva.LocatorUpdate
	}{{"id", mv.IDView}, {"attribute", mv.AttrView}}
	pageRows := make([]PageVersion, 0, len(mv.IDView.Pages)+len(mv.AttrView.Pages))
	viewRows := make([]ViewState, 0, 2)
	for _, v := range views {
		state, err := workingView(a.RegionID, v.name, v.update, me, mv.TreeOrder)
		if err != nil {
			return err
		}
		viewRows = append(viewRows, state)
		for _, page := range v.update.Pages {
			if page.RegionID != a.RegionID {
				return fmt.Errorf("cassandra MPM repository: MVA page has different Region")
			}
			row, err := pageVersion(page, v.name, me)
			if err != nil {
				return err
			}
			pageRows = append(pageRows, row)
		}
	}
	log := LogRecord{SegmentKey: SegmentKey{RegionID: a.RegionID, ShardID: a.ShardID, SegmentID: a.SegmentID},
		LeafID: a.LeafID, LogID: record.Log.LogID, SiteID: record.Descriptor.SiteID,
		DeviceID: record.Descriptor.DeviceID, EventType: record.Descriptor.Type,
		EventTSNS: record.Descriptor.TS.UnixNano(), Ciphertext: record.Log.Ciphertext,
		Nonce: record.Log.Nonce, Tag: record.Log.Tag, AssociatedData: record.Log.AD,
		Digest: record.Log.Digest, LocatorCommitment: record.Locator,
		HMFLeafCommitment: record.HMFLeaf, IngestedAt: record.AcceptedAt}
	// The first accepted leaf fixes OpenedAt. Later leaves read the existing
	// recovery row so that a restart preserves the actual sealing deadline.
	opened := record.AcceptedAt.UnixNano()
	if a.LeafID > 0 {
		active, err := r.store.GetActiveSegment(ctx, a.RegionID, a.ShardID)
		if err != nil {
			return fmt.Errorf("cassandra MPM repository: load active Segment: %w", err)
		}
		if active.SegmentID == nil || *active.SegmentID != a.SegmentID || active.OpenedAtNS == nil {
			return fmt.Errorf("cassandra MPM repository: active Segment recovery row does not match address")
		}
		opened = *active.OpenedAtNS
	}
	if a.LeafID == math.MaxInt64 || a.SegmentID == math.MaxInt64 {
		return fmt.Errorf("cassandra MPM repository: HMF address overflow")
	}
	segID, leafCount, nextID := a.SegmentID, a.LeafID+1, a.SegmentID+1
	active := ActiveSegment{RegionID: a.RegionID, ShardID: a.ShardID, SegmentID: &segID,
		OpenedAtNS: &opened, LeafCount: &leafCount, NextSegmentID: nextID}
	if err := r.store.ReserveLogID(ctx, log.LogID, log.SegmentKey, log.LeafID); err != nil {
		return fmt.Errorf("persist LogID reservation: %w", err)
	}
	if err := r.store.PutLog(ctx, log); err != nil {
		return fmt.Errorf("persist accepted log: %w", err)
	}
	for _, page := range pageRows {
		if err := r.store.PutPage(ctx, page); err != nil {
			return fmt.Errorf("persist MVA page %d: %w", page.PageID, err)
		}
	}
	for _, view := range viewRows {
		if err := r.store.PutWorkingViewState(ctx, view); err != nil {
			return fmt.Errorf("persist MVA working view %s: %w", view.View, err)
		}
	}
	if err := r.store.PutWorkingShardFilter(ctx, filter); err != nil {
		return fmt.Errorf("persist HPBF working filter: %w", err)
	}
	if err := r.store.PutActiveSegment(ctx, active); err != nil {
		return fmt.Errorf("persist HMF active Segment: %w", err)
	}
	return nil
}

func (r *MPMRepository) PersistSealed(ctx context.Context, segment mpm.Segment, nodes []merkle.MerkleNode) error {
	if r == nil || r.store == nil {
		return fmt.Errorf("cassandra MPM repository: nil repository")
	}
	id := segment.ID
	if id.Type != merkle.TreeSegment || id.RegionID == "" || id.ShardID < 0 || id.SegmentID < 0 ||
		segment.LeafCount <= 0 || id.SegmentID == math.MaxInt64 || segment.Height < 0 || segment.Height > math.MaxInt32 ||
		segment.MaxLeaves <= 0 || segment.MaxLeaves > math.MaxInt32 ||
		segment.OpenedAt.IsZero() || segment.SealedAt.IsZero() || segment.SealedAt.Before(segment.OpenedAt) ||
		segment.LeafCount > int64(segment.MaxLeaves) || len(nodes) == 0 {
		return fmt.Errorf("cassandra MPM repository: incomplete sealed Segment evidence")
	}
	key := SegmentKey{RegionID: id.RegionID, ShardID: id.ShardID, SegmentID: id.SegmentID}
	row := SealedSegment{SegmentKey: key, Root: segment.Root, LeafCount: segment.LeafCount,
		TreeHeight: int32(segment.Height), MaxLeaves: int32(segment.MaxLeaves),
		OpenedAtNS: segment.OpenedAt.UnixNano(), SealedAtNS: segment.SealedAt.UnixNano(), PersistedAt: time.Now().UTC()}
	converted := make([]MerkleNodeRecord, len(nodes))
	leaves := make(map[int64]struct{}, len(nodes))
	topFound := false
	for i, node := range nodes {
		if node.Level < 0 || node.Level > math.MaxInt32 || node.Index < 0 {
			return fmt.Errorf("cassandra MPM repository: invalid Segment node %d", i)
		}
		if node.Level == 0 {
			if node.Index >= segment.LeafCount {
				return fmt.Errorf("cassandra MPM repository: Segment leaf index exceeds count")
			}
			leaves[node.Index] = struct{}{}
		}
		if node.Level == segment.Height && node.Index == 0 {
			topFound = true
		}
		converted[i] = MerkleNodeRecord{Level: int32(node.Level), Index: node.Index, Hash: node.Hash}
	}
	if int64(len(leaves)) != segment.LeafCount || !topFound {
		return fmt.Errorf("cassandra MPM repository: incomplete Segment leaf evidence")
	}
	// Metadata is written after all proof nodes; HMF is acknowledged by MPM
	// only after this method returns successfully.
	for _, node := range converted {
		if err := r.store.PutSegmentNode(ctx, key, node); err != nil {
			return fmt.Errorf("persist Segment node: %w", err)
		}
	}
	if err := r.store.PutSealedSegment(ctx, row); err != nil {
		return fmt.Errorf("persist sealed Segment metadata: %w", err)
	}
	active, err := r.store.GetActiveSegment(ctx, id.RegionID, id.ShardID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return fmt.Errorf("read active Segment after seal: %w", err)
	}
	if err == nil && active.SegmentID != nil && *active.SegmentID == id.SegmentID {
		if err := r.store.ClearActiveSegment(ctx, id.RegionID, id.ShardID, id.SegmentID+1); err != nil {
			return fmt.Errorf("clear sealed active Segment: %w", err)
		}
	}
	return nil
}

func validateCandidateEvidence(candidate mpm.Candidate, evidence CandidateEvidence) error {
	e, err := signedEpoch(candidate.Epoch)
	if err != nil {
		return err
	}
	if evidence.HMFGlobal.Epoch != e || evidence.HMFGlobal.Root != candidate.Roots.HMF ||
		evidence.HMFGlobal.Scope != "GLOBAL" || evidence.HMFGlobal.RegionCount <= 0 ||
		len(evidence.MVARegions) == 0 || len(evidence.MVAGlobalNodes) == 0 ||
		len(evidence.HPBFShards) == 0 || len(evidence.HPBFRegions) == 0 ||
		len(evidence.HPBFGlobalNodes) == 0 ||
		int64(len(evidence.MVARegions)) != evidence.HMFGlobal.RegionCount ||
		len(evidence.HPBFRegions) != len(evidence.MVARegions) {
		return fmt.Errorf("cassandra MPM repository: incomplete candidate authentication evidence")
	}
	views := make(map[string]map[string][32]byte)
	for _, v := range evidence.MVAViews {
		if views[v.RegionID] == nil {
			views[v.RegionID] = make(map[string][32]byte)
		}
		if _, duplicate := views[v.RegionID][v.View]; duplicate {
			return fmt.Errorf("cassandra MPM repository: duplicate MVA view state")
		}
		views[v.RegionID][v.View] = v.RootHash
	}
	regionIDs := make(map[string]struct{}, len(evidence.MVARegions))
	for i, region := range evidence.MVARegions {
		if region.RegionIndex != int64(i) || region.RegionID == "" {
			return fmt.Errorf("cassandra MPM repository: noncanonical MVA Region manifest")
		}
		if _, duplicate := regionIDs[region.RegionID]; duplicate {
			return fmt.Errorf("cassandra MPM repository: duplicate MVA Region")
		}
		regionIDs[region.RegionID] = struct{}{}
		if views[region.RegionID]["id"] != region.IDRoot || views[region.RegionID]["attribute"] != region.AttrRoot || len(views[region.RegionID]) != 2 {
			return fmt.Errorf("cassandra MPM repository: MVA view roots do not match Region manifest")
		}
	}
	if len(views) != len(regionIDs) {
		return fmt.Errorf("cassandra MPM repository: extra MVA view state")
	}
	shardRegions := make(map[string]int)
	for _, shard := range evidence.HPBFShards {
		shardRegions[shard.RegionID]++
	}
	filters := make(map[string]struct{})
	for _, filter := range evidence.HPBFRegionFilters {
		filters[filter.RegionID] = struct{}{}
	}
	for i, region := range evidence.HPBFRegions {
		if region.RegionIndex != int64(i) || shardRegions[region.RegionID] == 0 {
			return fmt.Errorf("cassandra MPM repository: incomplete HPBF Region manifest")
		}
		if _, ok := regionIDs[region.RegionID]; !ok {
			return fmt.Errorf("cassandra MPM repository: HPBF Region does not match MVA/HMF")
		}
		if _, ok := filters[region.RegionID]; !ok {
			return fmt.Errorf("cassandra MPM repository: missing HPBF Region filter")
		}
	}
	if len(filters) != len(regionIDs) {
		return fmt.Errorf("cassandra MPM repository: extra HPBF Region filter")
	}
	if len(candidate.Segments) > 0 && (len(evidence.HMFShards) == 0 || len(evidence.HMFNodes) == 0) {
		return fmt.Errorf("cassandra MPM repository: missing changed HMF evidence")
	}
	for _, n := range evidence.HMFNodes {
		if n.VersionEpoch != e {
			return fmt.Errorf("cassandra MPM repository: HMF node epoch mismatch")
		}
	}
	for _, s := range evidence.HMFShards {
		if s.Epoch != e {
			return fmt.Errorf("cassandra MPM repository: HMF Shard epoch mismatch")
		}
	}
	for _, s := range evidence.HMFRegions {
		if s.Epoch != e {
			return fmt.Errorf("cassandra MPM repository: HMF Region epoch mismatch")
		}
	}
	for _, p := range evidence.MVAPages {
		if p.VersionEpoch != e {
			return fmt.Errorf("cassandra MPM repository: MVA page epoch mismatch")
		}
	}
	for _, v := range evidence.MVAViews {
		if v.Epoch != e {
			return fmt.Errorf("cassandra MPM repository: MVA view epoch mismatch")
		}
	}
	for _, v := range evidence.MVARegions {
		if v.Epoch != e {
			return fmt.Errorf("cassandra MPM repository: MVA Region epoch mismatch")
		}
	}
	for _, n := range evidence.MVAGlobalNodes {
		if n.Epoch != e {
			return fmt.Errorf("cassandra MPM repository: MVA node epoch mismatch")
		}
	}
	for _, f := range evidence.HPBFShardFilters {
		if f.Epoch != e {
			return fmt.Errorf("cassandra MPM repository: HPBF filter epoch mismatch")
		}
	}
	for _, s := range evidence.HPBFShards {
		if s.Epoch != e {
			return fmt.Errorf("cassandra MPM repository: HPBF Shard epoch mismatch")
		}
	}
	for _, f := range evidence.HPBFRegionFilters {
		if f.Epoch != e {
			return fmt.Errorf("cassandra MPM repository: HPBF Region filter epoch mismatch")
		}
	}
	for _, n := range evidence.HPBFRegionNodes {
		if n.Node.Epoch != e {
			return fmt.Errorf("cassandra MPM repository: HPBF Region node epoch mismatch")
		}
	}
	for _, r := range evidence.HPBFRegions {
		if r.Epoch != e {
			return fmt.Errorf("cassandra MPM repository: HPBF Region epoch mismatch")
		}
	}
	for _, n := range evidence.HPBFGlobalNodes {
		if n.Epoch != e {
			return fmt.Errorf("cassandra MPM repository: HPBF Global node epoch mismatch")
		}
	}
	return nil
}

// PersistCandidate writes evidence first and the three candidate roots last.
// Partial writes are retryable because all keys are deterministic for an epoch;
// only the separate trusted checkpoint store makes that epoch authoritative.
func (r *MPMRepository) PersistCandidate(ctx context.Context, candidate mpm.Candidate) error {
	if r == nil || r.store == nil || r.source == nil {
		return fmt.Errorf("cassandra MPM repository: incomplete repository")
	}
	evidence, err := r.source.CandidateEvidence(ctx, candidate)
	if err != nil {
		return fmt.Errorf("collect candidate evidence: %w", err)
	}
	if err := validateCandidateEvidence(candidate, evidence); err != nil {
		return err
	}
	for _, n := range evidence.HMFNodes {
		if err := r.store.PutHierarchyNode(ctx, n); err != nil {
			return fmt.Errorf("persist HMF hierarchy node: %w", err)
		}
	}
	for _, s := range evidence.HMFShards {
		if err := r.store.PutShardState(ctx, s); err != nil {
			return fmt.Errorf("persist HMF Shard state: %w", err)
		}
	}
	for _, s := range evidence.HMFRegions {
		if err := r.store.PutRegionState(ctx, s); err != nil {
			return fmt.Errorf("persist HMF Region state: %w", err)
		}
	}
	for _, p := range evidence.MVAPages {
		if err := r.store.PutPage(ctx, p); err != nil {
			return fmt.Errorf("persist candidate MVA page: %w", err)
		}
	}
	for _, v := range evidence.MVAViews {
		if err := r.store.PutViewState(ctx, v); err != nil {
			return fmt.Errorf("persist MVA view state: %w", err)
		}
	}
	for _, v := range evidence.MVARegions {
		if err := r.store.PutMVARegionCommitment(ctx, v); err != nil {
			return fmt.Errorf("persist MVA Region commitment: %w", err)
		}
	}
	for _, n := range evidence.MVAGlobalNodes {
		if err := r.store.PutMVAGlobalNode(ctx, n); err != nil {
			return fmt.Errorf("persist MVA Global node: %w", err)
		}
	}
	for _, f := range evidence.HPBFShardFilters {
		if err := r.store.PutShardFilterVersion(ctx, f); err != nil {
			return fmt.Errorf("persist HPBF Shard filter: %w", err)
		}
	}
	for _, s := range evidence.HPBFShards {
		if err := r.store.PutHPBFShardCommitment(ctx, s); err != nil {
			return fmt.Errorf("persist HPBF Shard commitment: %w", err)
		}
	}
	for _, f := range evidence.HPBFRegionFilters {
		if err := r.store.PutHPBFRegionFilter(ctx, f); err != nil {
			return fmt.Errorf("persist HPBF Region filter: %w", err)
		}
	}
	for _, n := range evidence.HPBFRegionNodes {
		if err := r.store.PutHPBFRegionNode(ctx, n.RegionID, n.Node); err != nil {
			return fmt.Errorf("persist HPBF Region node: %w", err)
		}
	}
	for _, v := range evidence.HPBFRegions {
		if err := r.store.PutHPBFRegionRoot(ctx, v); err != nil {
			return fmt.Errorf("persist HPBF Region root: %w", err)
		}
	}
	for _, n := range evidence.HPBFGlobalNodes {
		if err := r.store.PutHPBFGlobalNode(ctx, n); err != nil {
			return fmt.Errorf("persist HPBF Global node: %w", err)
		}
	}
	if err := r.store.PutGlobalState(ctx, evidence.HMFGlobal); err != nil {
		return fmt.Errorf("persist HMF Global root: %w", err)
	}
	if err := r.store.PutMVARoot(ctx, candidate.Epoch, candidate.Roots.MVA); err != nil {
		return fmt.Errorf("persist MVA root: %w", err)
	}
	if err := r.store.PutHPBFRoot(ctx, candidate.Epoch, candidate.Roots.HPBF); err != nil {
		return fmt.Errorf("persist HPBF root: %w", err)
	}
	return nil
}
