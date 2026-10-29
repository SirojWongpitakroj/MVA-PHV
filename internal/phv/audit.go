package phv

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"
	"uuid"

	"github.com/SirojWongpitakroj/mva-phv/internal/cloudprovider"
	"github.com/SirojWongpitakroj/mva-phv/internal/domain"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

type Auditor struct {
	Roots       TrustedRoots
	Pruner      Pruner
	Resolver    Resolver
	Repository  Repository
	Ciphertexts cloudprovider.Reader
	Topology    Topology
	Workers     int
}

type groupResult struct {
	nodes []Node
	err   error
}

func (a *Auditor) Audit(ctx context.Context, request Request) (Result, error) {
	started := time.Now()
	var out Result
	if a == nil || a.Roots == nil || a.Resolver == nil || a.Repository == nil || a.Ciphertexts == nil || request.Query == nil {
		return out, fmt.Errorf("PHV: roots, resolver, repository, ciphertext provider, and query are required")
	}
	ids, err := a.Topology.orderedRegions()
	if err != nil {
		return out, err
	}
	roots, err := a.Roots.Roots(ctx, request.Epoch)
	if err != nil {
		return out, fmt.Errorf("PHV: finalized roots: %w", err)
	}
	regions := make([]merkle.TreeID, len(ids))
	for i, rid := range ids {
		regions[i] = merkle.TreeID{Type: merkle.TreeRegion, RegionID: rid}
	}
	var bloomProof = out.Proof.HPBF
	var prunedRegions, prunedShards []merkle.TreeID
	var allowedShards map[merkle.TreeID]struct{}
	want, usable, err := pruningTokens(request.Query)
	if err != nil {
		return out, err
	}
	prune := request.UsePruning && usable
	if !prune {
		request.Tokens = [3][]byte{}
	}
	if prune {
		for i := range want {
			if len(request.Tokens[i]) > 0 && !bytes.Equal(want[i], request.Tokens[i]) {
				return out, fmt.Errorf("PHV: HPBF tokens do not match the MVA query")
			}
		}
		request.Tokens = want
		if a.Pruner == nil {
			return out, fmt.Errorf("PHV: requested HPBF pruning without authenticated pruner")
		}
		pruning, pruneErr := a.Pruner.Prune(ctx, request.Epoch, request.Tokens, roots.HPBF)
		regions, bloomProof, err = pruning.Regions, pruning.Proof, pruneErr
		prunedRegions, prunedShards = slices.Clone(pruning.Regions), slices.Clone(pruning.Shards)
		if err != nil {
			return out, fmt.Errorf("PHV: HPBF pruning: %w", err)
		}
		if bloomProof == nil || bloomProof.Epoch != request.Epoch {
			return out, fmt.Errorf("%w: HPBF proof", ErrWrongEpoch)
		}
		allowed := make(map[string]struct{}, len(ids))
		for _, id := range ids {
			allowed[id] = struct{}{}
		}
		seen := make(map[string]struct{})
		for _, region := range regions {
			if region.Type != merkle.TreeRegion {
				return out, fmt.Errorf("PHV: pruner returned a non-Region")
			}
			if _, ok := allowed[region.RegionID]; !ok {
				return out, fmt.Errorf("PHV: pruner returned an unconfigured Region")
			}
			if _, duplicate := seen[region.RegionID]; duplicate {
				return out, fmt.Errorf("PHV: duplicate pruned Region")
			}
			seen[region.RegionID] = struct{}{}
		}
		sort.Slice(regions, func(i, j int) bool { return regions[i].RegionID < regions[j].RegionID })
		allowedShards = make(map[merkle.TreeID]struct{}, len(pruning.Shards))
		for _, shard := range pruning.Shards {
			if shard.Type != merkle.TreeShard || shard.ShardID < 0 || shard.ShardID >= int64(a.Topology.ShardsPerRegion) {
				return out, fmt.Errorf("PHV: pruner returned an invalid Shard")
			}
			if _, ok := seen[shard.RegionID]; !ok {
				return out, fmt.Errorf("PHV: pruner returned a Shard outside candidate Regions")
			}
			if _, duplicate := allowedShards[shard]; duplicate {
				return out, fmt.Errorf("PHV: duplicate pruned Shard")
			}
			allowedShards[shard] = struct{}{}
		}
	}
	resolution, err := a.Resolver.Resolve(ctx, request.Epoch, request.Query, regions, roots.MVA)
	if err != nil {
		return out, fmt.Errorf("PHV: MVA resolution: %w", err)
	}
	if resolution.Epoch != request.Epoch || resolution.Proof == nil || resolution.Proof.Epoch != request.Epoch {
		return out, fmt.Errorf("%w: MVA proof", ErrWrongEpoch)
	}
	allowed := make(map[string]struct{}, len(regions))
	for _, region := range regions {
		allowed[region.RegionID] = struct{}{}
	}
	for _, record := range resolution.Records {
		if _, ok := allowed[record.Address.RegionID]; !ok {
			return out, fmt.Errorf("PHV: MVA returned a pruned Region")
		}
		if prune {
			shard := merkle.TreeID{Type: merkle.TreeShard, RegionID: record.Address.RegionID, ShardID: record.Address.ShardID}
			if _, ok := allowedShards[shard]; !ok {
				return out, fmt.Errorf("PHV: MVA returned a pruned Shard")
			}
		}
	}
	canonicalRecords := slices.Clone(resolution.Records)
	sort.Slice(canonicalRecords, func(i, j int) bool { return lessRecord(canonicalRecords[i], canonicalRecords[j]) })
	out.Proof = Proof{Epoch: request.Epoch, Topology: Topology{RegionIDs: slices.Clone(ids), ShardsPerRegion: a.Topology.ShardsPerRegion},
		Roots: roots, Query: request.Query, Tokens: request.Tokens, Selected: canonicalRecords,
		MVA: resolution.Proof, HPBF: bloomProof, PrunedRegions: prunedRegions, PrunedShards: prunedShards, Root: roots.HMF}
	if len(resolution.Records) == 0 {
		out.Verified = true // Resolver authenticated the empty/completeness proof.
		out.Metrics.ProofBytes, err = ProofSize(out.Proof)
		if err != nil {
			return out, err
		}
		out.Metrics.TotalTime = time.Since(started)
		return out, nil
	}
	planStart := time.Now()
	plan, err := BuildPlan(ctx, a.Repository, request.Epoch, a.Topology, resolution.Records)
	if err != nil {
		return out, err
	}
	out.Metrics.PlanningTime = time.Since(planStart)
	out.Metrics.SelectedRecords = len(plan.Selected)
	out.Metrics.NaiveNodes, out.Metrics.UniqueNodes = plan.NaiveNodes, plan.UniqueNodes
	out.Metrics.NaiveNodeBytes = int64(plan.NaiveNodes) * 32
	out.Metrics.FrontierNodeBytes = int64(plan.UniqueNodes) * 32
	out.Metrics.NaiveHashOperations = plan.NaiveNodes + 4*len(plan.Selected)
	out.Metrics.DeduplicatedNodes = plan.NaiveNodes - plan.UniqueNodes
	if plan.NaiveNodes > 0 {
		out.Metrics.DeduplicationRatio = float64(out.Metrics.DeduplicatedNodes) / float64(plan.NaiveNodes)
	}
	out.Metrics.SegmentGroups = plan.SegmentGroups
	out.Metrics.RetrievalGroups = len(plan.Groups)
	if _, ok := a.Repository.(PartitionMapper); ok {
		out.Metrics.StoragePartitions = len(plan.Groups)
	}
	for _, group := range plan.Groups {
		switch group.Tree.Type {
		case merkle.TreeShard:
			out.Metrics.ShardGroups++
		case merkle.TreeRegion:
			out.Metrics.RegionGroups++
		case merkle.TreeGlobal:
			out.Metrics.GlobalGroups++
		}
	}
	out.Proof.Trees = plan.Trees
	retrieveStart := time.Now()
	nodes, logs, calls, maxActive, err := a.retrieve(ctx, plan)
	out.Metrics.RetrievalTime = time.Since(retrieveStart)
	out.Metrics.RepositoryCalls, out.Metrics.MaxConcurrent = calls, maxActive
	if err != nil {
		out.Failures = append(out.Failures, Failure{Tree: merkle.TreeID{Type: merkle.TreeGlobal}, Unresolved: true, Reason: err.Error()})
		out.Unresolved = true
		out.LocalizationError = ErrLocalizationUnresolved
		return out, err
	}
	assembleStart := time.Now()
	out.Proof.Nodes, out.Proof.Logs = nodes, logs
	for _, log := range logs {
		out.Metrics.EvidenceBytes += int64(len(log.Ciphertext) + len(log.Nonce) + len(log.Tag) + len(log.AD))
	}
	out.Metrics.EvidenceBytes += int64(32 * len(nodes))
	out.Metrics.ProofBytes, err = ProofSize(out.Proof)
	if err != nil {
		return out, err
	}
	out.Metrics.AssemblyTime = time.Since(assembleStart)
	verifyStart := time.Now()
	verification, err := VerifyHMF(out.Proof, roots.HMF)
	out.Metrics.VerificationTime = time.Since(verifyStart)
	out.Metrics.HashOperations = verification.HashOperations
	if err != nil {
		return out, err
	}
	out.Verified = verification.Valid
	out.Failures = verification.Issues
	if !verification.Valid {
		if verification.GlobalRoot != roots.HMF {
			out.IntegrityError = ErrHMFRootMismatch
		} else {
			out.IntegrityError = ErrRecordInconsistency
		}
	}
	if verification.GlobalRoot != roots.HMF {
		localizeStart := time.Now()
		local := Localize(ctx, a.Repository, out.Proof, roots.HMF, verification)
		out.Metrics.LocalizationTime = time.Since(localizeStart)
		out.Failures = append(out.Failures, local.Failures...)
		out.Metrics.LocalizationBranches = local.Examined
		out.Metrics.LocalizationExpanded = local.Expanded
		out.Metrics.PrunedBranches = local.Pruned
		for _, failure := range local.Failures {
			if failure.Unresolved {
				out.Unresolved = true
				out.LocalizationError = ErrLocalizationUnresolved
				break
			}
		}
	}
	out.Metrics.TotalTime = time.Since(started)
	return out, nil
}

func (a *Auditor) retrieve(ctx context.Context, plan Plan) ([]Node, []EncryptedRecord, int, int, error) {
	// CP batches and CLS frontier groups are independent after MVA resolution.
	type cpResult struct {
		logs  []EncryptedRecord
		calls int
		err   error
	}
	cp := make(chan cpResult, 1)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		logs, calls, err := a.fetchCiphertexts(ctx, plan.Selected)
		if err != nil {
			cancel()
		}
		cp <- cpResult{logs, calls, err}
	}()
	workers := a.Workers
	if workers <= 0 {
		workers = 4
	}
	if workers > len(plan.Groups) {
		workers = len(plan.Groups)
	}
	jobs := make(chan RetrievalGroup)
	results := make(chan groupResult, len(plan.Groups))
	var wg sync.WaitGroup
	var state sync.Mutex
	calls, active, maxActive := 0, 0, 0
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for group := range jobs {
				state.Lock()
				active++
				if active > maxActive {
					maxActive = active
				}
				state.Unlock()
				result := groupResult{}
				if len(group.Positions) > 0 {
					state.Lock()
					calls++
					state.Unlock()
					result.nodes, result.err = a.Repository.FetchNodes(ctx, plan.Epoch, group.Tree, group.Positions)
					if result.err != nil {
						result.err = fmt.Errorf("%w: fetch nodes for %v: %w", ErrRepositoryFailure, group.Tree, result.err)
					}
					if result.err == nil {
						result.err = validateNodes(plan.Epoch, group.Positions, result.nodes)
					}
				}
				if result.err != nil {
					cancel()
				}
				state.Lock()
				active--
				state.Unlock()
				results <- result
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, group := range plan.Groups {
			select {
			case jobs <- group:
			case <-ctx.Done():
				return
			}
		}
	}()
	wg.Wait()
	close(results)
	var nodes []Node
	var firstErr error
	for result := range results {
		if result.err != nil && firstErr == nil {
			firstErr = result.err
		}
		nodes = append(nodes, result.nodes...)
	}
	cpDone := <-cp
	calls += cpDone.calls
	if firstErr == nil {
		firstErr = cpDone.err
	}
	if firstErr != nil {
		return nil, nil, calls, maxActive, firstErr
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, calls, maxActive, err
	}
	sort.Slice(nodes, func(i, j int) bool {
		a, b := nodes[i].Key, nodes[j].Key
		if a.Tree != b.Tree {
			return lessTree(a.Tree, b.Tree)
		}
		if a.Level != b.Level {
			return a.Level < b.Level
		}
		return a.Index < b.Index
	})
	logs := cpDone.logs
	sort.Slice(logs, func(i, j int) bool {
		a, b := logs[i].Address, logs[j].Address
		if a.RegionID != b.RegionID {
			return a.RegionID < b.RegionID
		}
		if a.ShardID != b.ShardID {
			return a.ShardID < b.ShardID
		}
		if a.SegmentID != b.SegmentID {
			return a.SegmentID < b.SegmentID
		}
		return a.LeafID < b.LeafID
	})
	return nodes, logs, calls, maxActive, nil
}

// fetchCiphertexts batches exact MVA-authenticated LogIDs. The external CP
// receives a logical deployment region and LogIDs, never HMF positions.
func (a *Auditor) fetchCiphertexts(ctx context.Context, selected []SelectedRecord) ([]EncryptedRecord, int, error) {
	const batchSize = 128
	type job struct {
		region  string
		records []SelectedRecord
	}
	byRegion := make(map[string][]SelectedRecord)
	seen := make(map[uuid.UUID]struct{}, len(selected))
	for _, record := range selected {
		if record.LogID == (uuid.UUID{}) || record.Descriptor.RegionID != record.Address.RegionID {
			return nil, 0, fmt.Errorf("%w: invalid MVA selected record", ErrEvidence)
		}
		if _, duplicate := seen[record.LogID]; duplicate {
			return nil, 0, fmt.Errorf("%w: selected LogID", ErrDuplicateEvidence)
		}
		seen[record.LogID] = struct{}{}
		byRegion[record.Address.RegionID] = append(byRegion[record.Address.RegionID], record)
	}
	regions := make([]string, 0, len(byRegion))
	for region := range byRegion {
		regions = append(regions, region)
	}
	sort.Strings(regions)
	var jobs []job
	for _, region := range regions {
		records := byRegion[region]
		for i := 0; i < len(records); i += batchSize {
			end := min(i+batchSize, len(records))
			jobs = append(jobs, job{region, records[i:end]})
		}
	}
	workers := a.Workers
	if workers <= 0 {
		workers = 4
	}
	workers = min(workers, len(jobs))
	type response struct {
		records []EncryptedRecord
		err     error
	}
	queue := make(chan job)
	results := make(chan response, len(jobs))
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range queue {
				ids := make([]uuid.UUID, len(item.records))
				want := make(map[uuid.UUID]SelectedRecord, len(ids))
				for i, record := range item.records {
					ids[i] = record.LogID
					want[record.LogID] = record
				}
				values, err := a.Ciphertexts.GetCiphertexts(ctx, item.region, ids)
				if err != nil {
					results <- response{err: fmt.Errorf("%w: CP batch: %w", ErrRepositoryFailure, err)}
					cancel()
					continue
				}
				got := make(map[uuid.UUID]struct{}, len(values))
				out := make([]EncryptedRecord, 0, len(values))
				for _, value := range values {
					record, ok := want[value.LogID]
					if !ok {
						err = fmt.Errorf("%w: CP LogID %s", ErrUnexpectedEvidence, value.LogID)
						break
					}
					if _, duplicate := got[value.LogID]; duplicate {
						err = fmt.Errorf("%w: CP LogID %s", ErrDuplicateEvidence, value.LogID)
						break
					}
					if check := cloudprovider.ValidateCiphertext(value); check != nil {
						err = fmt.Errorf("%w: %w", ErrEvidence, check)
						break
					}
					got[value.LogID] = struct{}{}
					content := make([]byte, 0, len(value.Nonce)+len(value.Ciphertext)+len(value.Tag))
					content = append(content, value.Nonce...)
					content = append(content, value.Ciphertext...)
					content = append(content, value.Tag...)
					digest := sha256.Sum256(content)
					encoded, e := domain.Serialize([]byte("LOG"), value.LogID, record.Locator[:], digest[:])
					if e != nil {
						err = e
						break
					}
					out = append(out, EncryptedRecord{SelectedRecord: record, Ciphertext: slices.Clone(value.Ciphertext), Nonce: slices.Clone(value.Nonce), Tag: slices.Clone(value.Tag), AD: slices.Clone(value.AD), Version: value.Version, Digest: digest, HMFLeaf: sha256.Sum256(encoded)})
				}
				if err == nil && len(got) != len(want) {
					err = fmt.Errorf("%w: CP batch missing LogID", ErrMissingEvidence)
				}
				if err != nil {
					cancel()
				}
				results <- response{records: out, err: err}
			}
		}()
	}
	go func() {
		defer close(queue)
		for _, item := range jobs {
			select {
			case queue <- item:
			case <-ctx.Done():
				return
			}
		}
	}()
	wg.Wait()
	close(results)
	var out []EncryptedRecord
	var firstErr error
	for result := range results {
		if firstErr == nil && result.err != nil {
			firstErr = result.err
		}
		out = append(out, result.records...)
	}
	if firstErr != nil {
		return nil, len(jobs), firstErr
	}
	if err := ctx.Err(); err != nil {
		return nil, len(jobs), err
	}
	return out, len(jobs), nil
}

func validateNodes(epoch uint64, expected []NodeKey, got []Node) error {
	wanted := make(map[NodeKey]struct{}, len(expected))
	for _, key := range expected {
		wanted[key] = struct{}{}
	}
	seen := make(map[NodeKey]struct{}, len(got))
	for _, node := range got {
		if _, ok := wanted[node.Key]; !ok {
			return fmt.Errorf("%w: node %v", ErrUnexpectedEvidence, node.Key)
		}
		if _, duplicate := seen[node.Key]; duplicate {
			return fmt.Errorf("%w: node %v", ErrDuplicateEvidence, node.Key)
		}
		if node.Key.Tree.Type != merkle.TreeSegment && node.VersionEpoch > epoch {
			return fmt.Errorf("%w: future node", ErrWrongEpoch)
		}
		seen[node.Key] = struct{}{}
	}
	if len(seen) != len(wanted) {
		return fmt.Errorf("%w: requested nodes", ErrMissingEvidence)
	}
	return nil
}
