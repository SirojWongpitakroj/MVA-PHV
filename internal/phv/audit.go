package phv

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
)

type Auditor struct {
	Roots      TrustedRoots
	Pruner     Pruner
	Resolver   Resolver
	Repository Repository
	Topology   Topology
	Workers    int
}

type groupResult struct {
	nodes []Node
	logs  []EncryptedRecord
	err   error
}

func (a *Auditor) Audit(ctx context.Context, request Request) (Result, error) {
	started := time.Now()
	var out Result
	if a == nil || a.Roots == nil || a.Resolver == nil || a.Repository == nil || request.Query == nil {
		return out, fmt.Errorf("PHV: roots, resolver, repository, and query are required")
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
	workers := a.Workers
	if workers <= 0 {
		workers = 4
	}
	if workers > len(plan.Groups) {
		workers = len(plan.Groups)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
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
				if result.err == nil && len(group.Leaves) > 0 {
					state.Lock()
					calls++
					state.Unlock()
					result.logs, result.err = a.Repository.FetchLogs(ctx, group.Tree, group.Leaves)
					if result.err != nil {
						result.err = fmt.Errorf("%w: fetch logs for %v: %w", ErrRepositoryFailure, group.Tree, result.err)
					}
					if result.err == nil {
						result.err = validateLogs(group.Tree, group.Leaves, result.logs)
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
	var logs []EncryptedRecord
	var firstErr error
	for result := range results {
		if result.err != nil && firstErr == nil {
			firstErr = result.err
		}
		nodes = append(nodes, result.nodes...)
		logs = append(logs, result.logs...)
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

func validateLogs(tree merkle.TreeID, expected []int64, got []EncryptedRecord) error {
	wanted := make(map[int64]struct{}, len(expected))
	for _, leaf := range expected {
		wanted[leaf] = struct{}{}
	}
	seen := make(map[int64]struct{}, len(got))
	for _, log := range got {
		a := log.Address
		if a.RegionID != tree.RegionID || a.ShardID != tree.ShardID || a.SegmentID != tree.SegmentID {
			return fmt.Errorf("%w: log outside Segment", ErrEvidence)
		}
		if _, ok := wanted[a.LeafID]; !ok {
			return fmt.Errorf("%w: unexpected log leaf", ErrEvidence)
		}
		if _, duplicate := seen[a.LeafID]; duplicate {
			return fmt.Errorf("%w: duplicate log leaf", ErrEvidence)
		}
		seen[a.LeafID] = struct{}{}
	}
	if len(seen) != len(wanted) {
		return fmt.Errorf("%w: missing log leaf", ErrEvidence)
	}
	return nil
}
