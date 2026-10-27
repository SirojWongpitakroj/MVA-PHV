package phv

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"io"
	"slices"

	"github.com/SirojWongpitakroj/mva-phv/internal/hpbf"
	"github.com/SirojWongpitakroj/mva-phv/internal/merkle"
	"github.com/SirojWongpitakroj/mva-phv/internal/mpm"
	"github.com/SirojWongpitakroj/mva-phv/internal/mva"
)

type filterWire struct {
	M, K  uint64
	Words []uint64
}
type shardWire struct {
	TreeID merkle.TreeID
	Filter filterWire
}
type regionWire struct {
	TreeID merkle.TreeID
	Filter filterWire
	Shards []shardWire
	Levels [][][32]byte
}
type hpbfWire struct {
	TreeID  merkle.TreeID
	Epoch   uint64
	Regions []regionWire
	Levels  [][][32]byte
}
type mvaRegionWire struct {
	RID   string
	Proof mva.MVARegionProof
}
type mvaWire struct {
	Epoch   uint64
	Levels  [][][32]byte
	Regions []mvaRegionWire
}
type proofWire struct {
	Epoch                       uint64
	Topology                    Topology
	Roots                       mpm.Roots
	Query                       mva.LocatorQuery
	Tokens                      [3][]byte
	Selected                    []SelectedRecord
	MVA                         *mvaWire
	HPBF                        *hpbfWire
	PrunedRegions, PrunedShards []merkle.TreeID
	Trees                       []TreePlan
	Nodes                       []Node
	Logs                        []EncryptedRecord
	Root                        [32]byte
}

func wireFilter(bf hpbf.BloomFilter) filterWire {
	m, k, words := bf.Snapshot()
	return filterWire{M: m, K: k, Words: words}
}
func restoreFilter(w filterWire) (hpbf.BloomFilter, error) {
	return hpbf.RestoreBloomFilter(w.M, w.K, w.Words)
}

// proofToWire converts a complete proof to a stable, portable representation.
func proofToWire(p Proof) (proofWire, error) {
	w := proofWire{Epoch: p.Epoch, Topology: p.Topology, Roots: p.Roots, Query: p.Query, Tokens: p.Tokens,
		Selected: p.Selected, PrunedRegions: p.PrunedRegions, PrunedShards: p.PrunedShards,
		Trees: p.Trees, Nodes: p.Nodes, Logs: p.Logs, Root: p.Root}
	if p.MVA != nil {
		w.MVA = &mvaWire{Epoch: p.MVA.Epoch, Levels: p.MVA.Levels}
		ids := make([]string, 0, len(p.MVA.Regions))
		for id := range p.MVA.Regions {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		for _, id := range ids {
			if p.MVA.Regions[id] == nil {
				return proofWire{}, fmt.Errorf("PHV: nil MVA Region proof")
			}
			w.MVA.Regions = append(w.MVA.Regions, mvaRegionWire{RID: id, Proof: *p.MVA.Regions[id]})
		}
	}
	if p.HPBF != nil {
		w.HPBF = &hpbfWire{TreeID: p.HPBF.TreeID, Epoch: p.HPBF.Epoch, Levels: p.HPBF.Levels}
		for _, r := range p.HPBF.Regions {
			rw := regionWire{TreeID: r.TreeID, Filter: wireFilter(r.BloomFilter), Levels: r.Levels}
			for _, s := range r.Shards {
				rw.Shards = append(rw.Shards, shardWire{TreeID: s.TreeID, Filter: wireFilter(s.BloomFilter)})
			}
			w.HPBF.Regions = append(w.HPBF.Regions, rw)
		}
	}
	return w, nil
}

// EncodeProof serializes a complete proof with stable Region ordering and
// explicit Bloom-filter content. No PHV process state is needed to decode it.
func EncodeProof(p Proof) ([]byte, error) {
	w, err := proofToWire(p)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(w); err != nil {
		return nil, fmt.Errorf("PHV: encode proof: %w", err)
	}
	return buf.Bytes(), nil
}

type proofByteCounter struct{ n int64 }

func (c *proofByteCounter) Write(data []byte) (int, error) {
	c.n += int64(len(data))
	return len(data), nil
}

// ProofSize measures the exact serialized package without keeping a second
// full copy of its evidence in memory.
func ProofSize(p Proof) (int64, error) {
	w, err := proofToWire(p)
	if err != nil {
		return 0, err
	}
	var counter proofByteCounter
	if err := gob.NewEncoder(&counter).Encode(w); err != nil {
		return 0, err
	}
	return counter.n, nil
}

// DecodeProof restores the portable proof package. Cryptographic validation
// is performed separately by VerifyAuditProof.
func DecodeProof(data []byte) (Proof, error) {
	var w proofWire
	reader := bytes.NewReader(data)
	decoder := gob.NewDecoder(reader)
	if err := decoder.Decode(&w); err != nil {
		return Proof{}, fmt.Errorf("PHV: decode proof: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return Proof{}, fmt.Errorf("PHV: trailing or malformed proof data")
	}
	p := Proof{Epoch: w.Epoch, Topology: w.Topology, Roots: w.Roots, Query: w.Query, Tokens: w.Tokens,
		Selected: w.Selected, PrunedRegions: w.PrunedRegions, PrunedShards: w.PrunedShards,
		Trees: w.Trees, Nodes: w.Nodes, Logs: w.Logs, Root: w.Root}
	if w.MVA != nil {
		p.MVA = &mva.MVAProof{Epoch: w.MVA.Epoch, Levels: w.MVA.Levels, Regions: make(map[string]*mva.MVARegionProof, len(w.MVA.Regions))}
		for _, r := range w.MVA.Regions {
			if _, duplicate := p.MVA.Regions[r.RID]; duplicate {
				return Proof{}, fmt.Errorf("PHV: duplicate MVA Region proof")
			}
			part := r.Proof
			p.MVA.Regions[r.RID] = &part
		}
	}
	if w.HPBF != nil {
		p.HPBF = &hpbf.HPBFProof{TreeID: w.HPBF.TreeID, Epoch: w.HPBF.Epoch, Levels: w.HPBF.Levels}
		for _, r := range w.HPBF.Regions {
			bf, err := restoreFilter(r.Filter)
			if err != nil {
				return Proof{}, err
			}
			part := hpbf.RegionHPBFProof{TreeID: r.TreeID, BloomFilter: bf, Levels: r.Levels}
			for _, s := range r.Shards {
				bf, err := restoreFilter(s.Filter)
				if err != nil {
					return Proof{}, err
				}
				part.Shards = append(part.Shards, hpbf.ShardHPBFProof{TreeID: s.TreeID, BloomFilter: bf})
			}
			p.HPBF.Regions = append(p.HPBF.Regions, part)
		}
	}
	return p, nil
}
