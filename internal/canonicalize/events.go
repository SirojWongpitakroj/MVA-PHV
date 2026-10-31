package canonicalize

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
)

// CanonicalRecord is the dataset-independent plaintext observation. It has no
// MPM identity, placement, encryption, or authentication fields.
type CanonicalRecord struct {
	Dataset   string    `json:"dataset"`
	Site      string    `json:"site"`
	Device    string    `json:"device"`
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Value     string    `json:"value"`
	Label     string    `json:"label"`
}

// DeviceIdentity describes one source-defined Site/Device without reading its
// observation values. Site has the same dataset-qualified form as Next output.
type DeviceIdentity struct {
	Dataset string
	Site    string
	Device  string
	Type    string
}

type processColumn struct {
	index  int
	site   string
	device string
	typ    string
}

type sourceSpec struct {
	path       string
	labelPath  string
	dataset    string
	kind       string
	labelFixed string
}

type sourceRows interface {
	Columns() []processColumn
	Next() (time.Time, string, []string, error)
	Close() error
}

// EventStream reads one source row and emits its process observations in
// original column order. It never builds a full canonical dataset in memory.
type EventStream struct {
	sources []sourceSpec
	current sourceRows
	index   int
	values  []string
	columns []processColumn
	column  int
	ts      time.Time
	label   string
	dataset string
	skipped uint64
	closed  bool
}

func OpenWADI(rawDir string) (*EventStream, error) {
	return openSources([]sourceSpec{
		{path: filepath.Join(rawDir, "WADI_14days_new.csv"), dataset: "WADI", kind: "wadi", labelFixed: "normal"},
		{path: filepath.Join(rawDir, "WADI_attackdataLABLE.csv"), dataset: "WADI", kind: "wadi-attack"},
	})
}

func OpenHAI(rawDir string) (*EventStream, error) {
	root := filepath.Join(rawDir, "hai-23.05")
	var sources []sourceSpec
	for i := 1; i <= 4; i++ {
		sources = append(sources, sourceSpec{path: filepath.Join(root, "train", fmt.Sprintf("hai-train%d.csv", i)), dataset: "HAI", kind: "hai", labelFixed: "normal"})
	}
	for i := 1; i <= 2; i++ {
		sources = append(sources, sourceSpec{path: filepath.Join(root, "test", fmt.Sprintf("hai-test%d.csv", i)), labelPath: filepath.Join(root, "test", fmt.Sprintf("label-test%d.csv", i)), dataset: "HAI", kind: "hai"})
	}
	return openSources(sources)
}

func OpenSWAT(rawDir string) (*EventStream, error) {
	return openSources([]sourceSpec{
		{path: filepath.Join(rawDir, "SWaT_Dataset_Normal_v1.xlsx"), dataset: "SWAT", kind: "swat", labelFixed: "normal"},
		{path: filepath.Join(rawDir, "SWaT_Dataset_Attack_v0.xlsx"), dataset: "SWAT", kind: "swat"},
	})
}

func openSources(sources []sourceSpec) (*EventStream, error) {
	for _, source := range sources {
		if source.path == "" {
			return nil, errors.New("canonicalize: empty source path")
		}
	}
	return &EventStream{sources: sources}, nil
}

// SourceDevices reads only source schemas and returns unique devices in first
// source-column order. It does not emit or materialize observation records.
func (s *EventStream) SourceDevices() ([]DeviceIdentity, error) {
	if s == nil || s.closed {
		return nil, errors.New("canonicalize: stream is closed")
	}
	seen := make(map[string]struct{})
	var devices []DeviceIdentity
	for _, spec := range s.sources {
		var rows sourceRows
		var err error
		if spec.kind == "swat" {
			rows, err = openSWATRows(spec)
		} else {
			rows, err = openCSVRows(spec)
		}
		if err != nil {
			return nil, fmt.Errorf("canonicalize source devices %s: %w", spec.path, err)
		}
		for _, column := range rows.Columns() {
			site := spec.dataset + ":" + column.site
			key := fmt.Sprintf("%d:%s:%s", len(site), site, column.device)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			devices = append(devices, DeviceIdentity{Dataset: spec.dataset, Site: site,
				Device: column.device, Type: column.typ})
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
	}
	return devices, nil
}

func (s *EventStream) openNext() error {
	if s.current != nil {
		if err := s.current.Close(); err != nil {
			return err
		}
		s.current = nil
	}
	if s.index == len(s.sources) {
		return io.EOF
	}
	spec := s.sources[s.index]
	s.index++
	var rows sourceRows
	var err error
	if spec.kind == "swat" {
		rows, err = openSWATRows(spec)
	} else {
		rows, err = openCSVRows(spec)
	}
	if err != nil {
		return fmt.Errorf("canonicalize %s: %w", spec.path, err)
	}
	s.current, s.columns, s.dataset = rows, rows.Columns(), spec.dataset
	s.values, s.column = nil, 0
	return nil
}

// Next returns io.EOF when all configured source files are exhausted.
func (s *EventStream) Next(ctx context.Context) (CanonicalRecord, error) {
	if s == nil || s.closed {
		return CanonicalRecord{}, errors.New("canonicalize: stream is closed")
	}
	for {
		if err := ctx.Err(); err != nil {
			return CanonicalRecord{}, err
		}
		if s.current == nil {
			if err := s.openNext(); err != nil {
				return CanonicalRecord{}, err
			}
		}
		if s.values == nil || s.column == len(s.columns) {
			ts, label, values, err := s.current.Next()
			if errors.Is(err, io.EOF) {
				if err := s.openNext(); err != nil {
					return CanonicalRecord{}, err
				}
				continue
			}
			if err != nil {
				return CanonicalRecord{}, err
			}
			s.ts, s.label, s.values, s.column = ts, label, values, 0
		}
		column := s.columns[s.column]
		s.column++
		if column.index >= len(s.values) {
			return CanonicalRecord{}, fmt.Errorf("canonicalize: missing column %d", column.index)
		}
		value := strings.TrimSpace(s.values[column.index])
		if value == "" || strings.EqualFold(value, "nan") || strings.EqualFold(value, "null") {
			s.skipped++
			continue
		}
		// Source process-stage labels overlap across datasets (for example P1).
		// Keep the source label after the dataset prefix so Site is globally unique.
		return CanonicalRecord{Dataset: s.dataset, Site: s.dataset + ":" + column.site, Device: column.device,
			Type: column.typ, Timestamp: s.ts, Value: value, Label: s.label}, nil
	}
}

func (s *EventStream) SkippedObservations() uint64 { return s.skipped }

func (s *EventStream) Close() error {
	if s == nil || s.closed {
		return nil
	}
	s.closed = true
	if s.current != nil {
		return s.current.Close()
	}
	return nil
}

func parseTag(kind, raw string) (processColumn, bool) {
	raw = strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
	switch kind {
	case "wadi", "wadi-attack":
		return wadiTag(raw)
	case "hai":
		return haiTag(raw)
	case "swat":
		return swatTag(raw)
	default:
		return processColumn{}, false
	}
}
