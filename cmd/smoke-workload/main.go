// Command smoke-workload streams a private, evenly mixed canonical workload.
// It does not assign MPM identities or write to CP, CLS, or the checkpoint store.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/SirojWongpitakroj/mva-phv/internal/canonicalize"
)

type datasetStream struct {
	name   string
	limit  int
	count  int
	stream *canonicalize.EventStream
}

type manifest struct {
	Name           string            `json:"name"`
	Format         string            `json:"format"`
	Selection      string            `json:"selection"`
	RawRoot        string            `json:"raw_root"`
	OutputFile     string            `json:"output_file"`
	OutputBytes    int64             `json:"output_bytes"`
	SHA256         string            `json:"sha256"`
	TotalRecords   int               `json:"total_records"`
	DatasetCounts  map[string]int    `json:"dataset_counts"`
	LabelCounts    map[string]int    `json:"label_counts"`
	SiteCounts     map[string]int    `json:"site_counts"`
	SkippedMissing map[string]uint64 `json:"skipped_missing_observations"`
}

func main() {
	rawRoot := flag.String("raw-root", "", "private datasets directory containing WADI, HAI, and SWAT")
	out := flag.String("out", "", "private smoke workload JSONL path outside the Git repository")
	flag.Parse()
	if *rawRoot == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "both -raw-root and -out are required")
		os.Exit(2)
	}
	result, err := generate(context.Background(), *rawRoot, *out)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("Created %d canonical records (WADI %d, HAI %d, SWAT %d)\nFile: %s\nManifest: %s\nSHA-256: %s\n",
		result.TotalRecords, result.DatasetCounts["WADI"], result.DatasetCounts["HAI"], result.DatasetCounts["SWAT"],
		result.OutputFile, manifestPath(result.OutputFile), result.SHA256)
}

func manifestPath(out string) string {
	ext := filepath.Ext(out)
	return strings.TrimSuffix(out, ext) + "_manifest.json"
}

func absent(path string) error {
	_, err := os.Stat(path)
	if err == nil {
		return fmt.Errorf("smoke workload: refusing to overwrite %s", path)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func generate(ctx context.Context, rawRoot, out string) (result manifest, err error) {
	rawRoot, err = filepath.Abs(rawRoot)
	if err != nil {
		return result, err
	}
	out, err = filepath.Abs(out)
	if err != nil {
		return result, err
	}
	if err = absent(out); err != nil {
		return result, err
	}
	if err = absent(manifestPath(out)); err != nil {
		return result, err
	}
	if err = os.MkdirAll(filepath.Dir(out), 0700); err != nil {
		return result, err
	}

	open := []struct {
		name  string
		limit int
		fn    func(string) (*canonicalize.EventStream, error)
	}{
		{"WADI", 33334, canonicalize.OpenWADI},
		{"HAI", 33333, canonicalize.OpenHAI},
		{"SWAT", 33333, canonicalize.OpenSWAT},
	}
	streams := make([]datasetStream, 0, len(open))
	defer func() {
		for _, source := range streams {
			if closeErr := source.stream.Close(); err == nil && closeErr != nil {
				err = closeErr
			}
		}
	}()
	for _, source := range open {
		stream, openErr := source.fn(filepath.Join(rawRoot, source.name, "raw"))
		if openErr != nil {
			return result, fmt.Errorf("open %s: %w", source.name, openErr)
		}
		streams = append(streams, datasetStream{name: source.name, limit: source.limit, stream: stream})
	}

	temp, err := os.CreateTemp(filepath.Dir(out), ".smoke-*.jsonl")
	if err != nil {
		return result, err
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	digest := sha256.New()
	buffer := bufio.NewWriterSize(io.MultiWriter(temp, digest), 1<<20)
	encoder := json.NewEncoder(buffer)
	result = manifest{Name: "MVA-PHV 100000-log smoke workload", Format: "JSONL canonical records",
		Selection: "Round-robin first canonical observations from each dataset in adapter source-file and process-column order",
		RawRoot:   rawRoot, OutputFile: out, DatasetCounts: map[string]int{}, LabelCounts: map[string]int{},
		SiteCounts: map[string]int{}, SkippedMissing: map[string]uint64{}}
	for result.TotalRecords < 100000 {
		for i := range streams {
			source := &streams[i]
			if source.count == source.limit {
				continue
			}
			record, nextErr := source.stream.Next(ctx)
			if nextErr != nil {
				return result, fmt.Errorf("%s record %d: %w", source.name, source.count+1, nextErr)
			}
			if record.Dataset != source.name || !strings.HasPrefix(record.Site, source.name+":") ||
				record.Device == "" || record.Type == "" || record.Timestamp.IsZero() || record.Value == "" ||
				(record.Label != "normal" && record.Label != "attack") {
				return result, fmt.Errorf("%s record %d: invalid canonical record", source.name, source.count+1)
			}
			if encodeErr := encoder.Encode(record); encodeErr != nil {
				return result, encodeErr
			}
			source.count++
			result.TotalRecords++
			result.DatasetCounts[record.Dataset]++
			result.LabelCounts[record.Label]++
			result.SiteCounts[record.Site]++
		}
	}
	if err = buffer.Flush(); err != nil {
		return result, err
	}
	if err = temp.Sync(); err != nil {
		return result, err
	}
	info, err := temp.Stat()
	if err != nil {
		return result, err
	}
	result.OutputBytes = info.Size()
	result.SHA256 = hex.EncodeToString(digest.Sum(nil))
	for _, source := range streams {
		result.SkippedMissing[source.name] = source.stream.SkippedObservations()
	}
	if err = temp.Close(); err != nil {
		return result, err
	}
	if err = os.Rename(temp.Name(), out); err != nil {
		return result, err
	}
	if err = writeManifest(manifestPath(out), result); err != nil {
		return result, err
	}
	return result, nil
}

func writeManifest(path string, data manifest) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".smoke-manifest-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
