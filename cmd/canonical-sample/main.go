package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/SirojWongpitakroj/mva-phv/internal/canonicalize"
)

func main() {
	dataset := flag.String("dataset", "", "WADI, HAI, or SWAT")
	raw := flag.String("raw", "", "private dataset raw directory")
	out := flag.String("out", "", "private sample JSONL path")
	limit := flag.Int("limit", 100, "canonical events to emit (maximum 100)")
	flag.Parse()
	if *raw == "" || *out == "" || *limit < 1 || *limit > 100 {
		log.Fatal("raw and out paths and a limit of 1..100 are required")
	}
	var stream *canonicalize.EventStream
	var err error
	switch strings.ToUpper(*dataset) {
	case "WADI":
		stream, err = canonicalize.OpenWADI(*raw)
	case "HAI":
		stream, err = canonicalize.OpenHAI(*raw)
	case "SWAT":
		stream, err = canonicalize.OpenSWAT(*raw)
	default:
		log.Fatal("dataset must be WADI, HAI, or SWAT")
	}
	if err != nil {
		log.Fatal(err)
	}
	defer stream.Close()
	file, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()
	count, examples, err := canonicalize.WriteSampleJSONL(context.Background(), stream, file, *limit)
	if err != nil {
		log.Fatal(err)
	}
	for _, record := range examples {
		fmt.Printf("%s %s %s %s %s %s %s\n", record.Dataset, record.Site, record.Device,
			record.Type, record.Timestamp.Format("2006-01-02T15:04:05Z07:00"), record.Value, record.Label)
	}
	if err := file.Sync(); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("emitted=%d skipped_observations=%d sample=%s\n", count, stream.SkippedObservations(), *out)
}
