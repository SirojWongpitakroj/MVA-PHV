package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/SirojWongpitakroj/mva-phv/internal/system"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	regions := flag.Int("regions", 1, "number of regions")
	shards := flag.Int("shards-per-region", 1, "shards in each region")
	segmentSize := flag.Int("max-segment-size", 1024, "maximum leaves per segment")
	sealInterval := flag.Duration("seal-interval", time.Minute, "maximum age of an active segment")
	mvaOrder := flag.Int("mva-order", 32, "MVA tree order")
	filterItems := flag.Int("filter-items", 10000, "expected Bloom filter items")
	falsePositive := flag.Float64("false-positive", 0.01, "Bloom filter false-positive probability")
	auditWorkers := flag.Int("audit-workers", 4, "maximum concurrent audit retrievals")
	flag.Parse()

	key, err := hex.DecodeString(os.Getenv("MVA_PHV_ENCRYPTION_KEY_HEX"))
	if err != nil || len(key) != 32 {
		return fmt.Errorf("MVA_PHV_ENCRYPTION_KEY_HEX must contain a 32-byte key encoded as 64 hex characters")
	}

	_, err = system.New(system.Config{
		NumRegions:      *regions,
		ShardsPerRegion: *shards,
		MaxSegmentSize:  *segmentSize,
		SealInterval:    *sealInterval,
		MVAOrder:        *mvaOrder,
		FilterItems:     *filterItems,
		FalsePositive:   *falsePositive,
		EncryptionKey:   key,
		AuditWorkers:    *auditWorkers,
	})
	if err != nil {
		return fmt.Errorf("initialize MVA-PHV: %w", err)
	}
	fmt.Println("MVA-PHV initialized (in-memory mode)")
	return nil
}
