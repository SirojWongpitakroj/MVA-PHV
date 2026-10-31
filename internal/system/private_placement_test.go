package system

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/SirojWongpitakroj/mva-phv/internal/canonicalize"
)

// This optional local test reads source headers for Site/Device identities.
// It never materializes canonical files or writes to a database.
func TestPrivateDatasetPlacementFourRegionsSixteenShards(t *testing.T) {
	root := os.Getenv("MVA_PHV_DATASETS_DIR")
	if root == "" {
		t.Skip("private datasets not configured")
	}
	cases := []struct {
		name string
		want int
		open func(string) (*canonicalize.EventStream, error)
	}{
		{"WADI", 102, canonicalize.OpenWADI},
		{"HAI", 55, canonicalize.OpenHAI},
		{"SWAT", 51, canonicalize.OpenSWAT},
	}
	config := testConfig()
	config.NumRegions, config.ShardsPerRegion = 4, 16
	config.MaxSegmentSize = 1024
	system, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	occupancy := make(map[string]map[int64]struct{})
	regionDevices := make(map[string]int)
	siteRegions := make(map[string]string)
	total := 0
	for _, tc := range cases {
		stream, err := tc.open(filepath.Join(root, tc.name, "raw"))
		if err != nil {
			t.Fatal(err)
		}
		devices, err := stream.SourceDevices()
		if err != nil {
			stream.Close()
			t.Fatal(err)
		}
		if len(devices) != tc.want {
			stream.Close()
			t.Fatalf("%s: header defines %d Site/Device keys, want %d", tc.name, len(devices), tc.want)
		}
		for i, device := range devices {
			// This tests placement for each source-defined device. It does not
			// materialize observations or write dataset output.
			ts := time.Unix(int64(i+1), 0).UTC()
			input := canonicalize.CanonicalRecord{Dataset: device.Dataset, Site: device.Site,
				Device: device.Device, Type: device.Type, Timestamp: ts,
				Value: "placement-probe", Label: "normal"}
			receipt, err := system.IngestCanonical(ctx, input, ts)
			if err != nil {
				stream.Close()
				t.Fatalf("%s %s/%s: %v", tc.name, device.Site, device.Device, err)
			}
			if occupancy[receipt.Address.RegionID] == nil {
				occupancy[receipt.Address.RegionID] = make(map[int64]struct{})
			}
			if previous, exists := siteRegions[device.Site]; exists && previous != receipt.Address.RegionID {
				stream.Close()
				t.Fatalf("Site %s moved from Region %s to %s", device.Site, previous, receipt.Address.RegionID)
			}
			siteRegions[device.Site] = receipt.Address.RegionID
			regionDevices[receipt.Address.RegionID]++
			occupancy[receipt.Address.RegionID][receipt.Address.ShardID] = struct{}{}
			total++
		}
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: placed %d unique Site/Device keys", tc.name, len(devices))
	}
	if len(occupancy) != 4 {
		t.Fatalf("used %d of 4 Regions", len(occupancy))
	}
	regionSites := make(map[string]int)
	for _, region := range siteRegions {
		regionSites[region]++
	}
	for region := 0; region < 4; region++ {
		id := fmt.Sprint(region)
		if len(occupancy[id]) != 16 {
			t.Errorf("Region %s uses %d of 16 Shards", id, len(occupancy[id]))
		}
		t.Logf("Region %s: %d Sites, %d devices, %d/16 Shards occupied",
			id, regionSites[id], regionDevices[id], len(occupancy[id]))
	}
	t.Logf("total placed sites: %d; devices: %d", len(siteRegions), total)
}
