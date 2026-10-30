package canonicalize

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Set MVA_PHV_DATASETS_DIR to validate private source headers locally. The
// public test suite contains no private dataset excerpts or absolute paths.
func TestPrivateSourceHeaders(t *testing.T) {
	root := os.Getenv("MVA_PHV_DATASETS_DIR")
	if root == "" {
		t.Skip("private datasets not configured")
	}
	cases := []struct {
		spec sourceSpec
		want int
	}{
		{sourceSpec{path: filepath.Join(root, "WADI", "raw", "WADI_14days_new.csv"), kind: "wadi", labelFixed: "normal"}, 124},
		{sourceSpec{path: filepath.Join(root, "WADI", "raw", "WADI_attackdataLABLE.csv"), kind: "wadi-attack"}, 124},
		{sourceSpec{path: filepath.Join(root, "HAI", "raw", "hai-23.05", "train", "hai-train1.csv"), kind: "hai", labelFixed: "normal"}, 79},
		{sourceSpec{path: filepath.Join(root, "HAI", "raw", "hai-23.05", "train", "hai-train2.csv"), kind: "hai", labelFixed: "normal"}, 79},
		{sourceSpec{path: filepath.Join(root, "HAI", "raw", "hai-23.05", "train", "hai-train3.csv"), kind: "hai", labelFixed: "normal"}, 79},
		{sourceSpec{path: filepath.Join(root, "HAI", "raw", "hai-23.05", "train", "hai-train4.csv"), kind: "hai", labelFixed: "normal"}, 79},
		{sourceSpec{path: filepath.Join(root, "HAI", "raw", "hai-23.05", "test", "hai-test1.csv"), labelPath: filepath.Join(root, "HAI", "raw", "hai-23.05", "test", "label-test1.csv"), kind: "hai"}, 79},
		{sourceSpec{path: filepath.Join(root, "HAI", "raw", "hai-23.05", "test", "hai-test2.csv"), labelPath: filepath.Join(root, "HAI", "raw", "hai-23.05", "test", "label-test2.csv"), kind: "hai"}, 79},
		{sourceSpec{path: filepath.Join(root, "SWAT", "raw", "SWaT_Dataset_Normal_v1.xlsx"), kind: "swat", labelFixed: "normal"}, 51},
		{sourceSpec{path: filepath.Join(root, "SWAT", "raw", "SWaT_Dataset_Attack_v0.xlsx"), kind: "swat"}, 51},
	}
	firstColumns := make(map[string][]processColumn)
	sites := make(map[string]map[string]struct{})
	devices := make(map[string]map[string]struct{})
	types := make(map[string]map[string]struct{})
	for _, test := range cases {
		var rows sourceRows
		var err error
		if test.spec.kind == "swat" {
			rows, err = openSWATRows(test.spec)
		} else {
			rows, err = openCSVRows(test.spec)
		}
		if err != nil {
			t.Errorf("%s: %v", filepath.Base(test.spec.path), err)
			continue
		}
		if got := len(rows.Columns()); got != test.want {
			t.Errorf("%s: %d process columns, want %d", filepath.Base(test.spec.path), got, test.want)
		}
		key := test.spec.dataset
		if key == "" {
			key = test.spec.kind
			if key == "wadi-attack" {
				key = "wadi"
			}
		}
		if previous, ok := firstColumns[key]; ok && !reflect.DeepEqual(previous, rows.Columns()) {
			t.Errorf("%s: inconsistent process schema", filepath.Base(test.spec.path))
		} else if !ok {
			firstColumns[key] = append([]processColumn(nil), rows.Columns()...)
		}
		if sites[key] == nil {
			sites[key], devices[key], types[key] = make(map[string]struct{}), make(map[string]struct{}), make(map[string]struct{})
		}
		for _, column := range rows.Columns() {
			sites[key][column.site] = struct{}{}
			devices[key][column.site+":"+column.device] = struct{}{}
			types[key][column.typ] = struct{}{}
		}
		if timestamp, label, _, err := rows.Next(); err != nil || timestamp.IsZero() || (label != "normal" && label != "attack") {
			t.Errorf("%s: first source row is invalid: timestamp=%s label=%q err=%v", filepath.Base(test.spec.path), timestamp, label, err)
		}
		if filepath.Base(test.spec.path) == "hai-test2.csv" {
			// Cross the first minute boundary without emitting canonical events.
			for i := 1; i < 120; i++ {
				if _, _, _, err := rows.Next(); err != nil {
					t.Errorf("HAI test2 label alignment at row %d: %v", i+1, err)
					break
				}
			}
		}
		if err := rows.Close(); err != nil {
			t.Error(err)
		}
	}
	for _, key := range []string{"wadi", "hai", "swat"} {
		t.Logf("%s header cardinality: sites=%d devices=%d types=%d", key, len(sites[key]), len(devices[key]), len(types[key]))
	}
}
