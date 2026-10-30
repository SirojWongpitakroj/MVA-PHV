package canonicalize

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDatasetTags(t *testing.T) {
	cases := []struct {
		kind, source, site, device, typ string
	}{
		{"wadi", "1_FIT_001_PV", "P1", "FIT_001", "FIT_PV"},
		{"wadi", "2_FIC_101_CO", "P2", "FIC_101", "FIC_CO"},
		{"wadi", "2_FIC_101_SP", "P2", "FIC_101", "FIC_SP"},
		{"wadi", "2A_AIT_001_PV", "P2A", "AIT_001", "AIT_PV"},
		{"wadi", "2B_AIT_001_PV", "P2B", "AIT_001", "AIT_PV"},
		{"wadi", "3_P_001_STATUS", "P3", "P_001", "P_STATUS"},
		{"hai", "P1_FT01", "P1", "FT01", "FT"},
		{"hai", "P1_FT01Z", "P1", "FT01", "FT_Z"},
		{"hai", "P3_LIT01", "P3", "LIT01", "LIT"},
		{"hai", "P1_PP04SP", "P1", "PP04", "PP_SP"},
		{"swat", "FIT101", "P1", "FIT101", "FIT"},
		{"swat", "AIT202", "P2", "AIT202", "AIT"},
		{"swat", "P601", "P6", "P601", "P"},
	}
	for _, test := range cases {
		got, ok := parseTag(test.kind, test.source)
		if !ok || got.site != test.site || got.device != test.device || got.typ != test.typ {
			t.Errorf("%s %s: %+v, %v", test.kind, test.source, got, ok)
		}
	}
	for _, test := range []struct{ kind, name string }{
		{"wadi", "Row"}, {"wadi", "LEAK_DIFF_PRESSURE"},
		{"hai", "timestamp"}, {"hai", "x1001_05_SETPOINT_OUT"},
		{"swat", "Normal/Attack"}, {"swat", "Timestamp"},
	} {
		if _, ok := parseTag(test.kind, test.name); ok {
			t.Errorf("metadata %s/%s became an event", test.kind, test.name)
		}
	}
	if (CanonicalRecord{Dataset: "WADI", Site: "P1"}) == (CanonicalRecord{Dataset: "HAI", Site: "P1"}) {
		t.Fatal("sites from different datasets merged")
	}
}

func TestTimestampAndLabels(t *testing.T) {
	var clock wadiClock
	for _, test := range []struct{ date, source, want string }{
		{"9/25/2017", "59:59.0", "2017-09-25T00:59:59Z"},
		{"9/25/2017", "00:00.0", "2017-09-25T01:00:00Z"},
		{"9/26/2017", "00:00.0", "2017-09-26T00:00:00Z"},
	} {
		got, err := clock.parse(test.date, test.source)
		if err != nil || got.Format(time.RFC3339) != test.want {
			t.Fatalf("WADI time %q: %v, %v", test.source, got, err)
		}
	}
	for _, raw := range []string{"2022-08-04 18:00:01", "22/12/2015 4:00:00 PM"} {
		if ts, err := parseTimestamp(raw); err != nil || ts.Location() != time.UTC {
			t.Fatalf("timestamp %q: %v, %v", raw, ts, err)
		}
	}
	for _, test := range []struct{ kind, source, want string }{
		{"wadi-attack", "1", "normal"}, {"wadi-attack", "-1", "attack"},
		{"hai", "0", "normal"}, {"hai", "1", "attack"},
		{"swat", "Normal", "normal"}, {"swat", " Attack ", "attack"},
	} {
		got, err := normalizeLabel(test.kind, test.source)
		if err != nil || got != test.want {
			t.Fatalf("label %q: %q, %v", test.source, got, err)
		}
	}
	if _, err := normalizeLabel("hai", "unknown"); err == nil {
		t.Fatal("unknown label accepted")
	}
}

func TestWADIInitialHourFromDateBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "normal.csv")
	data := "Row,Date,Time,1_FIT_001_PV\n1,9/25/2017,58:59.0,1\n2,9/25/2017,59:59.0,2\n3,9/26/2017,00:00.0,3\n"
	if err := os.WriteFile(path, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := openCSVRows(sourceSpec{path: path, kind: "wadi", labelFixed: "normal"})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for _, want := range []string{"2017-09-25T23:58:59Z", "2017-09-25T23:59:59Z", "2017-09-26T00:00:00Z"} {
		got, _, _, err := r.Next()
		if err != nil || got.Format(time.RFC3339) != want {
			t.Fatalf("WADI boundary got %s, want %s: %v", got, want, err)
		}
	}
}

func TestWADIStreamingOrderMissingAndSampleCap(t *testing.T) {
	dir := t.TempDir()
	var data strings.Builder
	data.WriteString("Row,Date,Time,1_FIT_001_PV,2_FIC_101_CO,2_FIC_101_SP,LEAK_DIFF_PRESSURE\n")
	for i := 0; i < 80; i++ {
		if i == 0 {
			data.WriteString("1,9/25/2017,00:00.0,0.240392,,1,999\n")
		} else {
			fmt.Fprintf(&data, "%d,9/25/2017,00:%02d.0,2,3,4,999\n", i+1, i%60)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "WADI_14days_new.csv"), []byte(data.String()), 0600); err != nil {
		t.Fatal(err)
	}
	open := func() *EventStream {
		stream, err := OpenWADI(dir)
		if err != nil {
			t.Fatal(err)
		}
		return stream
	}
	first := open()
	defer first.Close()
	if _, _, err := WriteSampleJSONL(context.Background(), first, io.Discard, 101); err == nil {
		t.Fatal("sample limit above 100 accepted")
	}
	var output bytes.Buffer
	count, examples, err := WriteSampleJSONL(context.Background(), first, &output, 100)
	if err != nil || count != 100 || len(examples) != 3 || first.SkippedObservations() != 1 {
		t.Fatalf("sample: count=%d skipped=%d examples=%+v err=%v", count, first.SkippedObservations(), examples, err)
	}
	if examples[0].Site != "WADI:P1" || examples[0].Device != "FIT_001" || examples[0].Value != "0.240392" ||
		examples[1].Device != "FIC_101" || examples[1].Type != "FIC_SP" ||
		examples[2].Device != "FIT_001" || strings.Contains(output.String(), "999") {
		t.Fatalf("wrong order, device grouping, or metadata exclusion: %+v", examples)
	}
	second := open()
	defer second.Close()
	var repeated bytes.Buffer
	if _, _, err := WriteSampleJSONL(context.Background(), second, &repeated, 100); err != nil || repeated.String() != output.String() {
		t.Fatalf("non-deterministic output: %v", err)
	}
}

func TestCSVAttackLabelAndMalformedRows(t *testing.T) {
	dir := t.TempDir()
	wadi := filepath.Join(dir, "attack.csv")
	content := "0,1,2,3,4\nRow ,Date ,Time,1_FIT_001_PV,\"Attack LABLE (1:No Attack, -1:Attack)\"\n" +
		"1,10/9/17,00:00.0,5,-1\n"
	if err := os.WriteFile(wadi, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	r, err := openCSVRows(sourceSpec{path: wadi, kind: "wadi-attack"})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	_, label, row, err := r.Next()
	if err != nil || label != "attack" || row[3] != "5" {
		t.Fatalf("WADI attack row: %q %+v %v", label, row, err)
	}
	hai := filepath.Join(dir, "hai.csv")
	labels := filepath.Join(dir, "label.csv")
	_ = os.WriteFile(hai, []byte("timestamp,P1_FT01\n2022-08-04 18:00:01,1\n"), 0600)
	_ = os.WriteFile(labels, []byte("timestamp,label\n2022-08-04 18:00:02,1\n"), 0600)
	h, err := openCSVRows(sourceSpec{path: hai, labelPath: labels, kind: "hai"})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if _, _, _, err := h.Next(); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("misaligned HAI label accepted: %v", err)
	}
	_ = os.WriteFile(hai, []byte("timestamp,P1_FT01\n2022-08-04 18:00:01,1,extra\n"), 0600)
	malformed, err := openCSVRows(sourceSpec{path: hai, kind: "hai", labelFixed: "normal"})
	if err != nil {
		t.Fatal(err)
	}
	defer malformed.Close()
	if _, _, _, err := malformed.Next(); err == nil {
		t.Fatal("malformed CSV field count accepted")
	}
}

func TestWADISourceOrderAndLabels(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "WADI_14days_new.csv"),
		[]byte("Row,Date,Time,1_FIT_001_PV\n1,9/25/2017,00:00.0,2\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "WADI_attackdataLABLE.csv"),
		[]byte("0,1,2,3,4\nRow,Date,Time,1_FIT_001_PV,\"Attack LABLE (1:No Attack, -1:Attack)\"\n1,10/9/17,00:00.0,3,-1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	stream, err := OpenWADI(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	first, err := stream.Next(context.Background())
	if err != nil || first.Label != "normal" || first.Value != "2" {
		t.Fatalf("normal source: %+v, %v", first, err)
	}
	second, err := stream.Next(context.Background())
	if err != nil || second.Label != "attack" || second.Value != "3" || !second.Timestamp.After(first.Timestamp) {
		t.Fatalf("attack source: %+v, %v", second, err)
	}
	if _, err := stream.Next(context.Background()); err != io.EOF {
		t.Fatalf("expected end of two sources, got %v", err)
	}
}

func TestHAITestLabelsAligned(t *testing.T) {
	dir := t.TempDir()
	measurements := filepath.Join(dir, "measurements.csv")
	labels := filepath.Join(dir, "labels.csv")
	_ = os.WriteFile(measurements, []byte("timestamp,P1_FT01\n2022-08-04 18:00:01,1.2\n"), 0600)
	_ = os.WriteFile(labels, []byte("timestamp,label\n2022-08-04 18:00:01,1\n"), 0600)
	r, err := openCSVRows(sourceSpec{path: measurements, labelPath: labels, kind: "hai"})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	_, label, row, err := r.Next()
	if err != nil || label != "attack" || row[1] != "1.2" {
		t.Fatalf("HAI attack label alignment: %q, %+v, %v", label, row, err)
	}
	_ = os.WriteFile(labels, []byte("timestamp,label\n2022-08-04 18:00,1\n"), 0600)
	coarse, err := openCSVRows(sourceSpec{path: measurements, labelPath: labels, kind: "hai"})
	if err != nil {
		t.Fatal(err)
	}
	defer coarse.Close()
	if _, got, _, err := coarse.Next(); err != nil || got != "attack" {
		t.Fatalf("minute-resolution HAI label: %q, %v", got, err)
	}
}

func TestSWATXLSXStreaming(t *testing.T) {
	path := filepath.Join(t.TempDir(), "swat.xlsx")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(f)
	stringsXML := `<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><si><t>Timestamp</t></si>`
	header := `<row r="1"><c r="A1" t="s"><v>0</v></c>`
	values := `<row r="2"><c r="A2" t="s"><v>22</v></c>`
	for i := 1; i <= 20; i++ {
		stringsXML += fmt.Sprintf("<si><t>FIT1%02d</t></si>", i)
		col := string(rune('A' + i))
		header += fmt.Sprintf(`<c r="%s1" t="s"><v>%d</v></c>`, col, i)
		values += fmt.Sprintf(`<c r="%s2"><v>%d</v></c>`, col, i)
	}
	stringsXML += `<si><t>Normal/Attack</t></si><si><t>22/12/2015 4:00:00 PM</t></si><si><t>Attack</t></si></sst>`
	header += `<c r="V1" t="s"><v>21</v></c></row>`
	values += `<c r="V2" t="s"><v>23</v></c></row>`
	for name, body := range map[string]string{
		"xl/sharedStrings.xml":     stringsXML,
		"xl/worksheets/sheet1.xml": `<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>` + header + values + `</sheetData></worksheet>`,
	} {
		w, err := z.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(w, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := openSWATRows(sourceSpec{path: path, kind: "swat"})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	if len(r.Columns()) != 20 {
		t.Fatalf("SWaT columns = %d", len(r.Columns()))
	}
	_, label, row, err := r.Next()
	if err != nil || label != "attack" || row[1] != "1" {
		t.Fatalf("SWaT row = %+v, label=%q, err=%v", row, label, err)
	}
}
