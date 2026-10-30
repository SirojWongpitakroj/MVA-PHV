package canonicalize

import (
	"archive/zip"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

type xlsxCell struct {
	Ref    string `xml:"r,attr"`
	Kind   string `xml:"t,attr"`
	Value  string `xml:"v"`
	Inline string `xml:"is>t"`
}

type xlsxRow struct {
	Number int        `xml:"r,attr"`
	Cells  []xlsxCell `xml:"c"`
}

type xlsxRows struct {
	spec       sourceSpec
	archive    *zip.ReadCloser
	sheet      io.ReadCloser
	decoder    *xml.Decoder
	strings    []string
	columns    []processColumn
	width      int
	timeIndex  int
	labelIndex int
}

func openSWATRows(spec sourceSpec) (out *xlsxRows, err error) {
	z, err := zip.OpenReader(spec.path)
	if err != nil {
		return nil, err
	}
	r := &xlsxRows{spec: spec, archive: z, timeIndex: 0, labelIndex: -1}
	defer func() {
		if err != nil {
			_ = r.Close()
		}
	}()
	shared := zipEntry(z, "xl/sharedStrings.xml")
	if shared == nil {
		return nil, errors.New("SWaT workbook has no shared strings")
	}
	r.strings, err = readSharedStrings(shared)
	if err != nil {
		return nil, fmt.Errorf("SWaT shared strings: %w", err)
	}
	sheet := zipEntry(z, "xl/worksheets/sheet1.xml")
	if sheet == nil {
		return nil, errors.New("SWaT workbook has no first worksheet")
	}
	r.sheet, err = sheet.Open()
	if err != nil {
		return nil, err
	}
	r.decoder = xml.NewDecoder(r.sheet)
	for i := 0; i < 10; i++ {
		row, err := r.readRow()
		if err != nil {
			return nil, fmt.Errorf("SWaT header: %w", err)
		}
		values, err := r.values(row)
		if err != nil {
			return nil, err
		}
		var columns []processColumn
		for index, name := range values {
			if column, ok := parseTag("swat", name); ok {
				column.index = index
				columns = append(columns, column)
			}
		}
		if len(columns) < 20 {
			continue
		}
		r.columns, r.width = columns, len(values)
		for index, name := range values {
			lower := strings.ToLower(strings.TrimSpace(name))
			if strings.Contains(lower, "timestamp") {
				r.timeIndex = index
			}
			if strings.Contains(lower, "normal/attack") || strings.Contains(lower, "normal/ attack") {
				r.labelIndex = index
			}
		}
		if spec.labelFixed == "" && r.labelIndex < 0 {
			return nil, errors.New("SWaT attack sheet has no label column")
		}
		return r, nil
	}
	return nil, errors.New("unrecognized SWaT worksheet header")
}

func zipEntry(z *zip.ReadCloser, name string) *zip.File {
	for _, entry := range z.File {
		if entry.Name == name {
			return entry
		}
	}
	return nil
}

func readSharedStrings(entry *zip.File) (values []string, err error) {
	stream, err := entry.Open()
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, stream.Close()) }()
	decoder := xml.NewDecoder(stream)
	for {
		token, nextErr := decoder.Token()
		if errors.Is(nextErr, io.EOF) {
			return values, nil
		}
		if nextErr != nil {
			return nil, nextErr
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "si" {
			continue
		}
		var item struct {
			Text string `xml:"t"`
			Runs []struct {
				Text string `xml:"t"`
			} `xml:"r"`
		}
		if err := decoder.DecodeElement(&item, &start); err != nil {
			return nil, err
		}
		var text strings.Builder
		text.WriteString(item.Text)
		for _, run := range item.Runs {
			text.WriteString(run.Text)
		}
		values = append(values, text.String())
	}
}

func (r *xlsxRows) readRow() (xlsxRow, error) {
	for {
		token, err := r.decoder.Token()
		if err != nil {
			return xlsxRow{}, err
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "row" {
			continue
		}
		var row xlsxRow
		if err := r.decoder.DecodeElement(&row, &start); err != nil {
			return xlsxRow{}, err
		}
		return row, nil
	}
}

func xlsxColumn(ref string) (int, error) {
	index := 0
	for _, char := range ref {
		if char < 'A' || char > 'Z' {
			break
		}
		index = index*26 + int(char-'A'+1)
	}
	if index == 0 {
		return 0, fmt.Errorf("invalid XLSX cell reference %q", ref)
	}
	return index - 1, nil
}

func (r *xlsxRows) values(row xlsxRow) ([]string, error) {
	width := r.width
	if width == 0 {
		width = 64
	}
	values := make([]string, width)
	for _, cell := range row.Cells {
		index, err := xlsxColumn(cell.Ref)
		if err != nil {
			return nil, err
		}
		if index >= len(values) {
			values = append(values, make([]string, index-len(values)+1)...)
		}
		value := cell.Value
		if cell.Kind == "s" {
			n, err := strconv.Atoi(cell.Value)
			if err != nil || n < 0 || n >= len(r.strings) {
				return nil, fmt.Errorf("SWaT row %d: invalid shared-string index %q", row.Number, cell.Value)
			}
			value = r.strings[n]
		} else if cell.Kind == "inlineStr" {
			value = cell.Inline
		}
		values[index] = value
	}
	return values, nil
}

func (r *xlsxRows) Columns() []processColumn { return r.columns }

func (r *xlsxRows) Next() (time.Time, string, []string, error) {
	for {
		row, err := r.readRow()
		if err != nil {
			return time.Time{}, "", nil, err
		}
		if len(row.Cells) == 0 {
			continue
		}
		values, err := r.values(row)
		if err != nil {
			return time.Time{}, "", nil, err
		}
		if r.timeIndex >= len(values) || strings.TrimSpace(values[r.timeIndex]) == "" {
			return time.Time{}, "", nil, fmt.Errorf("SWaT row %d: missing timestamp", row.Number)
		}
		ts, err := parseTimestamp(values[r.timeIndex])
		if err != nil {
			return time.Time{}, "", nil, fmt.Errorf("SWaT row %d: %w", row.Number, err)
		}
		label := r.spec.labelFixed
		if r.labelIndex >= 0 {
			label, err = normalizeLabel("swat", values[r.labelIndex])
			if err != nil {
				return time.Time{}, "", nil, fmt.Errorf("SWaT row %d: %w", row.Number, err)
			}
		}
		return ts, label, values, nil
	}
}

func (r *xlsxRows) Close() error {
	var err error
	if r.sheet != nil {
		err = errors.Join(err, r.sheet.Close())
		r.sheet = nil
	}
	if r.archive != nil {
		err = errors.Join(err, r.archive.Close())
		r.archive = nil
	}
	return err
}
