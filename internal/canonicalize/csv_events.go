package canonicalize

import (
	"bufio"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

type csvRows struct {
	spec       sourceSpec
	file       *os.File
	reader     *csv.Reader
	labelFile  *os.File
	labels     *csv.Reader
	header     []string
	columns    []processColumn
	timeIndex  int
	dateIndex  int
	labelIndex int
	clock      wadiClock
	row        uint64
}

func openCSVRows(spec sourceSpec) (out *csvRows, err error) {
	f, err := os.Open(spec.path)
	if err != nil {
		return nil, err
	}
	r := &csvRows{spec: spec, file: f, reader: csv.NewReader(bufio.NewReaderSize(f, 64*1024)),
		timeIndex: -1, dateIndex: -1, labelIndex: -1}
	defer func() {
		if err != nil {
			_ = r.Close()
		}
	}()
	r.reader.FieldsPerRecord = -1
	header, err := r.reader.Read()
	if err != nil {
		return nil, err
	}
	if spec.kind == "wadi-attack" && len(header) > 0 && strings.TrimSpace(header[0]) == "0" {
		header, err = r.reader.Read() // Original attack CSV has a numeric index row.
		if err != nil {
			return nil, err
		}
	}
	r.header = header
	for i, name := range header {
		name = strings.TrimSpace(strings.TrimPrefix(name, "\ufeff"))
		switch {
		case strings.EqualFold(name, "timestamp") || strings.EqualFold(name, "time"):
			r.timeIndex = i
		case strings.EqualFold(name, "date"):
			r.dateIndex = i
		case strings.EqualFold(name, "label") || strings.Contains(strings.ToLower(name), "attack lable"):
			r.labelIndex = i
		default:
			if column, ok := parseTag(spec.kind, name); ok {
				column.index = i
				r.columns = append(r.columns, column)
			}
		}
	}
	if r.timeIndex < 0 || len(r.columns) == 0 ||
		(strings.HasPrefix(spec.kind, "wadi") && r.dateIndex < 0) ||
		(spec.kind == "wadi-attack" && r.labelIndex < 0) {
		return nil, fmt.Errorf("unrecognized %s schema", spec.kind)
	}
	if strings.HasPrefix(spec.kind, "wadi") {
		r.clock.hour, err = inferWADIInitialHour(spec, r.dateIndex, r.timeIndex)
		if err != nil {
			return nil, err
		}
	}
	if spec.labelPath != "" {
		r.labelFile, err = os.Open(spec.labelPath)
		if err != nil {
			return nil, err
		}
		r.labels = csv.NewReader(bufio.NewReaderSize(r.labelFile, 32*1024))
		labelHeader, err := r.labels.Read()
		if err != nil || len(labelHeader) != 2 || strings.TrimSpace(labelHeader[0]) != "timestamp" || strings.TrimSpace(labelHeader[1]) != "label" {
			return nil, fmt.Errorf("invalid HAI label schema: %v", err)
		}
	}
	return r, nil
}

// WADI's Time cells contain only minute:second. A metadata-only pass through
// the first date block infers its starting hour from the next midnight. The
// supplied files start at 18:00; later dates restart at 00:00.
func inferWADIInitialHour(spec sourceSpec, dateIndex, timeIndex int) (int, error) {
	f, err := os.Open(spec.path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	reader := csv.NewReader(bufio.NewReaderSize(f, 64*1024))
	reader.FieldsPerRecord = -1
	if _, err := reader.Read(); err != nil {
		return 0, err
	}
	if spec.kind == "wadi-attack" {
		if _, err := reader.Read(); err != nil {
			return 0, err
		}
	}
	first, err := reader.Read()
	if err != nil {
		return 0, err
	}
	date := strings.TrimSpace(first[dateIndex])
	last, err := wadiMinuteSecond(first[timeIndex])
	if err != nil {
		return 0, err
	}
	hours := 1
	for {
		row, err := reader.Read()
		if err == io.EOF {
			return 0, nil // No day boundary: the hour is not recoverable.
		}
		if err != nil || len(row) <= timeIndex || len(row) <= dateIndex {
			return 0, fmt.Errorf("infer WADI hour: invalid row: %v", err)
		}
		if strings.TrimSpace(row[dateIndex]) != date {
			next, err := wadiMinuteSecond(row[timeIndex])
			if err != nil || last != 59*60+59 || next != 0 {
				return 0, fmt.Errorf("infer WADI hour: date boundary is not at minute:second 00:00: %v", err)
			}
			return 24 - hours, nil
		}
		current, err := wadiMinuteSecond(row[timeIndex])
		if err != nil {
			return 0, err
		}
		if current < last {
			hours++
			if hours > 24 {
				return 0, fmt.Errorf("infer WADI hour: more than 24 hour blocks in one date")
			}
		}
		last = current
	}
}

func wadiMinuteSecond(raw string) (int, error) {
	parts := strings.Split(strings.TrimSpace(raw), ":")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid WADI time %q", raw)
	}
	minute, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, err
	}
	seconds := strings.SplitN(parts[1], ".", 2)
	second, err := strconv.Atoi(seconds[0])
	if err != nil || minute < 0 || minute > 59 || second < 0 || second > 59 {
		return 0, fmt.Errorf("invalid WADI time %q", raw)
	}
	return minute*60 + second, nil
}

func (r *csvRows) Columns() []processColumn { return r.columns }

func (r *csvRows) Next() (time.Time, string, []string, error) {
	row, err := r.reader.Read()
	if err != nil {
		if errors.Is(err, io.EOF) && r.labels != nil {
			if _, labelErr := r.labels.Read(); labelErr != io.EOF {
				return time.Time{}, "", nil, fmt.Errorf("HAI label file has extra or malformed rows: %v", labelErr)
			}
		}
		return time.Time{}, "", nil, err
	}
	r.row++
	if len(row) != len(r.header) {
		return time.Time{}, "", nil, fmt.Errorf("row %d has %d fields, want %d", r.row, len(row), len(r.header))
	}
	var ts time.Time
	if strings.HasPrefix(r.spec.kind, "wadi") {
		ts, err = r.clock.parse(row[r.dateIndex], row[r.timeIndex])
	} else {
		ts, err = parseTimestamp(row[r.timeIndex])
	}
	if err != nil {
		return time.Time{}, "", nil, fmt.Errorf("row %d timestamp: %w", r.row, err)
	}
	label := r.spec.labelFixed
	if r.labelIndex >= 0 {
		label, err = normalizeLabel(r.spec.kind, row[r.labelIndex])
	} else if r.labels != nil {
		labelRow, labelErr := r.labels.Read()
		if labelErr != nil || len(labelRow) != 2 {
			return time.Time{}, "", nil, fmt.Errorf("row %d HAI label timestamp mismatch: %v", r.row, labelErr)
		}
		labelTime, minuteOnly, timeErr := parseHAIAnnotationTime(labelRow[0])
		if timeErr != nil || (minuteOnly && !ts.Truncate(time.Minute).Equal(labelTime)) ||
			(!minuteOnly && !ts.Equal(labelTime)) {
			return time.Time{}, "", nil, fmt.Errorf("row %d HAI label timestamp mismatch: %v", r.row, timeErr)
		}
		label, err = normalizeLabel("hai", labelRow[1])
	}
	if err != nil {
		return time.Time{}, "", nil, fmt.Errorf("row %d label: %w", r.row, err)
	}
	return ts, label, row, nil
}

func parseHAIAnnotationTime(raw string) (time.Time, bool, error) {
	value := strings.TrimSpace(raw)
	if strings.Count(value, ":") == 1 {
		ts, err := time.ParseInLocation("2006-01-02 15:04", value, time.UTC)
		return ts, true, err
	}
	ts, err := parseTimestamp(value)
	return ts, false, err
}

func (r *csvRows) Close() error {
	var err error
	if r.file != nil {
		err = errors.Join(err, r.file.Close())
		r.file = nil
	}
	if r.labelFile != nil {
		err = errors.Join(err, r.labelFile.Close())
		r.labelFile = nil
	}
	return err
}

func normalizeLabel(kind, raw string) (string, error) {
	value := strings.ToLower(strings.TrimSpace(raw))
	switch kind {
	case "wadi-attack":
		switch value {
		case "1":
			return "normal", nil
		case "-1":
			return "attack", nil
		}
	case "hai":
		switch value {
		case "0":
			return "normal", nil
		case "1":
			return "attack", nil
		}
	case "swat":
		switch value {
		case "normal":
			return "normal", nil
		case "attack":
			return "attack", nil
		}
	}
	return "", fmt.Errorf("unknown %s label %q", kind, raw)
}

func parseTimestamp(raw string) (time.Time, error) {
	value := strings.TrimSpace(raw)
	for _, layout := range []string{
		"2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05",
		"2006-01-02T15:04:05.999999999Z07:00", "2006-01-02T15:04:05Z07:00",
		"2/1/2006 3:04:05 PM", "2/1/2006 15:04:05", "1/2/2006 3:04:05 PM",
	} {
		if ts, err := time.ParseInLocation(layout, value, time.UTC); err == nil {
			return ts.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported timestamp %q", raw)
}

// WADI exports mm:ss.s without an hour field. The source's Date and the
// observed minute rollover determine the hour within each date block.
type wadiClock struct {
	date       time.Time
	lastSecond int
	hour       int
	seen       bool
	last       time.Time
}

func (c *wadiClock) parse(dateRaw, clockRaw string) (time.Time, error) {
	var day time.Time
	var err error
	for _, layout := range []string{"1/2/2006", "1/2/06"} {
		day, err = time.ParseInLocation(layout, strings.TrimSpace(dateRaw), time.UTC)
		if err == nil {
			break
		}
	}
	if err != nil {
		return time.Time{}, err
	}
	parts := strings.Split(strings.TrimSpace(clockRaw), ":")
	if len(parts) != 2 {
		return time.Time{}, fmt.Errorf("invalid WADI time %q", clockRaw)
	}
	minute, err := strconv.Atoi(parts[0])
	if err != nil {
		return time.Time{}, err
	}
	seconds := strings.SplitN(parts[1], ".", 2)
	second, err := strconv.Atoi(seconds[0])
	if err != nil || minute < 0 || minute > 59 || second < 0 || second > 59 {
		return time.Time{}, fmt.Errorf("invalid WADI time %q", clockRaw)
	}
	nanos := 0
	if len(seconds) == 2 {
		if len(seconds[1]) == 0 || len(seconds[1]) > 9 {
			return time.Time{}, fmt.Errorf("invalid WADI fractional time %q", clockRaw)
		}
		fraction := seconds[1] + strings.Repeat("0", 9-len(seconds[1]))
		nanos, err = strconv.Atoi(fraction)
		if err != nil {
			return time.Time{}, err
		}
	}
	withinHour := minute*60 + second
	if c.seen && day.Equal(c.date) && withinHour < c.lastSecond {
		c.hour++
	}
	if c.seen && !day.Equal(c.date) {
		c.hour = 0
	}
	ts := day.Add(time.Duration(c.hour)*time.Hour + time.Duration(withinHour)*time.Second + time.Duration(nanos))
	if c.seen && ts.Before(c.last) {
		return time.Time{}, fmt.Errorf("WADI time moved backward from %s to %s", c.last, ts)
	}
	c.date, c.lastSecond, c.last, c.seen = day, withinHour, ts, true
	return ts, nil
}
