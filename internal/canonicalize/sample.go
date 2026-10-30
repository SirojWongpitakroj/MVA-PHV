package canonicalize

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
)

// WriteSampleJSONL is intentionally capped. Full ingestion must consume
// EventStream.Next directly rather than materializing a canonical file.
func WriteSampleJSONL(ctx context.Context, stream *EventStream, out io.Writer, limit int) (int, []CanonicalRecord, error) {
	if stream == nil || out == nil || limit < 1 || limit > 100 {
		return 0, nil, fmt.Errorf("canonicalize: sample limit must be 1..100")
	}
	encoder := json.NewEncoder(out)
	var examples []CanonicalRecord
	count := 0
	for count < limit {
		record, err := stream.Next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, examples, err
		}
		if err := encoder.Encode(record); err != nil {
			return count, examples, err
		}
		if len(examples) < 3 {
			examples = append(examples, record)
		}
		count++
	}
	return count, examples, nil
}
