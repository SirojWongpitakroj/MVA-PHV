package domain

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"time"
	"uuid"
)

func writeString(buf *bytes.Buffer, s string) error {
	if err := binary.Write(buf, binary.BigEndian, uint32(len(s))); err != nil {
		return err
	}

	_, err := buf.WriteString(s)
	return err
}

func Serialize(args ...any) ([]byte, error) {
	var buf bytes.Buffer

	for _, obj := range args {
		switch v := obj.(type) {
		case string:
			if err := writeString(&buf, v); err != nil {
				return nil, err
			}
		case []byte:
			if _, err := buf.Write(v); err != nil {
				return nil, err
			}
		case uint64:
			if err := binary.Write(&buf, binary.BigEndian, v); err != nil {
				return nil, err
			}
		case time.Time:
			if err := binary.Write(
				&buf,
				binary.BigEndian,
				v.UnixNano(),
			); err != nil {
				return nil, err
			}
		case uuid.UUID:
			if _, err := buf.Write(v[:]); err != nil {
				return nil, err
			}
		}
	}
	return buf.Bytes(), nil
}

// Deserialize reads values in the same order they were passed to Serialize.
// Destinations must be *string, *[]byte, *uint64, *time.Time, or *uuid.UUID. A byte
// slice before the last destination must have the length to read already set;
// an empty final byte slice receives all remaining bytes.
func Deserialize(b []byte, destinations ...any) error {
	reader := bytes.NewReader(b)

	for i, destination := range destinations {
		if destination == nil {
			return fmt.Errorf("destination %d is nil", i)
		}

		switch v := destination.(type) {
		case *uint64:
			if v == nil {
				return fmt.Errorf("nil uint64 destination at index %d", i)
			}
			if err := binary.Read(reader, binary.BigEndian, v); err != nil {
				return fmt.Errorf("read uint64 at destination %d: %w", i, err)
			}
		case *string:
			if v == nil {
				return fmt.Errorf("destination %d is nil", i)
			}
			var length uint32
			if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
				return fmt.Errorf("read string length at destination %d: %w", i, err)
			}
			if uint64(length) > uint64(reader.Len()) {
				return fmt.Errorf("string at destination %d exceeds remaining data", i)
			}
			value := make([]byte, int(length))
			if _, err := io.ReadFull(reader, value); err != nil {
				return fmt.Errorf("read string at destination %d: %w", i, err)
			}
			*v = string(value)
		case *[]byte:
			if v == nil {
				return fmt.Errorf("destination %d is nil", i)
			}
			if i == len(destinations)-1 && len(*v) == 0 {
				*v = append([]byte(nil), b[len(b)-reader.Len():]...)
				reader = bytes.NewReader(nil)
				continue
			}
			if _, err := io.ReadFull(reader, *v); err != nil {
				return fmt.Errorf("read bytes at destination %d: %w", i, err)
			}
		case *time.Time:
			if v == nil {
				return fmt.Errorf("destination %d is nil", i)
			}
			var nanos int64
			if err := binary.Read(reader, binary.BigEndian, &nanos); err != nil {
				return fmt.Errorf("read time at destination %d: %w", i, err)
			}
			*v = time.Unix(0, nanos).UTC()
		case *uuid.UUID:
			if v == nil {
				return fmt.Errorf("destination %d is nil", i)
			}
			if _, err := io.ReadFull(reader, v[:]); err != nil {
				return fmt.Errorf("read UUID at destination %d: %w", i, err)
			}
		default:
			return fmt.Errorf("unsupported destination type %T at position %d", destination, i)
		}
	}

	if reader.Len() != 0 {
		return fmt.Errorf("%d trailing bytes after destinations", reader.Len())
	}
	return nil
}
