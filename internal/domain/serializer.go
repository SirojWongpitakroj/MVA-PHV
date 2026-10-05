package domain

import (
	"bytes"
	"encoding/binary"
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

// TO-DO
func Deserialize(b []byte) {}
