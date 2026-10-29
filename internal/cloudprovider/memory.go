package cloudprovider

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sync"
	"uuid"
)

// Memory is a process-local CP mock. Production deployments replace it with
// an external object/log-storage adapter implementing Provider.
type Memory struct {
	mu      sync.RWMutex
	records map[uuid.UUID]memoryEntry
}

type memoryEntry struct {
	region string
	value  Ciphertext
}

var _ Provider = (*Memory)(nil)

func NewMemory() *Memory { return &Memory{records: make(map[uuid.UUID]memoryEntry)} }

func clone(value Ciphertext) Ciphertext {
	value.Ciphertext = slices.Clone(value.Ciphertext)
	value.Nonce = slices.Clone(value.Nonce)
	value.Tag = slices.Clone(value.Tag)
	value.AD = slices.Clone(value.AD)
	return value
}

func same(a, b Ciphertext) bool {
	return a.LogID == b.LogID && a.Version == b.Version && bytes.Equal(a.Ciphertext, b.Ciphertext) &&
		bytes.Equal(a.Nonce, b.Nonce) && bytes.Equal(a.Tag, b.Tag) && bytes.Equal(a.AD, b.AD)
}

func (m *Memory) StoreCiphertext(ctx context.Context, region string, value Ciphertext) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if m == nil || region == "" {
		return fmt.Errorf("cloud provider: invalid ciphertext or region")
	}
	if err := ValidateCiphertext(value); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, exists := m.records[value.LogID]; exists {
		if old.region != region || !same(old.value, value) {
			return ErrConflict
		}
		return nil
	}
	m.records[value.LogID] = memoryEntry{region: region, value: clone(value)}
	return nil
}

// Missing IDs are omitted, as an external CP can withhold records. PHV must
// compare the response with its exact authenticated request and reject gaps.
func (m *Memory) GetCiphertexts(ctx context.Context, region string, ids []uuid.UUID) ([]Ciphertext, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if m == nil || region == "" {
		return nil, fmt.Errorf("cloud provider: invalid region")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	result := make([]Ciphertext, 0, len(ids))
	for _, id := range ids {
		if entry, ok := m.records[id]; ok && entry.region == region {
			result = append(result, clone(entry.value))
		}
	}
	return result, nil
}
