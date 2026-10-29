package postgresql

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"uuid"

	"github.com/SirojWongpitakroj/mva-phv/internal/cloudprovider"
)

// Store is an external CP backend. Supply a database/sql DB connected to the
// CP database, never the trusted checkpoint or internal CLS database.
type Store struct{ db *sql.DB }

var _ cloudprovider.Provider = (*Store)(nil)

func New(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("PostgreSQL CP: DB is nil")
	}
	return &Store{db: db}, nil
}

func (s *Store) StoreCiphertext(ctx context.Context, region string, value cloudprovider.Ciphertext) error {
	if s == nil || s.db == nil || region == "" {
		return fmt.Errorf("PostgreSQL CP: missing database or deployment region")
	}
	if err := cloudprovider.ValidateCiphertext(value); err != nil {
		return err
	}
	// A conflicting retry never overwrites an existing CP object. Read it back
	// so an identical retry succeeds and a different object is rejected.
	_, err := s.db.ExecContext(ctx, `INSERT INTO encrypted_logs
		(log_id, ciphertext, nonce, tag, associated_data, encryption_version)
		VALUES ($1::uuid, $2, $3, $4, $5, $6)
		ON CONFLICT (log_id) DO NOTHING`, value.LogID.String(), value.Ciphertext,
		value.Nonce, value.Tag, value.AD, int64(value.Version))
	if err != nil {
		return fmt.Errorf("PostgreSQL CP: store ciphertext: %w", err)
	}
	stored, err := s.getOne(ctx, value.LogID)
	if err != nil {
		return fmt.Errorf("PostgreSQL CP: confirm ciphertext: %w", err)
	}
	if stored.Version != value.Version || !bytes.Equal(stored.Ciphertext, value.Ciphertext) ||
		!bytes.Equal(stored.Nonce, value.Nonce) || !bytes.Equal(stored.Tag, value.Tag) || !bytes.Equal(stored.AD, value.AD) {
		return cloudprovider.ErrConflict
	}
	return nil
}

func (s *Store) getOne(ctx context.Context, id uuid.UUID) (cloudprovider.Ciphertext, error) {
	var result cloudprovider.Ciphertext
	var rawID string
	var version int64
	err := s.db.QueryRowContext(ctx, `SELECT log_id, ciphertext, nonce, tag, associated_data, encryption_version
		FROM encrypted_logs WHERE log_id = $1::uuid`, id.String()).
		Scan(&rawID, &result.Ciphertext, &result.Nonce, &result.Tag, &result.AD, &version)
	if err != nil {
		return result, err
	}
	parsed, err := uuid.Parse(rawID)
	if err != nil || parsed != id {
		return result, fmt.Errorf("PostgreSQL CP: returned wrong LogID %q", rawID)
	}
	if version < 0 || version > 65535 {
		return result, cloudprovider.ErrUnsupportedVersion
	}
	result.LogID, result.Version = parsed, uint16(version)
	if err := cloudprovider.ValidateCiphertext(result); err != nil {
		return result, err
	}
	return result, nil
}

// GetCiphertexts retrieves exact LogIDs only. A missing row is returned as a
// gap; PHV compares the response to its authenticated request and reports
// missing evidence separately from cryptographic inconsistency.
func (s *Store) GetCiphertexts(ctx context.Context, region string, ids []uuid.UUID) ([]cloudprovider.Ciphertext, error) {
	if s == nil || s.db == nil || region == "" {
		return nil, fmt.Errorf("PostgreSQL CP: missing database or deployment region")
	}
	if len(ids) == 0 {
		return nil, nil
	}
	const batchSize = 128
	result := make([]cloudprovider.Ciphertext, 0, len(ids))
	for start := 0; start < len(ids); start += batchSize {
		end := min(start+batchSize, len(ids))
		parts := make([]string, end-start)
		for i, id := range ids[start:end] {
			if id == (uuid.UUID{}) {
				return nil, fmt.Errorf("PostgreSQL CP: zero LogID in request")
			}
			parts[i] = id.String()
		}
		// UUID strings contain only hex digits and dashes. The single argument is
		// a bound PostgreSQL array literal, not SQL interpolation.
		array := "{" + strings.Join(parts, ",") + "}"
		rows, err := s.db.QueryContext(ctx, `SELECT log_id, ciphertext, nonce, tag, associated_data, encryption_version
			FROM encrypted_logs WHERE log_id = ANY($1::uuid[])`, array)
		if err != nil {
			return nil, fmt.Errorf("PostgreSQL CP: fetch ciphertexts: %w", err)
		}
		for rows.Next() {
			var value cloudprovider.Ciphertext
			var rawID string
			var version int64
			if err := rows.Scan(&rawID, &value.Ciphertext, &value.Nonce, &value.Tag, &value.AD, &version); err != nil {
				rows.Close()
				return nil, fmt.Errorf("PostgreSQL CP: scan ciphertext: %w", err)
			}
			id, err := uuid.Parse(rawID)
			if err != nil {
				rows.Close()
				return nil, fmt.Errorf("PostgreSQL CP: malformed returned LogID: %w", err)
			}
			if version < 0 || version > 65535 {
				rows.Close()
				return nil, cloudprovider.ErrUnsupportedVersion
			}
			value.LogID, value.Version = id, uint16(version)
			if err := cloudprovider.ValidateCiphertext(value); err != nil {
				rows.Close()
				return nil, err
			}
			result = append(result, value)
		}
		err = errors.Join(rows.Err(), rows.Close())
		if err != nil {
			return nil, fmt.Errorf("PostgreSQL CP: read ciphertexts: %w", err)
		}
	}
	return result, nil
}
