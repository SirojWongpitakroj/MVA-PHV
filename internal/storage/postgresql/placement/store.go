package placement

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"

	"github.com/SirojWongpitakroj/mva-phv/internal/mpm"
)

//go:embed schema.sql
var schemaSQL string

// Store keeps placement assignments and round-robin cursors in a dedicated
// trusted control-plane PostgreSQL database. The DB's owner closes it.
type Store struct {
	db        *sql.DB
	sites     sync.Map // site key -> region
	devices   sync.Map // length-prefixed region/device key -> shard
	validated sync.Map // cursor scope -> configured topology signature
}

var _ mpm.SiteRegionStore = (*Store)(nil)

func New(db *sql.DB) (*Store, error) {
	if db == nil {
		return nil, errors.New("placement store: PostgreSQL DB is nil")
	}
	return &Store{db: db}, nil
}

// EnsureSchema creates only the MPM control-plane tables in this database.
func (s *Store) EnsureSchema(ctx context.Context) error {
	if s == nil || s.db == nil {
		return errors.New("placement store: not initialized")
	}
	for _, statement := range strings.Split(schemaSQL, ";") {
		if strings.TrimSpace(statement) == "" {
			continue
		}
		if _, err := s.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("placement schema: %w", err)
		}
	}
	return nil
}

func scopeKey(kind, scope string) string {
	return strconv.Itoa(len(kind)) + ":" + kind + ":" + scope
}

func deviceCacheKey(region, key string) string {
	return strconv.Itoa(len(region)) + ":" + region + ":" + key
}

// cursor locks the policy's round-robin cursor for this transaction. New
// assignments in different Regions can advance independently.
func (s *Store) cursor(ctx context.Context, tx *sql.Tx, kind, scope, signature string, count int) (int64, error) {
	if _, err := tx.ExecContext(ctx, `INSERT INTO placement_cursors
		(kind, scope, config_signature, next_index) VALUES ($1, $2, $3, 0)
		ON CONFLICT (kind, scope) DO NOTHING`, kind, scope, signature); err != nil {
		return 0, fmt.Errorf("initialize %s cursor: %w", kind, err)
	}
	var stored string
	var next int64
	if err := tx.QueryRowContext(ctx, `SELECT config_signature, next_index
		FROM placement_cursors WHERE kind = $1 AND scope = $2 FOR UPDATE`,
		kind, scope).Scan(&stored, &next); err != nil {
		return 0, fmt.Errorf("lock %s cursor: %w", kind, err)
	}
	if stored != signature {
		return 0, fmt.Errorf("placement topology changed for %s/%s; existing assignments retained", kind, scope)
	}
	if next < 0 || next >= int64(count) {
		return 0, fmt.Errorf("invalid %s cursor %d for %d choices", kind, next, count)
	}
	return next, nil
}

func (s *Store) AssignSite(ctx context.Context, siteKey string, regions []string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if s == nil || s.db == nil || siteKey == "" || len(regions) == 0 || len(regions) > math.MaxInt32 {
		return "", errors.New("assign Site: store, Site key, and Regions are required")
	}
	seen := make(map[string]struct{}, len(regions))
	for _, region := range regions {
		if region == "" {
			return "", errors.New("assign Site: empty Region")
		}
		if _, duplicate := seen[region]; duplicate {
			return "", errors.New("assign Site: duplicate Region")
		}
		seen[region] = struct{}{}
	}
	signatureBytes, err := json.Marshal(regions)
	if err != nil {
		return "", err
	}
	signature := string(signatureBytes)
	cacheScope := scopeKey("site", "global")
	if value, ok := s.validated.Load(cacheScope); ok {
		if value.(string) != signature {
			return "", errors.New("assign Site: configured Region order changed")
		}
		if value, ok := s.sites.Load(siteKey); ok {
			return value.(string), nil
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("assign Site: begin transaction: %w", err)
	}
	defer tx.Rollback()
	next, err := s.cursor(ctx, tx, "site", "global", signature, len(regions))
	if err != nil {
		return "", err
	}
	var region string
	err = tx.QueryRowContext(ctx, `SELECT region_id FROM site_region_assignments
		WHERE site_key = $1`, siteKey).Scan(&region)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", fmt.Errorf("read Site assignment: %w", err)
	}
	if errors.Is(err, sql.ErrNoRows) {
		region = regions[next]
		if _, err := tx.ExecContext(ctx, `INSERT INTO site_region_assignments
			(site_key, region_id) VALUES ($1, $2)`, siteKey, region); err != nil {
			return "", fmt.Errorf("persist Site assignment: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE placement_cursors SET next_index = $1
			WHERE kind = 'site' AND scope = 'global'`, (next+1)%int64(len(regions))); err != nil {
			return "", fmt.Errorf("advance Site cursor: %w", err)
		}
	} else if _, ok := seen[region]; !ok {
		return "", fmt.Errorf("stored Site Region %q is not configured", region)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("commit Site assignment: %w", err)
	}
	s.validated.Store(cacheScope, signature)
	s.sites.Store(siteKey, region)
	return region, nil
}

// Assign is the SiteRegionStore operation used by MPM.
func (s *Store) Assign(ctx context.Context, siteKey string, regions []string) (string, error) {
	return s.AssignSite(ctx, siteKey, regions)
}

// AssignShard is the DeviceShardStore operation; the different method name is
// needed because the two MPM interfaces use distinct Assign signatures.
func (s *Store) AssignShard(ctx context.Context, regionID, deviceKey string, count int) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if s == nil || s.db == nil || regionID == "" || deviceKey == "" ||
		count <= 0 || count > math.MaxInt32 {
		return 0, errors.New("assign Device: store, Region, Device key, and valid Shard count are required")
	}
	signature := strconv.Itoa(count)
	cacheScope := scopeKey("device", regionID)
	if value, ok := s.validated.Load(cacheScope); ok {
		if value.(string) != signature {
			return 0, errors.New("assign Device: configured Shard count changed")
		}
		if value, ok := s.devices.Load(deviceCacheKey(regionID, deviceKey)); ok {
			return value.(int64), nil
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("assign Device: begin transaction: %w", err)
	}
	defer tx.Rollback()
	next, err := s.cursor(ctx, tx, "device", regionID, signature, count)
	if err != nil {
		return 0, err
	}
	var sid int64
	err = tx.QueryRowContext(ctx, `SELECT shard_id FROM device_shard_assignments
		WHERE region_id = $1 AND device_key = $2`, regionID, deviceKey).Scan(&sid)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("read Device assignment: %w", err)
	}
	if errors.Is(err, sql.ErrNoRows) {
		sid = next
		if _, err := tx.ExecContext(ctx, `INSERT INTO device_shard_assignments
			(region_id, device_key, shard_id) VALUES ($1, $2, $3)`,
			regionID, deviceKey, sid); err != nil {
			return 0, fmt.Errorf("persist Device assignment: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE placement_cursors SET next_index = $1
			WHERE kind = 'device' AND scope = $2`, (next+1)%int64(count), regionID); err != nil {
			return 0, fmt.Errorf("advance Device cursor: %w", err)
		}
	} else if sid < 0 || sid >= int64(count) {
		return 0, fmt.Errorf("stored Shard %d is not configured in Region %q", sid, regionID)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit Device assignment: %w", err)
	}
	s.validated.Store(cacheScope, signature)
	s.devices.Store(deviceCacheKey(regionID, deviceKey), sid)
	return sid, nil
}

// ShardStore presents the same durable DB as the DeviceShardStore interface.
type ShardStore struct{ *Store }

var _ mpm.DeviceShardStore = ShardStore{}

func (s ShardStore) Assign(ctx context.Context, regionID, deviceKey string, count int) (int64, error) {
	return s.Store.AssignShard(ctx, regionID, deviceKey, count)
}
