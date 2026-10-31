-- Trusted MPM control-plane state. Use a PostgreSQL database separate from
-- the external CP ciphertext store and the mock blockchain checkpoint store.
CREATE TABLE IF NOT EXISTS placement_cursors (
    kind             TEXT NOT NULL,
    scope            TEXT NOT NULL,
    config_signature TEXT NOT NULL,
    next_index       INTEGER NOT NULL CHECK (next_index >= 0),
    PRIMARY KEY (kind, scope)
);

CREATE TABLE IF NOT EXISTS site_region_assignments (
    site_key  TEXT PRIMARY KEY,
    region_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_shard_assignments (
    region_id  TEXT NOT NULL,
    device_key TEXT NOT NULL,
    shard_id   INTEGER NOT NULL CHECK (shard_id >= 0),
    PRIMARY KEY (region_id, device_key)
);
