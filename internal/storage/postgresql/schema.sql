-- Trusted, append-only checkpoint interface used during testing.
-- Cassandra keeps authentication evidence; this table publishes accepted epochs.
CREATE TABLE IF NOT EXISTS mock_checkpoints (
    epoch           BIGINT PRIMARY KEY,
    checkpoint_hash BYTEA NOT NULL CHECK (octet_length(checkpoint_hash) = 32),
    committed_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
