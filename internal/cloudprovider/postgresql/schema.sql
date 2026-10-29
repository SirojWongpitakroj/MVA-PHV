-- External Cloud Provider ciphertext store. Deploy in a PostgreSQL database
-- separate from the trusted mock-checkpoint database and Cassandra CLS.
-- MPM's LogID is a 128-bit UUID, so BIGINT cannot represent it without an
-- additional mapping that would change the protocol identity.
CREATE TABLE IF NOT EXISTS encrypted_logs (
    log_id              UUID PRIMARY KEY,
    ciphertext          BYTEA NOT NULL,
    nonce               BYTEA NOT NULL CHECK (octet_length(nonce) = 12),
    tag                 BYTEA NOT NULL CHECK (octet_length(tag) = 16),
    associated_data     BYTEA NOT NULL CHECK (octet_length(associated_data) > 0),
    encryption_version  SMALLINT NOT NULL DEFAULT 1 CHECK (encryption_version > 0),
    stored_at           TIMESTAMPTZ NOT NULL DEFAULT now()
);
