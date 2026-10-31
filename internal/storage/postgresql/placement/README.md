# Persistent MPM placement

Use a dedicated PostgreSQL **database** for MPM control-plane placement. Do
not point this store at the external ciphertext CP database or the trusted
mock-blockchain checkpoint database.

Set these values in the ignored `.env.local` file:

```text
MVA_PLACEMENT_HOST=<PostgreSQL host>
MVA_PLACEMENT_PORT=5432
MVA_PLACEMENT_DATABASE=<dedicated placement database>
MVA_PLACEMENT_USER=<user>
MVA_PLACEMENT_PASSWORD=<password>
MVA_PLACEMENT_SSLMODE=require
```

The database must already exist. On persistent startup, `EnsureSchema`
creates the three tables from [schema.sql](schema.sql) if necessary.

Each new Site or Device assignment and its round-robin cursor advance commit
in one transaction. Existing assignments are read from PostgreSQL after a
restart and cached in process for ordinary ingestion. Changing the configured
Region order or Shard count is rejected rather than silently remapping data.
