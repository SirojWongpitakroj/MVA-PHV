-- MVA-PHV evidence and working-recovery storage for Cassandra 4.1 / 5.0.
-- MPMRepository maps manager writes to the Store's bound CQL methods. A
-- concrete Cassandra Client and prepared-candidate evidence source are
-- supplied by the application; neither is a trusted checkpoint store.
-- Cassandra is internal Cloud Log Storage (CLS): it stores potentially
-- untrusted MVA/HPBF/HMF evidence, never the external CP ciphertext payload.
-- Its three mutable working tables support restart recovery only.
-- PostgreSQL, outside this schema, stores epoch orchestration, candidate and
-- finalized status, root tuples, checkpoint hashes, timestamps, and mock/real
-- blockchain references. During testing it is the trusted append-only mock
-- checkpoint store. Cassandra does not publish trusted checkpoints.
--
-- Write flow:
--   Ingest: log_addresses_by_id, hmf_active_segments_by_shard,
--           mva_pages/mva_working_view_state, hpbf_working_shard_filters.
--           MPM writes ciphertext separately to the external Cloud Provider.
--   Seal:   hmf_segments_by_shard and hmf_segment_nodes, then acknowledge the
--           persisted Segment in HMF so its in-memory proof nodes can be freed.
--   Commit: HMF changed hierarchy nodes and compact states; MVA view, region,
--           and global states; HPBF filters, commitments, and proof nodes.
-- Read flow: obtain the trusted finalized epoch and checkpoint from PostgreSQL
-- (or the blockchain interface), then verify Cassandra evidence against its
-- roots. For a versioned object at audit epoch e, use the newest version_epoch
-- <= e. Immutable sealed Segment evidence is stored once and shared by epochs.
--
-- All hash/commitment blobs are exactly 32 bytes. Numeric IDs are signed Go
-- int64. Epochs, counts, and indexes held as Go uint64 must fit CQL bigint
-- (0..MaxInt64). Blob formats need a versioned, deterministic Go codec; CQL
-- alone does not define one. No TTL is configured for proof evidence.

CREATE KEYSPACE IF NOT EXISTS mva_phv
WITH replication = {
    'class': 'NetworkTopologyStrategy',
    'datacenter1': '1'
}
AND durable_writes = true;

USE mva_phv;

-- A conditional insert reserves each LogID against its HMF address. This is
-- operational uniqueness metadata, not a ciphertext copy or trust
-- anchor. A retry with the same address is idempotent; another address fails.
CREATE TABLE IF NOT EXISTS log_addresses_by_id (
    log_id  uuid PRIMARY KEY,
    rid     text,
    sid     bigint,
    seg_id  bigint,
    leaf_id bigint
);

-- Mutable per-Shard working recovery state, not historical evidence. Update
-- after each HMF Insert; after sealing, clear active seg_id/opened_at_ns and
-- leaf_count but retain next_seg_id so IDs remain monotonic across a restart.
-- These rows may be overwritten. CP retains ciphertext; CLS retains evidence.
CREATE TABLE IF NOT EXISTS hmf_active_segments_by_shard (
    rid             text,
    sid             bigint,
    seg_id          bigint,
    opened_at_ns    bigint,
    leaf_count      bigint,
    next_seg_id     bigint,
    PRIMARY KEY ((rid), sid)
);

-- Sealed Segment evidence, stored once. Root and counts are immutable;
-- finalized_epoch records when the Segment entered finalized HMF evidence,
-- not whether that epoch's checkpoint is trusted. opened_at comes from the
-- working Shard; sealed_at comes from SegmentTree.SealedAt.
CREATE TABLE IF NOT EXISTS hmf_segments_by_shard (
    rid               text,
    sid               bigint,
    seg_id            bigint,
    segment_root      blob,
    leaf_count        bigint,
    tree_height       int,
    max_leaves        int,
    opened_at_ns      bigint,
    sealed_at_ns      bigint,
    finalized_epoch   bigint,
    persisted_at      timestamp,
    PRIMARY KEY ((rid, sid), seg_id)
) WITH CLUSTERING ORDER BY (seg_id ASC);

-- Persist all nodes returned by HMF.PendingSegmentNodes before calling
-- HMF.AcknowledgeSegmentPersisted. Level 0 contains d_i leaf commitments.
CREATE TABLE IF NOT EXISTS hmf_segment_nodes (
    rid          text,
    sid          bigint,
    seg_id       bigint,
    level        int,
    node_index   bigint,
    node_hash    blob,
    PRIMARY KEY ((rid, sid, seg_id), level, node_index)
) WITH CLUSTERING ORDER BY (level ASC, node_index ASC);

-- Changed finalized/candidate nodes only. tree_kind is SHARD, REGION, GLOBAL.
-- REGION uses sid=-1; GLOBAL uses rid='' and sid=-1. node_bucket is
-- floor(node_index / 4096); tune the bucket size with production measurements.
-- HMF currently calculates sparse Region/Global paths internally; its
-- candidate evidence source must export changed nodes for this table.
CREATE TABLE IF NOT EXISTS hmf_hierarchy_nodes (
    tree_kind       text,
    rid             text,
    sid             bigint,
    level           int,
    node_bucket     bigint,
    node_index      bigint,
    version_epoch   bigint,
    node_hash       blob,
    PRIMARY KEY (
        (tree_kind, rid, sid, level, node_bucket),
        node_index, version_epoch
    )
) WITH CLUSTERING ORDER BY (node_index ASC, version_epoch DESC);

-- Write a Shard state only when pending sealed Segments changed that Shard.
-- frontier_data must encode the ShardTree frontier with level/index/hash and
-- its order, sufficient to resume appends without old Segment leaves.
CREATE TABLE IF NOT EXISTS hmf_shard_state_by_epoch (
    rid             text,
    sid             bigint,
    epoch           bigint,
    shard_root      blob,
    segment_count   bigint,
    tree_height     int,
    frontier_data   blob,
    PRIMARY KEY ((rid, sid), epoch)
) WITH CLUSTERING ORDER BY (epoch DESC);

-- Write only changed Regions. At bootstrap, write one state for every Region.
CREATE TABLE IF NOT EXISTS hmf_region_state_by_epoch (
    rid             text,
    epoch           bigint,
    region_root     blob,
    shard_count     bigint,
    tree_height     int,
    PRIMARY KEY ((rid), epoch)
) WITH CLUSTERING ORDER BY (epoch DESC);

-- The HMF Global root is independent of epoch in its hash preimage. Store its
-- state by epoch for historical lookup; HMF.Commitment returns candidate root.
CREATE TABLE IF NOT EXISTS hmf_global_state_by_epoch (
    scope           text,
    epoch           bigint,
    global_root     blob,
    region_count    bigint,
    tree_height     int,
    PRIMARY KEY ((scope), epoch)
) WITH CLUSTERING ORDER BY (epoch DESC);

-- MVA writes each changed Page from LocatorUpdate.Pages during ingestion into
-- its working epoch. Repeated updates to the same page in that epoch upsert the
-- same row. Once PostgreSQL marks the epoch finalized, its page versions must
-- not be mutated. Earlier versions remain for historical Resolve/proof reads.
-- view is 'id' or
-- 'attribute', matching mva.ViewType. page_bucket=floor(page_id / 256).
-- page_data needs a canonical, versioned Page codec including ordered keys,
-- values or children, and child hashes. Page.Hash alone cannot reconstruct a
-- locator proof. Parent/neighbor IDs are also stored for navigation.
CREATE TABLE IF NOT EXISTS mva_pages (
    rid             text,
    view            text,
    page_bucket     bigint,
    page_id         bigint,
    version_epoch   bigint,
    is_leaf         boolean,
    parent_page_id  bigint,
    prev_page_id    bigint,
    next_page_id    bigint,
    page_hash       blob,
    page_data       blob,
    PRIMARY KEY ((rid, view, page_bucket), page_id, version_epoch)
) WITH CLUSTERING ORDER BY (page_id ASC, version_epoch DESC);

-- Mutable working recovery metadata for each Region/view, not historical
-- evidence. Update alongside changed pages on ingestion; retain the root and
-- allocation counters needed after restart. Rows may be overwritten. Each new
-- working epoch starts from the cumulative prior working view.
CREATE TABLE IF NOT EXISTS mva_working_view_state (
    rid             text,
    view            text,
    working_epoch   bigint,
    root_page_id    bigint,
    root_hash       blob,
    tree_height     int,
    record_count    bigint,
    next_page_id    bigint,
    tree_order      int,
    PRIMARY KEY ((rid), view)
);

-- Finalized locator roots from RegionMVASnapshot, one row per Region/view/epoch.
-- Persist initial root pages even for an empty view before its first manifest.
CREATE TABLE IF NOT EXISTS mva_region_view_state_by_epoch (
    rid             text,
    view            text,
    epoch           bigint,
    root_page_id    bigint,
    root_hash       blob,
    tree_height     int,
    record_count    bigint,
    next_page_id    bigint,
    tree_order      int,
    PRIMARY KEY ((rid, view), epoch)
) WITH CLUSTERING ORDER BY (epoch DESC);

-- Complete per-epoch Region manifest, in canonical MVA.Regions order.
CREATE TABLE IF NOT EXISTS mva_region_commitments_by_epoch (
    epoch           bigint,
    region_index    bigint,
    rid             text,
    id_root         blob,
    attr_root       blob,
    region_root     blob,
    PRIMARY KEY ((epoch), region_index)
) WITH CLUSTERING ORDER BY (region_index ASC);

-- MVA global Levels are produced by MVA.Commitment. Includes leaf level 0.
CREATE TABLE IF NOT EXISTS mva_global_nodes_by_epoch (
    epoch           bigint,
    level           int,
    node_index      bigint,
    node_hash       blob,
    PRIMARY KEY ((epoch), level, node_index)
) WITH CLUSTERING ORDER BY (level ASC, node_index ASC);

CREATE TABLE IF NOT EXISTS mva_epoch_roots (
    epoch           bigint PRIMARY KEY,
    mva_root        blob
);

-- Mutable working Shard BF for restart recovery, not finalized evidence.
-- HPBF.AddToken changes it; upsert the whole encoded BF after ingestion so an
-- unfinished epoch need not replay all logs. Rows may be overwritten. The next
-- working epoch starts cumulative.
-- filter_bits encodes the []uint64 words in canonical order; bit_count and
-- hash_count are BloomFilter.m and .k. There is no item count in the Go type.
CREATE TABLE IF NOT EXISTS hpbf_working_shard_filters (
    rid             text,
    sid             bigint,
    working_epoch   bigint,
    bit_count       bigint,
    hash_count      bigint,
    filter_bits     blob,
    PRIMARY KEY ((rid), sid)
);

-- Persist BF content only when it changes. Even if content is reused, every
-- epoch gets a distinct shard commitment because SHBF hashes the epoch.
CREATE TABLE IF NOT EXISTS hpbf_shard_filter_versions (
    rid             text,
    sid             bigint,
    version_epoch   bigint,
    bit_count       bigint,
    hash_count      bigint,
    filter_bits     blob,
    PRIMARY KEY ((rid, sid), version_epoch)
) WITH CLUSTERING ORDER BY (version_epoch DESC);

-- Complete per-epoch shard manifest in ShardID order. shard_index is the
-- canonical leaf position from ShardHPBFPartition.Index.
CREATE TABLE IF NOT EXISTS hpbf_shard_commitments_by_epoch (
    epoch                   bigint,
    rid                     text,
    sid                     bigint,
    shard_index             bigint,
    filter_version_epoch    bigint,
    shard_commitment        blob,
    PRIMARY KEY ((epoch, rid), sid)
) WITH CLUSTERING ORDER BY (sid ASC);

-- Derived Region BF used by HPBF.PruneRegions and RegionHPBFProof. It is
-- authenticated indirectly by the Shard BFs and commitments; verify proofs.
CREATE TABLE IF NOT EXISTS hpbf_region_filters_by_epoch (
    rid             text,
    epoch           bigint,
    bit_count       bigint,
    hash_count      bigint,
    filter_bits     blob,
    PRIMARY KEY ((rid), epoch)
) WITH CLUSTERING ORDER BY (epoch DESC);

-- RegionHPBFPartition.InternalNodes plus its root and canonical global index.
CREATE TABLE IF NOT EXISTS hpbf_region_nodes_by_epoch (
    epoch           bigint,
    rid             text,
    level           int,
    node_index      bigint,
    node_hash       blob,
    PRIMARY KEY ((epoch, rid), level, node_index)
) WITH CLUSTERING ORDER BY (level ASC, node_index ASC);

CREATE TABLE IF NOT EXISTS hpbf_region_roots_by_epoch (
    epoch           bigint,
    region_index    bigint,
    rid             text,
    region_root     blob,
    PRIMARY KEY ((epoch), region_index)
) WITH CLUSTERING ORDER BY (region_index ASC);

-- GlobalHPBFPartition.InternalNodes and RootHash.
CREATE TABLE IF NOT EXISTS hpbf_global_nodes_by_epoch (
    epoch           bigint,
    level           int,
    node_index      bigint,
    node_hash       blob,
    PRIMARY KEY ((epoch), level, node_index)
) WITH CLUSTERING ORDER BY (level ASC, node_index ASC);

CREATE TABLE IF NOT EXISTS hpbf_epoch_roots (
    epoch           bigint PRIMARY KEY,
    hpbf_root       blob
);

-- Historical read examples (after selecting the trusted epoch in PostgreSQL):
-- SELECT node_hash FROM hmf_hierarchy_nodes
-- WHERE tree_kind=? AND rid=? AND sid=? AND level=? AND node_bucket=?
--   AND node_index=? AND version_epoch<=? LIMIT 1;
-- SELECT * FROM hmf_shard_state_by_epoch
-- WHERE rid=? AND sid=? AND epoch<=? LIMIT 1;
-- SELECT * FROM mva_pages
-- WHERE rid=? AND view=? AND page_bucket=? AND page_id=?
--   AND version_epoch<=? LIMIT 1;
-- SELECT * FROM hpbf_shard_filter_versions
-- WHERE rid=? AND sid=? AND version_epoch<=? LIMIT 1;
-- Resolve then loads the selected MVA root page and walks its page IDs; HMF
-- verification loads the physical log and Segment nodes plus historical upper
-- nodes; HPBF pruning loads finalized region/shard filters and proof nodes.
