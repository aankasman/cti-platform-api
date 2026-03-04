-- Performance Indexes for V3 Backend API
-- Run: psql $DATABASE_URL -f apps/api/scripts/add-performance-indexes.sql

-- IOCs: timestamp queries in ops/ingestion (DATE_TRUNC, WHERE createdAt >= ...)
CREATE INDEX CONCURRENTLY IF NOT EXISTS iocs_created_at_idx ON iocs (created_at);
CREATE INDEX CONCURRENTLY IF NOT EXISTS iocs_severity_idx ON iocs (severity);

-- Sync Logs: monitoring/feeds ORDER BY + filter queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS sync_logs_created_at_idx ON sync_logs (created_at);
CREATE INDEX CONCURRENTLY IF NOT EXISTS sync_logs_entity_type_idx ON sync_logs (entity_type);

-- Vulnerabilities: timestamp queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS vulnerabilities_created_at_idx ON vulnerabilities (created_at);

-- Composite index for sync_logs (entity_type + created_at DESC) — used by monitoring/feeds
CREATE INDEX CONCURRENTLY IF NOT EXISTS sync_logs_entity_type_created_at_idx ON sync_logs (entity_type, created_at DESC);
