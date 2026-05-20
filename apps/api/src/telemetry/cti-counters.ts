/**
 * CTI Domain Counters — In-memory metrics for threat intelligence operations
 *
 * Tracks ingestion and sync events per entity type.
 * Exposed via the Prometheus scrape endpoint as rinjani_cti_* metrics.
 *
 * Usage:
 *   import { recordIngest, recordSync, getCtiCounters } from './cti-counters';
 *   recordIngest('iocs', 150);
 *   recordSync('misp-galaxy', 1104, 28600);
 */

export interface CtiCounterSnapshot {
    iocs_ingested: number;
    vulns_synced: number;
    actors_synced: number;
    malware_synced: number;
    galaxy_synced: number;
    sigma_synced: number;
    feed_syncs: Record<string, { count: number; items: number; lastDurationMs: number; lastSyncAt: string }>;
}

const counters = {
    iocs_ingested: 0,
    vulns_synced: 0,
    actors_synced: 0,
    malware_synced: 0,
    galaxy_synced: 0,
    sigma_synced: 0,
};

const feedSyncs: Record<string, { count: number; items: number; lastDurationMs: number; lastSyncAt: string }> = {};

/**
 * Record entity ingestion / sync event
 */
export function recordIngest(entity: keyof typeof counters, count: number): void {
    if (entity in counters) {
        counters[entity] += count;
    }
}

/**
 * Record a feed sync completion
 */
export function recordSync(feed: string, itemCount: number, durationMs: number): void {
    if (!feedSyncs[feed]) {
        feedSyncs[feed] = { count: 0, items: 0, lastDurationMs: 0, lastSyncAt: '' };
    }
    feedSyncs[feed].count++;
    feedSyncs[feed].items += itemCount;
    feedSyncs[feed].lastDurationMs = durationMs;
    feedSyncs[feed].lastSyncAt = new Date().toISOString();
}

/**
 * Get current counter snapshot
 */
export function getCtiCounters(): CtiCounterSnapshot {
    return {
        ...counters,
        feed_syncs: { ...feedSyncs },
    };
}

/**
 * Format CTI counters as Prometheus text metrics
 */
export function getCtiPrometheusMetrics(): string {
    const lines: string[] = [];

    // Entity ingestion counters
    lines.push('# HELP rinjani_cti_ingested_total Total entities ingested by type');
    lines.push('# TYPE rinjani_cti_ingested_total counter');
    for (const [entity, count] of Object.entries(counters)) {
        lines.push(`rinjani_cti_ingested_total{entity="${entity}"} ${count}`);
    }

    // Feed sync counters
    lines.push('# HELP rinjani_feed_sync_total Total feed sync operations');
    lines.push('# TYPE rinjani_feed_sync_total counter');
    lines.push('# HELP rinjani_feed_sync_items_total Total items processed by feed');
    lines.push('# TYPE rinjani_feed_sync_items_total counter');
    lines.push('# HELP rinjani_feed_sync_duration_ms Last sync duration in milliseconds');
    lines.push('# TYPE rinjani_feed_sync_duration_ms gauge');

    for (const [feed, stats] of Object.entries(feedSyncs)) {
        lines.push(`rinjani_feed_sync_total{feed="${feed}"} ${stats.count}`);
        lines.push(`rinjani_feed_sync_items_total{feed="${feed}"} ${stats.items}`);
        lines.push(`rinjani_feed_sync_duration_ms{feed="${feed}"} ${stats.lastDurationMs}`);
    }

    return lines.join('\n');
}
