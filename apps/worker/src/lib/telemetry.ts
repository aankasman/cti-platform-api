/**
 * Worker Telemetry — Feed sync metrics for observability
 *
 * Records feed sync events (count, duration, items) per feed.
 * Used by the Prometheus endpoint on the API side via shared state,
 * and logs structured telemetry for Loki ingestion.
 *
 * Usage:
 *   import { workerTelemetry } from './lib/telemetry';
 *   const end = workerTelemetry.startSync('misp-galaxy');
 *   // ... sync logic ...
 *   end({ items: 1104, success: true });
 */

import { createLogger } from './logger';

const log = createLogger('WorkerTelemetry');

interface SyncRecord {
    feed: string;
    count: number;
    totalItems: number;
    lastDurationMs: number;
    lastSuccess: boolean;
    lastSyncAt: string;
    errors: number;
}

const syncs: Map<string, SyncRecord> = new Map();

/**
 * Start timing a feed sync. Returns a function to call when sync completes.
 */
function startSync(feed: string): (result: { items: number; success: boolean }) => void {
    const startTime = Date.now();

    return (result: { items: number; success: boolean }) => {
        const durationMs = Date.now() - startTime;
        const existing = syncs.get(feed) || {
            feed,
            count: 0,
            totalItems: 0,
            lastDurationMs: 0,
            lastSuccess: true,
            lastSyncAt: '',
            errors: 0,
        };

        existing.count++;
        existing.totalItems += result.items;
        existing.lastDurationMs = durationMs;
        existing.lastSuccess = result.success;
        existing.lastSyncAt = new Date().toISOString();
        if (!result.success) existing.errors++;

        syncs.set(feed, existing);

        // Structured log for Loki ingestion
        log.info('Feed sync completed', {
            feed,
            items: result.items,
            durationMs,
            success: result.success,
            totalSyncs: existing.count,
            totalItems: existing.totalItems,
        });
    };
}

/**
 * Get all sync records for reporting
 */
function getSyncRecords(): SyncRecord[] {
    return Array.from(syncs.values());
}

/**
 * Record a quick sync event (without start/end timing)
 */
function recordSync(feed: string, items: number, durationMs: number, success: boolean = true): void {
    const existing = syncs.get(feed) || {
        feed,
        count: 0,
        totalItems: 0,
        lastDurationMs: 0,
        lastSuccess: true,
        lastSyncAt: '',
        errors: 0,
    };

    existing.count++;
    existing.totalItems += items;
    existing.lastDurationMs = durationMs;
    existing.lastSuccess = success;
    existing.lastSyncAt = new Date().toISOString();
    if (!success) existing.errors++;

    syncs.set(feed, existing);

    log.info('Feed sync recorded', { feed, items, durationMs, success });
}

export const workerTelemetry = {
    startSync,
    getSyncRecords,
    recordSync,
};

export default workerTelemetry;
