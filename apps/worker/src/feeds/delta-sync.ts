/**
 * Delta Sync Helper
 *
 * Provides utilities for incremental feed synchronization.
 * Queries `sync_logs` to determine when each feed last ran successfully,
 * and stores cursors (catalog versions, timestamps) for change detection.
 */

import { db } from '@rinjani/db';
import { syncLogs } from '@rinjani/db/schema';
import { eq, desc, and, sql } from '@rinjani/db';

// =============================================================================
// Last Sync Timestamp
// =============================================================================

/**
 * Get the last successful sync time for a given feed.
 * Returns null if the feed has never synced.
 */
export async function getLastSyncTime(entityType: string): Promise<Date | null> {
    const rows = await db
        .select({ completedAt: syncLogs.completedAt })
        .from(syncLogs)
        .where(
            and(
                eq(syncLogs.entityType, entityType),
                eq(syncLogs.status, 'success'),
            ),
        )
        .orderBy(desc(syncLogs.completedAt))
        .limit(1);

    return rows[0]?.completedAt ?? null;
}

/**
 * Get the last sync cursor (e.g., catalog version, page token) for a feed.
 * Returns null if never synced.
 */
export async function getLastSyncCursor(entityType: string): Promise<string | null> {
    const rows = await db
        .select({ cursor: syncLogs.lastSyncCursor })
        .from(syncLogs)
        .where(
            and(
                eq(syncLogs.entityType, entityType),
                eq(syncLogs.status, 'success'),
            ),
        )
        .orderBy(desc(syncLogs.completedAt))
        .limit(1);

    return rows[0]?.cursor ?? null;
}

/**
 * Compute the number of days since the last successful sync.
 * Falls back to `defaultDays` if never synced.
 */
export async function daysSinceLastSync(entityType: string, defaultDays: number): Promise<number> {
    const lastSync = await getLastSyncTime(entityType);
    if (!lastSync) return defaultDays;

    const diffMs = Date.now() - lastSync.getTime();
    const diffDays = Math.ceil(diffMs / (24 * 60 * 60 * 1000));
    return Math.max(1, Math.min(diffDays + 1, defaultDays)); // +1 buffer, cap at default
}

/**
 * Format a Date as an ISO string safe for API parameters.
 * Returns format: "2026-03-05T00:00:00"
 */
export function toISOParam(date: Date): string {
    return date.toISOString().replace(/\.\d{3}Z$/, '');
}
