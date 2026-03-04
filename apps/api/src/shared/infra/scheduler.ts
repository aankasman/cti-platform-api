/**
 * Scheduler Service
 * 
 * Background tasks for scheduled operations like OpenSearch reindexing.
 */

import { reindexAll } from './opensearch';
import { createLogger } from '../lib/logger';

const log = createLogger('ReindexScheduler');

// Track last reindex time
let lastReindexTime: Date | null = null;
let isReindexing = false;

// ============================================================================
// Scheduled Reindex
// ============================================================================

/**
 * Run full reindex of all data to OpenSearch
 */
export async function runScheduledReindex(): Promise<{ success: boolean; indexed?: Record<string, number>; error?: string }> {
    if (isReindexing) {
        return { success: false, error: 'Reindex already in progress' };
    }

    isReindexing = true;
    log.info('Starting scheduled reindex');

    try {
        const startTime = Date.now();
        const result = await reindexAll();
        const duration = (Date.now() - startTime) / 1000;

        lastReindexTime = new Date();
        log.info('Reindex completed', { durationSec: duration.toFixed(1), result });

        return { success: true, indexed: result };
    } catch (error) {
        log.error('Reindex failed', error as Error);
        return { success: false, error: (error as Error).message };
    } finally {
        isReindexing = false;
    }
}

/**
 * Get scheduler status
 */
export function getSchedulerStatus() {
    return {
        lastReindexTime: lastReindexTime?.toISOString() || null,
        isReindexing,
        nextScheduledReindex: getNextReindexTime(),
    };
}

// ============================================================================
// Simple Interval-Based Scheduler
// ============================================================================

let schedulerInterval: NodeJS.Timeout | null = null;

/**
 * Start the scheduler (reindex every 24 hours)
 */
export function startScheduler() {
    if (schedulerInterval) {
        log.info('Scheduler already running');
        return;
    }

    // Run reindex every 24 hours (can be configured via env)
    const intervalHours = parseInt(process.env.REINDEX_INTERVAL_HOURS || '24', 10);
    const intervalMs = intervalHours * 60 * 60 * 1000;

    log.info('Scheduler started', { intervalHours });

    // Schedule periodic reindex
    schedulerInterval = setInterval(async () => {
        await runScheduledReindex();
    }, intervalMs);

    // Optional: Run initial reindex on startup (disabled by default)
    if (process.env.REINDEX_ON_STARTUP === 'true') {
        log.info('Running initial reindex on startup');
        runScheduledReindex();
    }
}

/**
 * Stop the scheduler
 */
export function stopScheduler() {
    if (schedulerInterval) {
        clearInterval(schedulerInterval);
        schedulerInterval = null;
        log.info('Scheduler stopped');
    }
}

/**
 * Get next scheduled reindex time
 */
function getNextReindexTime(): string | null {
    if (!lastReindexTime) return null;

    const intervalHours = parseInt(process.env.REINDEX_INTERVAL_HOURS || '24', 10);
    const next = new Date(lastReindexTime.getTime() + intervalHours * 60 * 60 * 1000);
    return next.toISOString();
}
