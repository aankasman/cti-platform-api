/**
 * Monitoring — System Health Route
 *
 * Uses sql.raw() for the sync failure query to avoid Drizzle ORM
 * dual-package type conflicts (shouldInlineParams).
 */

import { Hono } from 'hono';
import { rawQuery } from '@rinjani/db';
import type { RawQueryResult } from '@rinjani/db';
import { escSql } from '../../lib/sanitize';

const healthRoutes = new Hono();

// Track process start time for uptime calculation
const PROCESS_START = new Date(Date.now() - process.uptime() * 1000);

/**
 * Format seconds into human-readable uptime string.
 */
function formatUptime(seconds: number): string {
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = Math.floor(seconds % 60);
    const parts: string[] = [];
    if (d > 0) parts.push(`${d}d`);
    if (h > 0) parts.push(`${h}h`);
    if (m > 0) parts.push(`${m}m`);
    parts.push(`${s}s`);
    return parts.join(' ');
}

/**
 * GET /v1/monitoring/health
 * Get overall system health with actual uptime tracking.
 */
healthRoutes.get('/health', async (c) => {
    // Get recent sync failures (last 24 hours) using sql.raw to avoid Drizzle type conflicts
    const oneDayAgo = new Date();
    oneDayAgo.setDate(oneDayAgo.getDate() - 1);

    const result = await rawQuery<{ status: string; cnt: number }>(
        `SELECT status, COUNT(*)::int as cnt FROM sync_logs
         WHERE created_at >= '${escSql(oneDayAgo.toISOString())}'
         GROUP BY status`
    );

    const rows = result.rows || [];
    const statusCounts: Record<string, number> = {};
    for (const row of rows) {
        statusCounts[row.status] = row.cnt;
    }

    const totalSyncs = Object.values(statusCounts).reduce((a, b) => a + b, 0);
    const failedSyncs = statusCounts['error'] || 0;
    const partialSyncs = statusCounts['partial'] || 0;

    // Determine overall health
    let overallHealth = 'healthy';
    const failureRate = totalSyncs > 0 ? (failedSyncs / totalSyncs) * 100 : 0;

    if (failureRate > 20) overallHealth = 'critical';
    else if (failureRate > 10 || partialSyncs > 5) overallHealth = 'degraded';

    // Actual uptime from process.uptime()
    const uptimeSeconds = process.uptime();

    return c.json({
        success: true,
        data: {
            status: overallHealth,
            uptime: {
                seconds: Math.floor(uptimeSeconds),
                formatted: formatUptime(uptimeSeconds),
                startedAt: PROCESS_START.toISOString(),
            },
            syncs: {
                total: totalSyncs,
                successful: totalSyncs - failedSyncs - partialSyncs,
                partial: partialSyncs,
                failed: failedSyncs,
            },
            timestamp: new Date().toISOString(),
        },
    });
});

export default healthRoutes;
