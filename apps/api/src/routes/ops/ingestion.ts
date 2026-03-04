/**
 * Ops Ingestion Metrics Route
 *
 * IOC ingestion rates and per-feed breakdown.
 */

import { Hono } from 'hono';
import { and, count, db, eq, gte, sql } from '@rinjani/db';
import { iocs, syncLogs } from '@rinjani/db/schema';
import { requireAuth } from '../../middleware/auth';

const router = new Hono();

/** GET /ingestion — IOC ingestion rates and per-feed breakdown */
router.get('/ingestion', requireAuth, async (c) => {
    const now = new Date();
    const oneDayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
    const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

    // Run ALL queries in parallel
    const [lastHourCount, hourlyIngestion, dailyIngestion, sourceBreakdownResult, totalIOCs, syncCountsResult] = await Promise.all([
        db.select({ count: count() }).from(iocs).where(gte(iocs.createdAt, oneHourAgo)),
        db.select({
            hour: sql<string>`DATE_TRUNC('hour', ${iocs.createdAt})`,
            count: count(),
        }).from(iocs).where(gte(iocs.createdAt, oneDayAgo))
            .groupBy(sql`DATE_TRUNC('hour', ${iocs.createdAt})`)
            .orderBy(sql`DATE_TRUNC('hour', ${iocs.createdAt})`),
        db.select({
            date: sql<string>`DATE(${iocs.createdAt})`,
            count: count(),
        }).from(iocs).where(gte(iocs.createdAt, sevenDaysAgo))
            .groupBy(sql`DATE(${iocs.createdAt})`)
            .orderBy(sql`DATE(${iocs.createdAt})`),
        db.execute(sql`SELECT source, COUNT(*) as count FROM iocs GROUP BY source ORDER BY count DESC`),
        db.select({ count: count() }).from(iocs),
        db.select({
            entityType: syncLogs.entityType,
            syncCount: count(),
        }).from(syncLogs)
            .where(gte(syncLogs.startedAt, oneDayAgo))
            .groupBy(syncLogs.entityType),
    ]);

    const sourceBreakdown = (sourceBreakdownResult as unknown as Record<string, unknown>[]).map((row) => ({
        source: String(row.source),
        count: Number(row.count),
    }));

    // Build sync count lookup from sync_logs
    const syncCountMap: Record<string, number> = {};
    for (const row of syncCountsResult) {
        syncCountMap[row.entityType] = Number(row.syncCount);
    }

    return c.json({
        success: true,
        data: {
            currentRate: {
                iocsPerHour: Number(lastHourCount[0]?.count || 0),
                iocsPerMinute: Math.round(Number(lastHourCount[0]?.count || 0) / 60),
            },
            hourly: hourlyIngestion.map(h => ({
                timestamp: h.hour,
                count: Number(h.count),
            })),
            daily: dailyIngestion.map(d => ({
                date: d.date,
                count: Number(d.count),
            })),
            feedBreakdown: sourceBreakdown.map((f: { source: string; count: number }) => ({
                feed: f.source,
                itemsProcessed: Number(f.count),
                syncCount: syncCountMap[f.source] || syncCountMap['iocs'] || 0,
            })),
            totalIOCs: Number(totalIOCs[0]?.count || 0),
            timestamp: now.toISOString(),
        },
    });
});

export default router;
