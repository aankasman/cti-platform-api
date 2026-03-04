/**
 * Monitoring — Performance Metrics Routes
 */

import { Hono } from 'hono';
import { count, db, gte, sql } from '@rinjani/db';
import { syncLogs, iocs, vulnerabilities } from '@rinjani/db/schema';
import { DaysQuerySchema, MetricsGrowthQuerySchema } from '../../lib/schemas';

const metricsRoutes = new Hono();

/**
 * GET /v1/monitoring/metrics/growth
 * Get IOC and vulnerability growth metrics
 * Query params:
 *   - days: number of days (default 7)
 *   - granularity: 'day' or 'hour' (default 'day')
 */
metricsRoutes.get('/metrics/growth', async (c) => {
    const { days } = DaysQuerySchema.parse(c.req.query());
    const { granularity } = MetricsGrowthQuerySchema.parse(c.req.query());
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    let iocGrowth;
    let vulnGrowth;

    if (granularity === 'hour') {
        // Get IOC growth by hour
        iocGrowth = await db
            .select({
                date: sql<string>`DATE_TRUNC('hour', ${iocs.createdAt})`,
                count: count(),
            })
            .from(iocs)
            .where(gte(iocs.createdAt, startDate))
            .groupBy(sql`DATE_TRUNC('hour', ${iocs.createdAt})`)
            .orderBy(sql`DATE_TRUNC('hour', ${iocs.createdAt})`);

        // Get vulnerability growth by hour
        vulnGrowth = await db
            .select({
                date: sql<string>`DATE_TRUNC('hour', ${vulnerabilities.createdAt})`,
                count: count(),
            })
            .from(vulnerabilities)
            .where(gte(vulnerabilities.createdAt, startDate))
            .groupBy(sql`DATE_TRUNC('hour', ${vulnerabilities.createdAt})`)
            .orderBy(sql`DATE_TRUNC('hour', ${vulnerabilities.createdAt})`);
    } else {
        // Get IOC growth by day
        iocGrowth = await db
            .select({
                date: sql<string>`DATE(${iocs.createdAt})`,
                count: count(),
            })
            .from(iocs)
            .where(gte(iocs.createdAt, startDate))
            .groupBy(sql`DATE(${iocs.createdAt})`)
            .orderBy(sql`DATE(${iocs.createdAt})`);

        // Get vulnerability growth by day
        vulnGrowth = await db
            .select({
                date: sql<string>`DATE(${vulnerabilities.createdAt})`,
                count: count(),
            })
            .from(vulnerabilities)
            .where(gte(vulnerabilities.createdAt, startDate))
            .groupBy(sql`DATE(${vulnerabilities.createdAt})`)
            .orderBy(sql`DATE(${vulnerabilities.createdAt})`);
    }

    return c.json({
        success: true,
        data: {
            period: `${days} ${granularity === 'hour' ? 'day(s) hourly' : 'days'}`,
            granularity,
            iocs: iocGrowth,
            vulnerabilities: vulnGrowth,
        },
    });
});

/**
 * GET /v1/monitoring/metrics/performance
 * Get sync performance metrics
 */
metricsRoutes.get('/metrics/performance', async (c) => {
    const { days } = DaysQuerySchema.parse(c.req.query());
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const performance = await db
        .select({
            feed: syncLogs.entityType,
            avgDuration: sql<number>`AVG(EXTRACT(EPOCH FROM (${syncLogs.completedAt} - ${syncLogs.startedAt})))`,
            avgItems: sql<number>`AVG(${syncLogs.itemsProcessed})`,
            totalSyncs: count(),
        })
        .from(syncLogs)
        .where(gte(syncLogs.createdAt, startDate))
        .groupBy(syncLogs.entityType);

    return c.json({
        success: true,
        data: {
            period: `${days} days`,
            feeds: performance.map((p) => ({
                feed: p.feed,
                avgDuration: Math.round(p.avgDuration || 0),
                avgItems: Math.round(p.avgItems || 0),
                totalSyncs: p.totalSyncs,
                itemsPerSecond: p.avgDuration > 0
                    ? Math.round((p.avgItems || 0) / (p.avgDuration || 1))
                    : 0,
            })),
        },
    });
});

/**
 * GET /v1/monitoring/metrics/errors
 * Get error rate metrics
 */
metricsRoutes.get('/metrics/errors', async (c) => {
    const { days } = DaysQuerySchema.parse(c.req.query());
    const startDate = new Date();
    startDate.setDate(startDate.getDate() - days);

    const errors = await db
        .select({
            feed: syncLogs.entityType,
            totalSyncs: count(),
            errorCount: sql<number>`COUNT(CASE WHEN ${syncLogs.status} = 'error' THEN 1 END)`,
            partialCount: sql<number>`COUNT(CASE WHEN ${syncLogs.status} = 'partial' THEN 1 END)`,
        })
        .from(syncLogs)
        .where(gte(syncLogs.createdAt, startDate))
        .groupBy(syncLogs.entityType);

    return c.json({
        success: true,
        data: {
            period: `${days} days`,
            feeds: errors.map((e) => ({
                feed: e.feed,
                totalSyncs: e.totalSyncs,
                errors: e.errorCount,
                partial: e.partialCount,
                errorRate: e.totalSyncs > 0
                    ? Math.round((e.errorCount / e.totalSyncs) * 100)
                    : 0,
            })),
        },
    });
});

export default metricsRoutes;
