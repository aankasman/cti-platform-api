/**
 * Monitoring — Feed Health Routes
 */

import { Hono } from 'hono';
import { db, desc, eq, gte, sql } from '@rinjani/db';
import { syncLogs } from '@rinjani/db/schema';
import { NotFoundError } from '../../lib/errors';

const feedRoutes = new Hono();

/**
 * GET /v1/monitoring/feeds
 * Get health status for all feeds
 */
feedRoutes.get('/feeds', async (c) => {
    // Get latest sync for each feed
    const latestSyncs = await db
        .select({
            entityType: syncLogs.entityType,
            status: syncLogs.status,
            itemsProcessed: syncLogs.itemsProcessed,
            itemsFailed: syncLogs.itemsFailed,
            errorMessage: syncLogs.errorMessage,
            startedAt: syncLogs.startedAt,
            completedAt: syncLogs.completedAt,
            duration: sql<number>`EXTRACT(EPOCH FROM (${syncLogs.completedAt} - ${syncLogs.startedAt}))`,
        })
        .from(syncLogs)
        .orderBy(desc(syncLogs.createdAt))
        .limit(100);

    // Group by entity type and get latest
    const feedMap = new Map();
    for (const sync of latestSyncs) {
        if (!feedMap.has(sync.entityType)) {
            feedMap.set(sync.entityType, sync);
        }
    }

    const feeds = Array.from(feedMap.values()).map((sync) => {
        const successRate = sync.itemsProcessed + sync.itemsFailed > 0
            ? (sync.itemsProcessed / (sync.itemsProcessed + sync.itemsFailed)) * 100
            : 0;

        // Determine health status
        let health = 'healthy';
        if (sync.status === 'error') health = 'critical';
        else if (sync.status === 'partial') health = 'warning';
        else if (successRate < 90) health = 'warning';

        return {
            feed: sync.entityType,
            health,
            status: sync.status,
            lastSync: sync.completedAt,
            itemsProcessed: sync.itemsProcessed,
            itemsFailed: sync.itemsFailed,
            successRate: Math.round(successRate),
            duration: Math.round(sync.duration || 0),
            errorMessage: sync.errorMessage,
        };
    });

    return c.json({
        success: true,
        data: {
            feeds,
            summary: {
                total: feeds.length,
                healthy: feeds.filter(f => f.health === 'healthy').length,
                warning: feeds.filter(f => f.health === 'warning').length,
                critical: feeds.filter(f => f.health === 'critical').length,
            },
        },
    });
});

/**
 * GET /v1/monitoring/feeds/:feedId
 * Get detailed status for a specific feed
 */
feedRoutes.get('/feeds/:feedId', async (c) => {
    const feedId = c.req.param('feedId');

    // Get last 10 syncs for this feed
    const syncs = await db
        .select({
            id: syncLogs.id,
            status: syncLogs.status,
            itemsProcessed: syncLogs.itemsProcessed,
            itemsFailed: syncLogs.itemsFailed,
            errorMessage: syncLogs.errorMessage,
            startedAt: syncLogs.startedAt,
            completedAt: syncLogs.completedAt,
            duration: sql<number>`EXTRACT(EPOCH FROM (${syncLogs.completedAt} - ${syncLogs.startedAt}))`,
        })
        .from(syncLogs)
        .where(eq(syncLogs.entityType, feedId))
        .orderBy(desc(syncLogs.createdAt))
        .limit(10);

    if (syncs.length === 0) {
        throw new NotFoundError('Feed', feedId);
    }

    const latest = syncs[0];
    const itemsProcessed = latest.itemsProcessed ?? 0;
    const itemsFailed = latest.itemsFailed ?? 0;
    const successRate = itemsProcessed + itemsFailed > 0
        ? (itemsProcessed / (itemsProcessed + itemsFailed)) * 100
        : 0;

    return c.json({
        success: true,
        data: {
            feed: feedId,
            latest: {
                status: latest.status,
                lastSync: latest.completedAt,
                itemsProcessed: latest.itemsProcessed,
                itemsFailed: latest.itemsFailed,
                successRate: Math.round(successRate),
                duration: Math.round(latest.duration || 0),
                errorMessage: latest.errorMessage,
            },
            history: syncs.map(s => ({
                timestamp: s.completedAt,
                status: s.status,
                itemsProcessed: s.itemsProcessed,
                itemsFailed: s.itemsFailed,
                duration: Math.round(s.duration || 0),
            })),
        },
    });
});

export default feedRoutes;
