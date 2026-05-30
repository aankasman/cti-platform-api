/**
 * Stats & Monitoring Routes
 *
 * Extracted from v1.ts — aggregated counts, distribution, heatmap,
 * tactics, and feed/system health monitoring.
 */

import { Hono } from 'hono';
import { count, db, desc, sql, rawQuery } from '@rinjani/db';
import type { RawQueryResult } from '@rinjani/db';
import { pulses, indicators, syncLogs, threatActors } from '@rinjani/db/schema';
// `iocs` / `vulnerabilities` / `feed_sync_runs` are queried via `rawQuery`
// below — Drizzle schema imports aren't needed for the SQL-string path.
import * as opensearch from '../../services/opensearch';
import { DaysQuerySchema } from '../../lib/schemas';

const router = new Hono();

// ============================================================================
// Stats
// ============================================================================

router.get('/stats', async (c) => {
    // `?days=N` is optional — when present, the response also includes
    // `windowCounts` (new arrivals within the last N days). `counts`
    // remains total-of-record so older clients keep working unchanged.
    // The command dashboard uses `windowCounts` for the KPI tile values
    // when the user has picked 24H/7D/30D on the rolling-window switch.
    const daysRaw = c.req.query('days');
    const daysParam = daysRaw != null ? Number(daysRaw) : null;
    const days = daysParam != null && Number.isFinite(daysParam) && daysParam > 0
        ? Math.min(Math.floor(daysParam), 365)
        : null;

    const [counts, [pulseCount], [indicatorCount], recentSyncs, windowCounts] = await Promise.all([
        opensearch.getCounts(),
        db.select({ count: count() }).from(pulses),
        db.select({ count: count() }).from(indicators),
        db.select().from(syncLogs).orderBy(desc(syncLogs.completedAt)).limit(5),
        days != null ? getWindowCounts(days) : Promise.resolve(null),
    ]);

    return c.json({
        success: true,
        data: {
            counts: {
                vulnerabilities: counts.vulnerabilities,
                iocs: counts.iocs,
                pulses: pulseCount.count,
                threatActors: counts.actors,
                indicators: indicatorCount.count,
            },
            // Only present when `?days=N` is passed. Shape mirrors `counts`
            // so the frontend can swap one for the other without
            // re-mapping fields.
            ...(windowCounts != null && { windowCounts, windowDays: days }),
            recentSyncs,
        },
    });
});

/**
 * Counts of records that arrived (or were last-seen, for actors) within
 * the last N days. Same shape as the `counts` object so the frontend can
 * use either interchangeably.
 *
 *   • iocs/vulnerabilities/pulses/indicators — bucket by `created_at`
 *     (when the row landed in our DB).
 *   • threatActors — bucket by `last_seen` (when MITRE / OTX last saw
 *     activity for the actor). `created_at` would lie because actors
 *     get seeded en-masse on MITRE sync and most days would read zero.
 */
async function getWindowCounts(days: number): Promise<{
    vulnerabilities: number;
    iocs: number;
    pulses: number;
    threatActors: number;
    indicators: number;
}> {
    const result = await rawQuery<{
        iocs: number;
        vulnerabilities: number;
        pulses: number;
        threat_actors: number;
        indicators: number;
    }>(sql`
        SELECT
            (SELECT COUNT(*)::int FROM iocs WHERE created_at > now() - (${days}::int * interval '1 day'))            AS iocs,
            (SELECT COUNT(*)::int FROM vulnerabilities WHERE created_at > now() - (${days}::int * interval '1 day')) AS vulnerabilities,
            (SELECT COUNT(*)::int FROM pulses WHERE created_at > now() - (${days}::int * interval '1 day'))          AS pulses,
            (SELECT COUNT(*)::int FROM threat_actors WHERE last_seen > now() - (${days}::int * interval '1 day'))    AS threat_actors,
            (SELECT COUNT(*)::int FROM indicators WHERE created_at > now() - (${days}::int * interval '1 day'))      AS indicators
    `);
    const row = result.rows[0] ?? {
        iocs: 0, vulnerabilities: 0, pulses: 0, threat_actors: 0, indicators: 0,
    };
    return {
        vulnerabilities: Number(row.vulnerabilities),
        iocs: Number(row.iocs),
        pulses: Number(row.pulses),
        threatActors: Number(row.threat_actors),
        indicators: Number(row.indicators),
    };
}

/**
 * GET /v1/stats/sparklines?days=7
 *
 * Daily-bucketed counts for the four overview KPI tiles, so the dashboard
 * can render a Workbench-style mini-trend next to each headline number.
 *
 * Series are zero-filled — a quiet day on a given metric returns `0` for
 * that bucket rather than dropping the index, so frontend sparklines render
 * with a constant array length regardless of activity.
 *
 *   iocs           — new IOCs created per day (iocs.created_at)
 *   vulnerabilities — new vulns created per day (vulnerabilities.created_at)
 *   threatActors   — actors observed per day (threat_actors.last_seen) — proxy
 *                    for "active actors". Using created_at is misleading
 *                    because actors are seeded en-masse by MITRE sync, so
 *                    most days would be flat zero.
 *   feedSyncs      — successful feed-sync runs per day (feed_sync_runs.started_at, status='completed')
 *
 * The shape is intentionally small (4 × ~7-30 ints) so this is cheap to
 * fetch alongside the existing /stats call from the overview page.
 */
router.get('/stats/sparklines', async (c) => {
    const { days } = DaysQuerySchema.parse(c.req.query());

    // One SQL trip per metric — cheap (indexed timestamp range + GROUP BY day).
    // Could be Promise.all'd, but the connection pool can serialize them just
    // as fast for under-1ms per query at our row counts.
    const series = await Promise.all([
        bucketDaily('iocs', 'created_at', days),
        bucketDaily('vulnerabilities', 'created_at', days),
        bucketDaily('threat_actors', 'last_seen', days),
        bucketDailyFeedSyncs(days),
    ]);

    return c.json({
        success: true,
        data: {
            days,
            iocs:            series[0],
            vulnerabilities: series[1],
            threatActors:    series[2],
            feedSyncs:       series[3],
        },
    });
});

/**
 * Generic daily bucketing helper. `table` and `column` are NOT user input —
 * they are hardcoded identifiers from the call sites above. The day series
 * is generated via `generate_series` so missing days return 0 (left-join).
 */
async function bucketDaily(
    table: 'iocs' | 'vulnerabilities' | 'threat_actors',
    column: 'created_at' | 'last_seen',
    days: number,
): Promise<number[]> {
    const result = await rawQuery(`
        WITH d AS (
            SELECT generate_series(
                date_trunc('day', NOW()) - INTERVAL '${days - 1} days',
                date_trunc('day', NOW()),
                INTERVAL '1 day'
            )::date AS day
        )
        SELECT
            d.day,
            COALESCE(COUNT(t.${column}), 0)::int AS n
        FROM d
        LEFT JOIN ${table} t
            ON date_trunc('day', t.${column}) = d.day
        GROUP BY d.day
        ORDER BY d.day ASC
    `) as RawQueryResult<{ day: string; n: number }>;
    return result.rows.map(r => Number(r.n));
}

/**
 * `feed_sync_runs` has a different shape — bucketing by `started_at` and
 * filtering by `status='completed'` so we count successful sync runs, not
 * failed ones. The latter are visible on /admin/services.
 */
async function bucketDailyFeedSyncs(days: number): Promise<number[]> {
    const result = await rawQuery(`
        WITH d AS (
            SELECT generate_series(
                date_trunc('day', NOW()) - INTERVAL '${days - 1} days',
                date_trunc('day', NOW()),
                INTERVAL '1 day'
            )::date AS day
        )
        SELECT
            d.day,
            COALESCE(COUNT(r.started_at) FILTER (WHERE r.status = 'completed'), 0)::int AS n
        FROM d
        LEFT JOIN feed_sync_runs r
            ON date_trunc('day', r.started_at) = d.day
        GROUP BY d.day
        ORDER BY d.day ASC
    `) as RawQueryResult<{ day: string; n: number }>;
    return result.rows.map(r => Number(r.n));
}

/**
 * GET /v1/stats/distribution
 * Get IOC distribution by type
 */
router.get('/stats/distribution', async (c) => {
    const { days } = DaysQuerySchema.parse(c.req.query());
    const distribution = await opensearch.getIOCDistribution(days);
    return c.json({ success: true, data: distribution });
});

/**
 * GET /v1/stats/severity-trend
 * Get severity distribution over time (last 30 days)
 */
router.get('/stats/severity-trend', async (c) => {
    const { days } = DaysQuerySchema.parse(c.req.query());
    const data = await opensearch.getDateHistogram(days);
    return c.json({ success: true, data });
});

/**
 * GET /v1/stats/source-breakdown
 * Get IOC count by source
 */
router.get('/stats/source-breakdown', async (c) => {
    const { days } = DaysQuerySchema.parse(c.req.query());
    const breakdown = await opensearch.getSourceBreakdown(days);
    return c.json({ success: true, data: breakdown });
});

/**
 * GET /v1/stats/threat-heatmap
 * Get IOC distribution by type and severity
 */
router.get('/stats/threat-heatmap', async (c) => {
    const { days } = DaysQuerySchema.parse(c.req.query());
    const heatmapData = await opensearch.getThreatHeatmap(days);
    return c.json({ success: true, data: heatmapData });
});

// ============================================================================
// MITRE ATT&CK - Tactics
// ============================================================================

router.get('/tactics', async (c) => {
    const items = await db.execute(sql`SELECT * FROM tactics ORDER BY mitre_id`) as unknown as Record<string, unknown>[];
    return c.json({
        success: true,
        data: { items, total: items.length },
    });
});

// ============================================================================
// Monitoring & Alerting
// ============================================================================

/**
 * GET /v1/monitoring/feeds
 * Get health status for all feeds
 */
router.get('/monitoring/feeds', async (c) => {
    // Use DISTINCT ON to get only the latest sync per entity_type directly in SQL
    const latestSyncs = await db.execute(sql`
        SELECT DISTINCT ON (entity_type)
            entity_type,
            status,
            items_processed,
            items_failed,
            error_message,
            started_at,
            completed_at,
            EXTRACT(EPOCH FROM (completed_at - started_at)) as duration
        FROM sync_logs
        ORDER BY entity_type, created_at DESC
    `) as unknown as RawQueryResult;

    const feeds = (Array.isArray(latestSyncs) ? latestSyncs : latestSyncs.rows || []).map((sync: Record<string, unknown>) => {
        const itemsProcessed = Number(sync.items_processed || 0);
        const itemsFailed = Number(sync.items_failed || 0);
        const successRate = itemsProcessed + itemsFailed > 0
            ? (itemsProcessed / (itemsProcessed + itemsFailed)) * 100
            : 0;

        let health = 'healthy';
        if (sync.status === 'error') health = 'critical';
        else if (sync.status === 'partial') health = 'warning';
        else if (successRate < 90) health = 'warning';

        return {
            feed: sync.entity_type,
            health,
            status: sync.status,
            lastSync: sync.completed_at,
            itemsProcessed,
            itemsFailed,
            successRate: Math.round(successRate),
            duration: Math.round(Number(sync.duration) || 0),
            errorMessage: sync.error_message,
        };
    });

    return c.json({
        success: true,
        data: {
            feeds,
            summary: {
                total: feeds.length,
                healthy: feeds.filter((f: { health: string }) => f.health === 'healthy').length,
                warning: feeds.filter((f: { health: string }) => f.health === 'warning').length,
                critical: feeds.filter((f: { health: string }) => f.health === 'critical').length,
            },
        },
    });
});

/**
 * GET /v1/monitoring/health
 * Get overall system health
 */
router.get('/monitoring/health', async (c) => {
    const oneDayAgo = new Date();
    oneDayAgo.setDate(oneDayAgo.getDate() - 1);

    const recentSyncs = await db
        .select({ status: syncLogs.status })
        .from(syncLogs)
        .where(sql`${syncLogs.createdAt} >= ${oneDayAgo.toISOString()}`);

    const totalSyncs = recentSyncs.length;
    const failedSyncs = recentSyncs.filter(s => s.status === 'error').length;
    const partialSyncs = recentSyncs.filter(s => s.status === 'partial').length;

    let overallHealth = 'healthy';
    const failureRate = totalSyncs > 0 ? (failedSyncs / totalSyncs) * 100 : 0;

    if (failureRate > 20) overallHealth = 'critical';
    else if (failureRate > 10 || partialSyncs > 5) overallHealth = 'degraded';

    return c.json({
        success: true,
        data: {
            status: overallHealth,
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

/**
 * GET /v1/stats/freshness
 * Get per-category latest record timestamp and per-feed last sync info.
 * Powers the "Data as of" freshness banners in explorer pages.
 */
router.get('/stats/freshness', async (c) => {
    const [iocFreshness, vulnFreshness, actorFreshness, actorCount, feedSyncs] = await Promise.all([
        opensearch.unifiedSearch({
            query: '', filters: { entityType: ['ioc'] },
            sort: { field: 'updatedAt', order: 'desc' },
            pagination: { page: 1, limit: 1 }, aggregations: false,
        }),
        opensearch.unifiedSearch({
            query: '', filters: { entityType: ['vulnerability'] },
            sort: { field: 'updatedAt', order: 'desc' },
            pagination: { page: 1, limit: 1 }, aggregations: false,
        }),
        db.select({ updatedAt: threatActors.updatedAt })
            .from(threatActors)
            .orderBy(desc(threatActors.updatedAt))
            .limit(1),
        db.select({ count: count() }).from(threatActors),
        db.execute(sql`
            SELECT DISTINCT ON (entity_type)
                entity_type, completed_at, status
            FROM sync_logs
            ORDER BY entity_type, created_at DESC
        `) as unknown as RawQueryResult,
    ]);

    const feedRows = Array.isArray(feedSyncs) ? feedSyncs : feedSyncs.rows || [];

    return c.json({
        success: true,
        data: {
            categories: {
                iocs: { latestRecord: iocFreshness.items[0]?.updatedAt || null, total: iocFreshness.total },
                vulnerabilities: { latestRecord: vulnFreshness.items[0]?.updatedAt || null, total: vulnFreshness.total },
                actors: { latestRecord: actorFreshness[0]?.updatedAt || null, total: actorCount[0]?.count ?? 0 },
            },
            feeds: feedRows.map((f: Record<string, unknown>) => ({
                feed: f.entity_type,
                lastSync: f.completed_at,
                status: f.status,
            })),
            timestamp: new Date().toISOString(),
        },
    });
});

/**
 * GET /v1/stats/trending-tags?days=30&limit=8
 *
 * Top IOC tags from the last N days. Powers the "Trending Now" search
 * sidebar and the command page's trending panel. `days` defaults to 30
 * — the original hardcoded window — so older clients see no change.
 */
router.get('/stats/trending-tags', async (c) => {
    const limit = Math.min(Number(c.req.query('limit') || '8'), 20);
    const daysRaw = Number(c.req.query('days') || '30');
    const days = Math.max(1, Math.min(Math.floor(daysRaw) || 30, 365));
    const rows = await db.execute(sql`
        SELECT tag, cnt FROM (
            SELECT unnest(tags) as tag, count(*) as cnt
            FROM iocs
            WHERE tags IS NOT NULL AND array_length(tags,1) > 0
              AND created_at > now() - (${days}::int * interval '1 day')
            GROUP BY tag
        ) sub
        WHERE tag <> '' AND length(tag) > 1
        ORDER BY cnt DESC
        LIMIT ${limit}
    `) as unknown as Array<{ tag: string; cnt: number }>;

    // A tag is "hot" if it has notable absolute volume AND sits within 70% of
    // the leader's count. Adapts to the dataset — flat distributions surface
    // multiple hot tags, dominant leaders mark only the spike. During low-
    // volume windows nothing is hot (which is honest).
    const counts = (Array.isArray(rows) ? rows : []).map(r => Number(r.cnt));
    const top = counts[0] ?? 0;
    const HOT_MIN_ABS = 100;
    const HOT_REL_THRESHOLD = 0.7;
    const hotFloor = Math.max(HOT_MIN_ABS, top * HOT_REL_THRESHOLD);

    const tags = (Array.isArray(rows) ? rows : []).map((r) => {
        const count = Number(r.cnt);
        return {
            tag: String(r.tag),
            count,
            hot: count >= hotFloor,
        };
    });

    return c.json({ success: true, data: tags });
});

export default router;
