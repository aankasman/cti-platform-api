/**
 * Sparkline Data Route — Time-series data for KPI sparklines
 *
 * Primary: queries Prometheus for rate data over time
 * Fallback: queries PostgreSQL created_at histograms
 *
 * GET /v1/ops/sparkline?entity=iocs|vulns|actors&range=24h|7d|30d
 */

import { Hono } from 'hono';
import { createLogger } from '../../lib/logger';

const log = createLogger('Sparkline');
const router = new Hono();

// Prometheus metric name per entity
const PROM_METRICS: Record<string, string> = {
    iocs: 'rinjani_iocs_total',
    vulns: 'rinjani_vulnerabilities_total',
    actors: 'rinjani_threat_actors_total',
    malware: 'rinjani_malware_total',
    galaxy_clusters: 'rinjani_galaxy_clusters_total',
    detection_rules: 'rinjani_detection_rules_total',
    relationships: 'rinjani_relationships_total',
};

// PostgreSQL table name per entity
const PG_TABLES: Record<string, string> = {
    iocs: 'iocs',
    vulns: 'vulnerabilities',
    actors: 'threat_actors',
    malware: 'malware',
    galaxy_clusters: 'galaxy_clusters',
    detection_rules: 'detection_rules',
    relationships: 'relationships',
};

// Range to seconds/step mapping
const RANGE_CONFIG: Record<string, { seconds: number; step: string; pgTrunc: string; points: number }> = {
    '24h': { seconds: 86400, step: '1h', pgTrunc: 'hour', points: 24 },
    '7d': { seconds: 604800, step: '6h', pgTrunc: 'day', points: 28 },
    '30d': { seconds: 2592000, step: '1d', pgTrunc: 'day', points: 30 },
};

const PROMETHEUS_URL = process.env.PROMETHEUS_URL || 'http://v3-prometheus:9090';

/**
 * Try to get sparkline data from Prometheus
 */
async function queryPrometheus(metricName: string, range: string): Promise<Array<{ t: string; v: number }> | null> {
    const config = RANGE_CONFIG[range] || RANGE_CONFIG['24h'];
    const query = `${metricName}`;
    const end = Math.floor(Date.now() / 1000);
    const start = end - config.seconds;

    try {
        const url = `${PROMETHEUS_URL}/api/v1/query_range?query=${encodeURIComponent(query)}&start=${start}&end=${end}&step=${config.step}`;
        const res = await fetch(url, { signal: AbortSignal.timeout(3000) });

        if (!res.ok) return null;

        const data = await res.json() as {
            status: string;
            data: {
                resultType: string;
                result: Array<{
                    metric: Record<string, string>;
                    values: Array<[number, string]>;
                }>;
            };
        };

        if (data.status !== 'success' || !data.data?.result?.length) return null;

        // Extract the first series (there should be only one for a gauge)
        const values = data.data.result[0].values;
        return values.map(([ts, val]) => ({
            t: new Date(ts * 1000).toISOString(),
            v: parseFloat(val),
        }));
    } catch (err) {
        log.debug('Prometheus query failed, falling back to PostgreSQL', {
            error: (err as Error).message,
        });
        return null;
    }
}

/**
 * Fallback: get sparkline data from PostgreSQL
 */
async function queryPostgres(table: string, range: string): Promise<Array<{ t: string; v: number }>> {
    const config = RANGE_CONFIG[range] || RANGE_CONFIG['24h'];

    try {
        const { db, sql } = await import('@rinjani/db');

        // Use db.execute with a raw SQL string for dynamic table/interval
        const query = `
            WITH series AS (
                SELECT generate_series(
                    date_trunc('${config.pgTrunc}', NOW() - interval '${config.seconds} seconds'),
                    date_trunc('${config.pgTrunc}', NOW()),
                    interval '1 ${config.pgTrunc}'
                ) AS bucket
            )
            SELECT
                s.bucket AS t,
                COALESCE(COUNT(d.created_at), 0) AS v
            FROM series s
            LEFT JOIN ${table} d ON date_trunc('${config.pgTrunc}', d.created_at) = s.bucket
            GROUP BY s.bucket
            ORDER BY s.bucket ASC
        `;

        const result = await db.execute(sql.raw(query));
        const rows = result as unknown as Record<string, unknown>[];

        return (rows || []).map((row) => ({
            t: new Date(row.t as string).toISOString(),
            v: Number(row.v || 0),
        }));
    } catch (err) {
        log.warn('PostgreSQL sparkline fallback failed', {
            table,
            error: (err as Error).message,
        });
        return [];
    }
}

/**
 * GET /ops/sparkline
 *
 * Query params:
 *   entity: iocs | vulns | actors | malware | galaxy_clusters | detection_rules | relationships
 *   range: 24h | 7d | 30d (default: 24h)
 *   source: prometheus | postgres | auto (default: auto)
 */
router.get('/sparkline', async (c) => {
    const entity = c.req.query('entity') || 'iocs';
    const range = c.req.query('range') || '24h';
    const source = c.req.query('source') || 'auto';

    const metricName = PROM_METRICS[entity];
    const tableName = PG_TABLES[entity];

    if (!metricName && !tableName) {
        return c.json({ success: false, error: { code: 'INVALID_ENTITY', message: `Unknown entity: ${entity}` } }, 400);
    }

    let points: Array<{ t: string; v: number }> = [];
    let dataSource = 'none';

    // Try Prometheus first (unless explicitly postgres)
    if (source !== 'postgres' && metricName) {
        const promData = await queryPrometheus(metricName, range);
        if (promData && promData.length > 0) {
            points = promData;
            dataSource = 'prometheus';
        }
    }

    // Fallback to PostgreSQL
    if (points.length === 0 && tableName && source !== 'prometheus') {
        points = await queryPostgres(tableName, range);
        dataSource = points.length > 0 ? 'postgres' : 'none';
    }

    return c.json({
        success: true,
        data: {
            entity,
            range,
            source: dataSource,
            points,
        },
    });
});

export default router;
