/**
 * Ops System Health Route
 *
 * Infrastructure health check: PostgreSQL, Redis, OpenSearch, Neo4j.
 */

import { Hono } from 'hono';
import { db, sql } from '@rinjani/db';
import { connection as redisConnection } from '../../services/redis';
import { requireAuth } from '../../middleware/auth';
import { createLogger } from '../../lib/logger';

const router = new Hono();
const log = createLogger('Ops:system');

/** GET /system — Infrastructure health: PostgreSQL, Redis, OpenSearch, Neo4j */
router.get('/system', requireAuth, async (c) => {
    // Run ALL health checks in parallel using Promise.allSettled
    const [pgResult, redisResult, osResult, neo4jResult] = await Promise.allSettled([
        // PostgreSQL health
        (async () => {
            const startTime = Date.now();
            const pgResult = await db.execute(sql`
                    SELECT count(*) as active_connections,
                           (SELECT count(*) FROM pg_stat_activity WHERE state = 'idle') as idle_connections
                    FROM pg_stat_activity 
                    WHERE state = 'active'
                `);
            const pgRow = (pgResult as unknown as Record<string, unknown>[])[0] ?? {};
            return {
                status: 'healthy' as const,
                activeConnections: Number(pgRow.active_connections || 0),
                idleConnections: Number(pgRow.idle_connections || 0),
                queryLatencyMs: Date.now() - startTime,
            };
        })(),

        // Redis health
        (async () => {
            const redisInfo = await redisConnection.info('all');
            const parseInfo = (info: string, key: string): number => {
                const match = info.match(new RegExp(`${key}:(\\d+)`));
                return match ? parseInt(match[1], 10) : 0;
            };
            return {
                status: 'healthy' as const,
                memoryUsedMB: Math.round(parseInfo(redisInfo, 'used_memory') / 1024 / 1024),
                connectedClients: parseInfo(redisInfo, 'connected_clients'),
                opsPerSec: parseInfo(redisInfo, 'instantaneous_ops_per_sec'),
                uptime: parseInfo(redisInfo, 'uptime_in_seconds'),
            };
        })(),

        // OpenSearch health
        (async () => {
            const osUrl = process.env.OPENSEARCH_URL || 'http://localhost:9200';
            const [healthRes, statsRes] = await Promise.all([
                fetch(`${osUrl}/_cluster/health`, { headers: { 'Content-Type': 'application/json' } }),
                fetch(`${osUrl}/_stats`, { headers: { 'Content-Type': 'application/json' } }),
            ]);
            const health = healthRes.ok ? await healthRes.json() : {};
            const stats = statsRes.ok ? await statsRes.json() : {};
            return {
                status: (health.status || 'unknown') as string,
                clusterName: health.cluster_name || '',
                nodeCount: health.number_of_nodes || 0,
                indexCount: Object.keys(stats.indices || {}).length,
                documentCount: stats._all?.primaries?.docs?.count || 0,
                storeSizeGB: Math.round((stats._all?.primaries?.store?.size_in_bytes || 0) / 1024 / 1024 / 1024 * 100) / 100,
            };
        })(),

        // Neo4j health
        (async () => {
            const { checkNeo4jHealth } = await import('../../services/neo4j.js');
            const neo4jHealth = await checkNeo4jHealth();
            const metrics = { connected: neo4jHealth.connected, nodeCount: 0, relationshipCount: 0, iocCount: 0, serverInfo: neo4jHealth.serverInfo || '' };

            if (neo4jHealth.connected) {
                const { getNeo4jDriver } = await import('../../services/neo4j.js');
                const driver = getNeo4jDriver();
                const session = driver.session();
                try {
                    const countResult = await session.run(`
                            MATCH (n) WITH count(n) as nodes
                            MATCH ()-[r]->() WITH nodes, count(r) as rels
                            MATCH (i:IOC) RETURN nodes, rels, count(i) as iocs
                        `);
                    const record = countResult.records[0];
                    metrics.nodeCount = record?.get('nodes')?.toNumber?.() || Number(record?.get('nodes') || 0);
                    metrics.relationshipCount = record?.get('rels')?.toNumber?.() || Number(record?.get('rels') || 0);
                    metrics.iocCount = record?.get('iocs')?.toNumber?.() || Number(record?.get('iocs') || 0);
                } finally {
                    await session.close();
                }
            }
            return { status: neo4jHealth.connected ? 'healthy' : 'critical', ...metrics };
        })(),
    ]);

    // Extract results with fallbacks for failures
    const pg = pgResult.status === 'fulfilled'
        ? pgResult.value
        : { status: 'critical' as const, activeConnections: 0, idleConnections: 0, queryLatencyMs: 0 };
    const redis = redisResult.status === 'fulfilled'
        ? redisResult.value
        : { status: 'critical' as const, memoryUsedMB: 0, connectedClients: 0, opsPerSec: 0, uptime: 0 };
    const os = osResult.status === 'fulfilled'
        ? osResult.value
        : { status: 'critical', clusterName: '', nodeCount: 0, indexCount: 0, documentCount: 0, storeSizeGB: 0 };
    const neo4j = neo4jResult.status === 'fulfilled'
        ? neo4jResult.value
        : { status: 'critical', connected: false, nodeCount: 0, relationshipCount: 0, iocCount: 0, serverInfo: '' };

    // Log failures for debugging
    if (pgResult.status === 'rejected') log.warn('PostgreSQL health check failed', { error: (pgResult.reason as Error)?.message });
    if (redisResult.status === 'rejected') log.warn('Redis health check failed', { error: (redisResult.reason as Error)?.message });
    if (osResult.status === 'rejected') log.warn('OpenSearch health check failed', { error: (osResult.reason as Error)?.message });
    if (neo4jResult.status === 'rejected') log.warn('Neo4j health check failed', { error: (neo4jResult.reason as Error)?.message });

    // Overall status
    const statuses = [pg.status, redis.status, os.status, neo4j.status];
    const overallStatus =
        statuses.includes('critical') ? 'critical' :
            statuses.includes('yellow') || os.status === 'yellow' ? 'degraded' :
                'healthy';

    return c.json({
        success: true,
        data: {
            status: overallStatus,
            services: {
                postgresql: pg,
                redis,
                opensearch: os,
                neo4j,
            },
            timestamp: new Date().toISOString(),
        },
    });
});

export default router;
