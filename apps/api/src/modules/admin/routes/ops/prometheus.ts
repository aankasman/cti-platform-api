/**
 * Ops Prometheus Metrics Route
 *
 * Exposes metrics in Prometheus text format for scraping.
 * Combines OTEL counters, application-level stats, and infrastructure health.
 */

import { Hono } from 'hono';
import { getMetricsSnapshot } from '../../../../telemetry/otel';
import { createLogger } from '../../../../lib/logger';

const log = createLogger('Prometheus');
const router = new Hono();

// Helper: format a single metric line
function metric(name: string, type: 'counter' | 'gauge', help: string, value: number, labels?: Record<string, string>): string {
    const labelStr = labels
        ? `{${Object.entries(labels).map(([k, v]) => `${k}="${v}"`).join(',')}}`
        : '';
    return [
        `# HELP ${name} ${help}`,
        `# TYPE ${name} ${type}`,
        `${name}${labelStr} ${value}`,
    ].join('\n');
}

/**
 * GET /ops/metrics/prometheus
 * Prometheus scrape endpoint — returns text/plain metrics
 */
router.get('/metrics/prometheus', async (c) => {
    const snapshot = getMetricsSnapshot();
    const sections: string[] = [];

    // ========================================================================
    // HTTP Metrics
    // ========================================================================
    sections.push(metric('rinjani_http_requests_total', 'counter', 'Total HTTP requests processed', snapshot.requestCount));
    sections.push(metric('rinjani_http_errors_total', 'counter', 'Total HTTP errors', snapshot.errorCount));
    sections.push(metric('rinjani_http_response_time_avg_ms', 'gauge', 'Average HTTP response time in ms', snapshot.avgResponseTime));
    sections.push(metric('rinjani_http_active_connections', 'gauge', 'Current active connections', snapshot.activeConnections));

    // ========================================================================
    // Database Entity Counts
    // ========================================================================
    let dbStats = { totalActors: 0, totalVulns: 0, totalIOCs: 0 };
    try {
        const { db, sql } = await import('@rinjani/db');
        const { threatActors, vulnerabilities, iocs } = await import('@rinjani/db/schema');

        const [actorCount] = await db.select({ count: sql<number>`count(*)` }).from(threatActors);
        const [vulnCount] = await db.select({ count: sql<number>`count(*)` }).from(vulnerabilities);
        const [iocCount] = await db.select({ count: sql<number>`count(*)` }).from(iocs);

        dbStats = {
            totalActors: Number(actorCount?.count || 0),
            totalVulns: Number(vulnCount?.count || 0),
            totalIOCs: Number(iocCount?.count || 0),
        };
    } catch (err) {
        log.warn('Failed to get DB stats for Prometheus', { error: (err as Error).message });
    }

    sections.push(metric('rinjani_threat_actors_total', 'gauge', 'Total threat actors in database', dbStats.totalActors));
    sections.push(metric('rinjani_vulnerabilities_total', 'gauge', 'Total vulnerabilities in database', dbStats.totalVulns));
    sections.push(metric('rinjani_iocs_total', 'gauge', 'Total IOCs in database', dbStats.totalIOCs));

    // ========================================================================
    // Enrichment Queue
    // ========================================================================
    let queueStats = { active: 0, waiting: 0, completed: 0, failed: 0 };
    try {
        const { enrichmentQueue } = await import('../../../../queues');
        if (enrichmentQueue) {
            const counts = await enrichmentQueue.getJobCounts();
            queueStats = {
                active: counts.active || 0,
                waiting: counts.waiting || 0,
                completed: counts.completed || 0,
                failed: counts.failed || 0,
            };
        }
    } catch {
        // Queue may not be available
    }

    sections.push(metric('rinjani_queue_active', 'gauge', 'Active jobs in enrichment queue', queueStats.active));
    sections.push(metric('rinjani_queue_waiting', 'gauge', 'Waiting jobs in enrichment queue', queueStats.waiting));
    sections.push(metric('rinjani_queue_completed', 'counter', 'Completed jobs in enrichment queue', queueStats.completed));
    sections.push(metric('rinjani_queue_failed', 'counter', 'Failed jobs in enrichment queue', queueStats.failed));

    // ========================================================================
    // PostgreSQL Health
    // ========================================================================
    try {
        const { db, sql } = await import('@rinjani/db');
        const startTime = Date.now();
        const pgResult = await db.execute(sql`
            SELECT count(*) as active_connections,
                   (SELECT count(*) FROM pg_stat_activity WHERE state = 'idle') as idle_connections
            FROM pg_stat_activity WHERE state = 'active'
        `);
        const latency = Date.now() - startTime;
        const pgRow = (pgResult as unknown as Record<string, unknown>[])[0] ?? {};

        sections.push(metric('rinjani_postgres_status', 'gauge', 'PostgreSQL reachability (1=up, 0=down)', 1));
        sections.push(metric('rinjani_postgres_active_connections', 'gauge', 'PostgreSQL active connections', Number(pgRow.active_connections || 0)));
        sections.push(metric('rinjani_postgres_idle_connections', 'gauge', 'PostgreSQL idle connections', Number(pgRow.idle_connections || 0)));
        sections.push(metric('rinjani_postgres_query_latency_ms', 'gauge', 'PostgreSQL query latency in ms', latency));
    } catch {
        sections.push(metric('rinjani_postgres_status', 'gauge', 'PostgreSQL reachability (1=up, 0=down)', 0));
    }

    // ========================================================================
    // Redis Health
    // ========================================================================
    try {
        const { connection: redisConnection } = await import('../../../../services/redis');
        const redisInfo = await redisConnection.info('all');
        const parseInfo = (info: string, key: string): number => {
            const match = info.match(new RegExp(`${key}:(\\d+)`));
            return match ? parseInt(match[1], 10) : 0;
        };

        sections.push(metric('rinjani_redis_status', 'gauge', 'Redis reachability (1=up, 0=down)', 1));
        sections.push(metric('rinjani_redis_memory_bytes', 'gauge', 'Redis used memory in bytes', parseInfo(redisInfo, 'used_memory')));
        sections.push(metric('rinjani_redis_connected_clients', 'gauge', 'Redis connected clients', parseInfo(redisInfo, 'connected_clients')));
        sections.push(metric('rinjani_redis_ops_per_second', 'gauge', 'Redis instantaneous ops/sec', parseInfo(redisInfo, 'instantaneous_ops_per_sec')));
    } catch {
        sections.push(metric('rinjani_redis_status', 'gauge', 'Redis reachability (1=up, 0=down)', 0));
    }

    // ========================================================================
    // OpenSearch Health
    // ========================================================================
    try {
        const osUrl = process.env.OPENSEARCH_URL || 'http://localhost:9200';
        const [healthRes, statsRes] = await Promise.all([
            fetch(`${osUrl}/_cluster/health`, { headers: { 'Content-Type': 'application/json' } }),
            fetch(`${osUrl}/_stats`, { headers: { 'Content-Type': 'application/json' } }),
        ]);
        const health = healthRes.ok ? await healthRes.json() as Record<string, unknown> : {} as Record<string, unknown>;
        const stats = statsRes.ok ? await statsRes.json() as Record<string, unknown> : {} as Record<string, unknown>;
        const allStats = (stats as Record<string, Record<string, Record<string, Record<string, unknown>>>>)?._all;

        const statusMap: Record<string, number> = { green: 1, yellow: 1, red: 0 };
        sections.push(metric('rinjani_opensearch_status', 'gauge', 'OpenSearch reachability (1=up, 0=down)', statusMap[health.status as string] ?? 0));
        sections.push(metric('rinjani_opensearch_node_count', 'gauge', 'OpenSearch node count', Number(health.number_of_nodes || 0)));
        sections.push(metric('rinjani_opensearch_document_count', 'gauge', 'OpenSearch total document count', Number(allStats?.primaries?.docs?.count || 0)));
        sections.push(metric('rinjani_opensearch_store_size_bytes', 'gauge', 'OpenSearch total store size in bytes', Number(allStats?.primaries?.store?.size_in_bytes || 0)));
    } catch {
        sections.push(metric('rinjani_opensearch_status', 'gauge', 'OpenSearch reachability (1=up, 0=down)', 0));
    }

    // ========================================================================
    // Neo4j Health
    // ========================================================================
    try {
        const { checkNeo4jHealth } = await import('../../../../services/neo4j.js');
        const neo4jHealth = await checkNeo4jHealth();

        if (neo4jHealth.connected) {
            sections.push(metric('rinjani_neo4j_status', 'gauge', 'Neo4j reachability (1=up, 0=down)', 1));

            const { getNeo4jDriver } = await import('../../../../services/neo4j.js');
            const driver = getNeo4jDriver();
            const session = driver.session();
            try {
                const result = await session.run(`
                    MATCH (n) WITH count(n) as nodes
                    MATCH ()-[r]->() RETURN nodes, count(r) as rels
                `);
                const record = result.records[0];
                sections.push(metric('rinjani_neo4j_node_count', 'gauge', 'Neo4j total node count', Number(record?.get('nodes') || 0)));
                sections.push(metric('rinjani_neo4j_relationship_count', 'gauge', 'Neo4j total relationship count', Number(record?.get('rels') || 0)));
            } finally {
                await session.close();
            }
        } else {
            sections.push(metric('rinjani_neo4j_status', 'gauge', 'Neo4j reachability (1=up, 0=down)', 0));
        }
    } catch {
        sections.push(metric('rinjani_neo4j_status', 'gauge', 'Neo4j reachability (1=up, 0=down)', 0));
    }

    // ========================================================================
    // Process Metrics
    // ========================================================================
    const memUsage = process.memoryUsage();
    sections.push(metric('rinjani_process_memory_rss_bytes', 'gauge', 'Process RSS memory in bytes', memUsage.rss));
    sections.push(metric('rinjani_process_memory_heap_used_bytes', 'gauge', 'Process heap used in bytes', memUsage.heapUsed));
    sections.push(metric('rinjani_process_memory_heap_total_bytes', 'gauge', 'Process heap total in bytes', memUsage.heapTotal));
    sections.push(metric('rinjani_process_uptime_seconds', 'gauge', 'Process uptime in seconds', Math.floor(process.uptime())));

    // ========================================================================
    // Rate Limiting Metrics
    // ========================================================================
    try {
        const { cacheConnection } = await import('../../../../services/redis');
        const exceeded = Number(await cacheConnection.get('rjn:rl:exceeded:total') || 0);
        const abused = Number(await cacheConnection.get('rjn:rl:abuse:total') || 0);

        // Count active penalty keys via SCAN
        let activePenalties = 0;
        let cursor = '0';
        do {
            const [newCursor, keys] = await cacheConnection.scan(cursor, 'MATCH', 'rjn:abuse:*', 'COUNT', '100');
            cursor = newCursor;
            activePenalties += keys.length;
        } while (cursor !== '0');

        sections.push(metric('rinjani_rate_limit_exceeded_total', 'counter', 'Total rate limit 429 responses', exceeded));
        sections.push(metric('rinjani_rate_limit_abuse_total', 'counter', 'Total abuse penalties applied', abused));
        sections.push(metric('rinjani_rate_limit_abuse_penalties_active', 'gauge', 'Currently active abuse penalty keys', activePenalties));
    } catch {
        sections.push(metric('rinjani_rate_limit_exceeded_total', 'counter', 'Total rate limit 429 responses', 0));
    }

    // ========================================================================
    // Info
    // ========================================================================
    sections.push(metric('rinjani_info', 'gauge', 'Rinjani API info', 1, { version: '3.0.0', service: 'rinjani-api' }));

    c.header('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    return c.text(sections.join('\n\n') + '\n');
});

export default router;
