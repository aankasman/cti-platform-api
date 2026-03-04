/**
 * Health, Readiness, Info & API Docs Routes
 *
 * Top-level endpoints that don't belong to a versioned API.
 * Enhanced with split Redis health (cache + queue), latency reporting,
 * and a readiness probe for Kubernetes/Docker health checks.
 */

import { Hono } from 'hono';
import { getSwaggerUIHTML, getOpenAPISpec } from '../openapi';

const router = new Hono();

/** GET /healthz — Lightweight liveness probe (no DB, always 200 if process is up) */
router.get('/healthz', (c) => {
    return c.json({
        status: 'alive',
        timestamp: new Date().toISOString(),
    }, 200);
});

/**
 * GET /health — Full dependency health check with latency reporting.
 * Queries all databases and both Redis instances.
 */
router.get('/health', async (c) => {
    try {
        const { healthCheckAll } = await import('../lib/db/clients');
        const { checkRedisHealth } = await import('../services/redis');

        const [dbHealth, redisHealth] = await Promise.all([
            healthCheckAll(),
            checkRedisHealth(),
        ]);

        const allHealthy = dbHealth.healthy
            && redisHealth.cache.connected
            && redisHealth.queue.connected;

        return c.json({
            status: allHealthy ? 'healthy' : 'degraded',
            version: '1.0.0',
            timestamp: new Date().toISOString(),
            services: {
                postgres: {
                    status: dbHealth.postgres ? 'up' : 'down',
                },
                redis_cache: {
                    status: redisHealth.cache.connected ? 'up' : 'down',
                    latency_ms: redisHealth.cache.latency,
                },
                redis_queue: {
                    status: redisHealth.queue.connected ? 'up' : 'down',
                    latency_ms: redisHealth.queue.latency,
                },
                neo4j: {
                    status: dbHealth.neo4j ? 'up' : 'down',
                },
                opensearch: {
                    status: dbHealth.opensearch ? 'up' : 'down',
                },
            },
        }, allHealthy ? 200 : 503);
    } catch {
        return c.json({
            status: 'unknown',
            version: '1.0.0',
            timestamp: new Date().toISOString(),
        }, 200);
    }
});

/**
 * GET /readyz — Readiness probe for Kubernetes/Docker orchestration.
 * Returns 200 only when ALL critical services are ready (Postgres + Redis Queue).
 * Non-critical services (Neo4j, OpenSearch, Redis Cache) are reported but don't block readiness.
 */
router.get('/readyz', async (c) => {
    try {
        const { healthCheckAll } = await import('../lib/db/clients');
        const { checkRedisHealth } = await import('../services/redis');

        const [dbHealth, redisHealth] = await Promise.all([
            healthCheckAll(),
            checkRedisHealth(),
        ]);

        // Critical: Postgres + Redis Queue must be up
        const ready = dbHealth.postgres && redisHealth.queue.connected;

        return c.json({
            ready,
            timestamp: new Date().toISOString(),
            critical: {
                postgres: dbHealth.postgres ? 'ready' : 'not_ready',
                redis_queue: redisHealth.queue.connected ? 'ready' : 'not_ready',
            },
            optional: {
                redis_cache: redisHealth.cache.connected ? 'ready' : 'not_ready',
                neo4j: dbHealth.neo4j ? 'ready' : 'not_ready',
                opensearch: dbHealth.opensearch ? 'ready' : 'not_ready',
            },
        }, ready ? 200 : 503);
    } catch {
        return c.json({ ready: false, timestamp: new Date().toISOString() }, 503);
    }
});

/** GET / — API info */
router.get('/', (c) => {
    return c.json({
        name: 'RinjaniAnalytics API',
        version: '1.0.0',
        description: 'Rinjani Analytics Threat Intelligence API',
        endpoints: {
            v1: '/v1',
            v2: '/v2',
            auth: '/auth',
            opengate: '/opengate',
            admin: '/admin',
            queues: '/admin/queues',
            alerts: '/v1/alerts',
            health: '/health',
            healthz: '/healthz',
            readyz: '/readyz',
            graphql: '/graphql',
            docs: '/api-docs',
        },
    });
});

/** GET /api-docs — Swagger UI */
router.get('/api-docs', (c) => {
    return c.html(getSwaggerUIHTML('/api-docs/openapi.json'));
});

/** GET /api-docs/openapi.json — OpenAPI spec */
router.get('/api-docs/openapi.json', (c) => {
    return c.json(getOpenAPISpec());
});

export default router;
