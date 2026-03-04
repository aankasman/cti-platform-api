/**
 * Health, Info & API Docs Routes
 *
 * Top-level endpoints that don't belong to a versioned API.
 */

import { Hono } from 'hono';
import { getSwaggerUIHTML, getOpenAPISpec } from '../../../openapi';

const router = new Hono();

/** GET /healthz — Lightweight liveness probe (no DB, always 200 if process is up) */
router.get('/healthz', (c) => {
    return c.json({
        status: 'alive',
        timestamp: new Date().toISOString(),
    }, 200);
});

/** GET /health — Queries all 4 databases for real connectivity status */
router.get('/health', async (c) => {
    try {
        const { healthCheckAll } = await import('../../../lib/db/clients');
        const health = await healthCheckAll();

        return c.json({
            status: health.healthy ? 'healthy' : 'degraded',
            version: '1.0.0',
            timestamp: new Date().toISOString(),
            services: {
                postgres: health.postgres ? 'up' : 'down',
                redis: health.redis ? 'up' : 'down',
                neo4j: health.neo4j ? 'up' : 'down',
                opensearch: health.opensearch ? 'up' : 'down',
            },
        }, health.healthy ? 200 : 503);
    } catch {
        return c.json({
            status: 'unknown',
            version: '1.0.0',
            timestamp: new Date().toISOString(),
        }, 200);
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
