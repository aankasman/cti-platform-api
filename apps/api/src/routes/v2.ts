/**
 * API v2 Router — Barrel
 *
 * Mounts sub-routers:
 *   - v2/search.ts   → OpenSearch unified search
 *   - v2/ai.ts       → AI analysis
 *   - v2/threats.ts  → Threats/indicators stubs
 *   - stix.ts        → STIX export
 *   - bulk.ts        → Bulk operations
 *   - graph.ts       → Graph explorer
 */

import { Hono } from 'hono';
import stixRouter from './stix';
import bulkRouter from './bulk';
import graphRouter from './graph';
import searchRoutes from './v2/search';
import aiRoutes from './v2/ai';
import { threatRoutes, indicatorRoutes } from './v2/threats';

const v2 = new Hono();

// Mount sub-routers
v2.route('/stix', stixRouter);
v2.route('/bulk', bulkRouter);
v2.route('/graph', graphRouter);
v2.route('/search', searchRoutes);
v2.route('/ai', aiRoutes);
v2.route('/threats', threatRoutes);
v2.route('/indicators', indicatorRoutes);

// API info
v2.get('/', (c) => {
    return c.json({
        version: 'v2',
        status: 'stable',
        features: ['STIX 2.1 export', 'OpenSearch full-text search', 'bulk operations', 'Neo4j graph explorer', 'AI analysis'],
        endpoints: {
            threats: '/v2/threats',
            indicators: '/v2/indicators',
            search: '/v2/search',
            bulk: '/v2/bulk',
            stix: '/v2/stix',
            graph: '/v2/graph',
            ai: '/v2/ai',
        },
    });
});

export default v2;
