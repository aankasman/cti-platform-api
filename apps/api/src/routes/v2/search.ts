/**
 * V2 OpenSearch Routes
 *
 * Unified search, health, reindex, init, recreate endpoints.
 */

import { Hono } from 'hono';
import {
    unifiedSearch,
    reindexAll,
    checkHealth,
    createIndices,
    recreateIndex,
    SearchOptions
} from '../../services/opensearch';
import { requireAuth, requireRole } from '../../middleware/auth';

const searchRoutes = new Hono();

/**
 * POST /search
 * Unified full-text search across IOCs, vulnerabilities, and actors
 */
searchRoutes.post('/', async (c) => {
    const startTime = Date.now();
    const body = await c.req.json();

    const options: SearchOptions = {
        query: body.query || '',
        filters: body.filters || {},
        sort: body.sort || { field: 'updatedAt', order: 'desc' },
        pagination: {
            page: body.pagination?.page || 1,
            limit: Math.min(body.pagination?.limit || 25, 500),
        },
        aggregations: body.aggregations !== false,
    };

    const result = await unifiedSearch(options);

    return c.json({
        success: true,
        data: {
            query: options.query,
            items: result.items,
            facets: result.facets,
            pagination: {
                page: options.pagination?.page || 1,
                limit: options.pagination?.limit || 25,
                total: result.total,
                pages: Math.ceil(result.total / (options.pagination?.limit || 25)),
            },
        },
        meta: {
            requestId: crypto.randomUUID(),
            took: result.took,
            totalTime: Date.now() - startTime,
        },
    });
});

/**
 * GET /search/health
 * Check OpenSearch health
 */
searchRoutes.get('/health', async (c) => {
    const health = await checkHealth();
    return c.json({
        success: true,
        data: health,
    });
});

/**
 * POST /search/reindex
 * Reindex all data from PostgreSQL to OpenSearch (admin only)
 */
searchRoutes.post('/reindex', requireAuth, requireRole('admin'), async (c) => {
    const result = await reindexAll();
    return c.json({
        success: true,
        data: {
            indexed: result,
            message: 'Reindexing completed',
        },
    });
});

/**
 * POST /search/init
 * Initialize OpenSearch indices (admin only)
 */
searchRoutes.post('/init', requireAuth, requireRole('admin'), async (c) => {
    await createIndices();
    return c.json({
        success: true,
        message: 'Indices created',
    });
});

/**
 * POST /search/recreate
 * Delete and recreate OpenSearch index with knn_vector mapping, then reindex with embeddings (admin only)
 * ⚠️ This is a destructive operation — all data will be re-indexed from PostgreSQL
 */
searchRoutes.post('/recreate', requireAuth, requireRole('admin'), async (c) => {
    const result = await recreateIndex();
    return c.json({
        success: true,
        data: {
            indexed: result,
            message: 'Index recreated with vector mapping and data reindexed with embeddings',
        },
    });
});

export default searchRoutes;
