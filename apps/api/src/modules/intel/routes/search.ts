/**
 * Search Routes (Unified + Vector + Similar)
 *
 * Extracted from v1.ts — unified search, vector search, and similar document lookup.
 */

import { Hono } from 'hono';
import * as opensearch from '../../../services/opensearch';
import {
    UnifiedSearchSchema, VectorSearchSchema,
} from '../../../lib/schemas';
import { paginate } from './helpers';

const router = new Hono();

// ============================================================================
// Unified Search
// ============================================================================

router.get('/search', async (c) => {
    const { page, pageSize, q, type } = UnifiedSearchSchema.parse(c.req.query());

    if (!q) {
        return c.json({
            success: true,
            data: { query: q, items: [], pagination: paginate(page, pageSize, 0) },
        });
    }

    // Use OpenSearch for fast unified search across all entity types
    // When searching, sort by relevance (_score); when browsing, sort by date
    const result = await opensearch.unifiedSearch({
        query: q,
        filters: {
            ...(type ? { entityType: [type] } : {}),
        },
        sort: q ? { field: '_score', order: 'desc' } : { field: 'updatedAt', order: 'desc' },
        pagination: { page, limit: pageSize },
        aggregations: true,
    });

    return c.json({
        success: true,
        data: {
            query: q,
            items: result.items,
            pagination: paginate(page, pageSize, result.total),
            facets: result.facets,
            took: result.took,
        },
    });
});

// ============================================================================
// Vector Search (Semantic Similarity)
// ============================================================================

router.get('/search/vector', async (c) => {
    const { q: query, k, type: entityType } = VectorSearchSchema.parse(c.req.query());

    const result = await opensearch.vectorSearch(query, Math.min(k, 50), entityType);
    return c.json({
        success: true,
        data: {
            items: result.items,
            total: result.total,
            took: result.took,
        },
    });
});

router.get('/search/similar/:docId', async (c) => {
    const { docId } = c.req.param();
    const { k, type: entityType } = VectorSearchSchema.omit({ q: true }).parse(c.req.query());

    const result = await opensearch.findSimilar(docId, Math.min(k, 50), entityType);
    return c.json({
        success: true,
        data: {
            items: result.items,
            total: result.total,
            took: result.took,
        },
    });
});

export default router;
