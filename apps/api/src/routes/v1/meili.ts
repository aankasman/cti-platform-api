/**
 * MeiliSearch Instant Search Routes
 *
 * Exposes MeiliSearch's typo-tolerant instant search as REST endpoints.
 * Falls back gracefully when MeiliSearch is unavailable.
 */

import { Hono } from 'hono';
import { meiliSearch } from '../../services/meilisearch';
import { createLogger } from '../../lib/logger';

const log = createLogger('MeiliRoutes');
const meili = new Hono();

// ============================================================================
// GET /search/instant?q=emotet&limit=20&filter=type:ioc
// ============================================================================
meili.get('/search/instant', async (c) => {
    const q = c.req.query('q') || '';
    const limit = parseInt(c.req.query('limit') || '20', 10);
    const offset = parseInt(c.req.query('offset') || '0', 10);
    const filter = c.req.query('filter') || undefined;
    const sort = c.req.query('sort')?.split(',') || undefined;

    if (!q.trim()) {
        return c.json({ data: { hits: [], query: '', processingTimeMs: 0, estimatedTotalHits: 0 } });
    }

    const result = await meiliSearch.search(q, { limit, offset, filter, sort });
    return c.json({ data: result });
});

// ============================================================================
// GET /search/instant/stats
// ============================================================================
meili.get('/search/instant/stats', async (c) => {
    const available = await meiliSearch.isAvailable();
    if (!available) {
        return c.json({ data: { available: false, numberOfDocuments: 0, isIndexing: false } });
    }

    const stats = await meiliSearch.getStats();
    return c.json({ data: { available: true, ...stats } });
});

// ============================================================================
// POST /search/instant/reindex — trigger full reindex from OpenSearch
// ============================================================================
meili.post('/search/instant/reindex', async (c) => {
    const available = await meiliSearch.isAvailable();
    if (!available) {
        return c.json({ data: { success: false, message: 'MeiliSearch unavailable' } }, 503);
    }

    // Re-initialize the index settings
    await meiliSearch.setupIndex();
    log.info('MeiliSearch reindex triggered');
    return c.json({ data: { success: true, message: 'Index settings refreshed. Documents will sync via stream consumers.' } });
});

export default meili;
