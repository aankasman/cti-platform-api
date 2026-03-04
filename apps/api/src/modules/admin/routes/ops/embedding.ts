/**
 * Ops Embedding & Reindex Progress Route
 *
 * Real-time progress for embedding generation and OpenSearch reindexing.
 */

import { Hono } from 'hono';
import { getEmbeddingProgress } from '../../../../services/embedding';
import { getReindexProgress } from '../../../../services/opensearch/indexing';
import { getSchedulerStatus } from '../../../../services/scheduler';
import { requireAuth } from '../../../../middleware/auth';

const router = new Hono();

/** GET /embedding — Combined embedding + reindex + scheduler progress */
router.get('/embedding', requireAuth, async (c) => {
    return c.json({
        success: true,
        data: {
            embedding: getEmbeddingProgress(),
            reindex: getReindexProgress(),
            scheduler: getSchedulerStatus(),
            timestamp: new Date().toISOString(),
        },
    });
});

export default router;
