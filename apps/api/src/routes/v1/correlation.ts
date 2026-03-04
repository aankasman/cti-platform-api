/**
 * Correlation API Routes
 *
 * Discover relationships between IOCs via CIDR, domain, campaign, and temporal analysis.
 */

import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../middleware/auth';
import { correlateIOC, runBatchCorrelation } from '../../services/correlation';
import { BatchCorrelationSchema } from '../../lib/schemas';

const correlationRoutes = new Hono();

correlationRoutes.use('*', requireAuth);

// ============================================================================
// IOC-Specific Correlation
// ============================================================================

/**
 * POST /v1/iocs/:iocId/correlate
 * Trigger correlation analysis for a specific IOC
 */
correlationRoutes.post('/iocs/:iocId/correlate', async (c) => {
    const { iocId } = c.req.param();

    const correlations = await correlateIOC(iocId);

    return c.json({
        success: true,
        data: {
            iocId,
            correlations,
            count: correlations.length,
        },
    });
});

/**
 * GET /v1/iocs/:iocId/correlations
 * Get stored correlations for an IOC (same as correlate, but named for read semantics)
 */
correlationRoutes.get('/iocs/:iocId/correlations', async (c) => {
    const { iocId } = c.req.param();

    const correlations = await correlateIOC(iocId);

    return c.json({
        success: true,
        data: {
            iocId,
            correlations,
            count: correlations.length,
        },
    });
});

// ============================================================================
// Batch Correlation
// ============================================================================

/**
 * POST /v1/correlation/batch
 * Trigger batch correlation for recent IOCs (admin only)
 */
correlationRoutes.post('/correlation/batch', requireRole('admin'), async (c) => {
    const { limit } = BatchCorrelationSchema.parse(c.req.query());

    const result = await runBatchCorrelation(limit);

    return c.json({
        success: true,
        data: result,
    });
});

export default correlationRoutes;
