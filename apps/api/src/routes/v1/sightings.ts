/**
 * Sightings API Routes
 *
 * Track IOC observations in the wild with confidence scoring.
 */

import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../middleware/auth';
import { ValidationError, NotFoundError } from '../../lib/errors';
import { AddSightingSchema, SightingListSchema, SightingFeedSchema } from '../../lib/schemas';
import {
    addSighting,
    getSightingsForIOC,
    getRecentSightings,
    getSightingStats,
} from '../../services/sightings';

const sightingRoutes = new Hono();

/** API-key auth produces non-UUID ids like "key:xxx" — guard before FK insert */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

sightingRoutes.use('*', requireAuth);

// ============================================================================
// IOC-Specific Sightings
// ============================================================================

/**
 * POST /v1/iocs/:iocId/sightings
 * Report a sighting of an IOC
 */
sightingRoutes.post('/iocs/:iocId/sightings', async (c) => {
    const { iocId } = c.req.param();
    const body = AddSightingSchema.parse(await c.req.json().catch(() => ({})));

    const userId = c.get('user')?.id;

    const sighting = await addSighting({
        iocId,
        type: body.type,
        source: body.source,
        description: body.description,
        confidence: body.confidence,
        count: body.count,
        observedAt: body.observedAt,
        createdBy: userId && UUID_RE.test(userId) ? userId : undefined,
    });

    return c.json({
        success: true,
        data: sighting,
    }, 201);
});

/**
 * GET /v1/iocs/:iocId/sightings
 * List sightings for a specific IOC
 */
sightingRoutes.get('/iocs/:iocId/sightings', async (c) => {
    const { iocId } = c.req.param();
    const { limit, offset } = SightingListSchema.parse(c.req.query());

    const result = await getSightingsForIOC(iocId, limit, offset);

    return c.json({
        success: true,
        data: {
            items: result.items,
            total: result.total,
            limit,
            offset,
        },
    });
});

// ============================================================================
// Global Sightings
// ============================================================================

/**
 * GET /v1/sightings/recent
 * Global feed of most recent sightings
 */
sightingRoutes.get('/sightings/recent', async (c) => {
    const { limit } = SightingFeedSchema.parse(c.req.query());
    const items = await getRecentSightings(limit);

    return c.json({
        success: true,
        data: { items, count: items.length },
    });
});

/**
 * GET /v1/sightings/stats
 * Sighting statistics (optionally filtered by IOC)
 */
sightingRoutes.get('/sightings/stats', async (c) => {
    const { iocId } = SightingFeedSchema.parse(c.req.query());
    const stats = await getSightingStats(iocId);

    return c.json({
        success: true,
        data: stats,
    });
});

export default sightingRoutes;
