/**
 * Warninglists API Routes
 *
 * CRUD + IOC checking against curated benign indicator lists.
 */

import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../../middleware/auth';
import { ValidationError, NotFoundError } from '../../../lib/errors';
import {
    CreateWarninglistSchema, UpdateWarninglistSchema,
    WarninglistEntriesSchema, WarninglistCheckSchema,
} from '../../../lib/schemas';
import { z } from 'zod';
import {
    getWarninglists,
    getWarninglistById,
    createWarninglist,
    updateWarninglist,
    deleteWarninglist,
    addEntries,
    removeEntries,
    checkAgainstWarninglists,
    seedDefaults,
} from '../../../services/warninglists';

const warninglistRoutes = new Hono();

warninglistRoutes.use('*', requireAuth);

// ============================================================================
// CRUD
// ============================================================================

/**
 * GET /v1/warninglists
 * List all warninglists with entry counts
 */
warninglistRoutes.get('/', async (c) => {
    const { enabled } = z.object({ enabled: z.enum(['true', 'false']).optional() }).parse(c.req.query());
    const enabledOnly = enabled === 'true';
    const lists = await getWarninglists(enabledOnly);

    return c.json({
        success: true,
        data: { items: lists, count: lists.length },
    });
});

/**
 * POST /v1/warninglists
 * Create a new warninglist
 */
warninglistRoutes.post('/', requireRole('admin'), async (c) => {
    const body = CreateWarninglistSchema.parse(await c.req.json());

    const wl = await createWarninglist(body);

    if (body.entries && body.entries.length > 0) {
        await addEntries(wl.id, body.entries);
    }

    return c.json({
        success: true,
        data: wl,
    }, 201);
});

/**
 * GET /v1/warninglists/:id
 * Get warninglist details with entries
 */
warninglistRoutes.get('/:id', async (c) => {
    const { id } = c.req.param();
    const wl = await getWarninglistById(id);

    if (!wl) throw new NotFoundError('Warninglist', id);

    return c.json({
        success: true,
        data: wl,
    });
});

/**
 * PUT /v1/warninglists/:id
 * Update a warninglist
 */
warninglistRoutes.put('/:id', requireRole('admin'), async (c) => {
    const { id } = c.req.param();
    const body = UpdateWarninglistSchema.parse(await c.req.json());

    const wl = await updateWarninglist(id, body);
    if (!wl) throw new NotFoundError('Warninglist', id);

    return c.json({
        success: true,
        data: wl,
    });
});

/**
 * DELETE /v1/warninglists/:id
 * Delete a warninglist
 */
warninglistRoutes.delete('/:id', requireRole('admin'), async (c) => {
    const { id } = c.req.param();
    const existing = await getWarninglistById(id);
    if (!existing) throw new NotFoundError('Warninglist', id);

    await deleteWarninglist(id);

    return c.json({
        success: true,
        message: 'Warninglist deleted',
    });
});

// ============================================================================
// Entry Management
// ============================================================================

/**
 * POST /v1/warninglists/:id/entries
 * Add entries to a warninglist
 */
warninglistRoutes.post('/:id/entries', requireRole('admin', 'analyst'), async (c) => {
    const { id } = c.req.param();
    const { values } = WarninglistEntriesSchema.parse(await c.req.json());

    const existing = await getWarninglistById(id);
    if (!existing) throw new NotFoundError('Warninglist', id);

    const added = await addEntries(id, values);

    return c.json({
        success: true,
        data: { added },
    });
});

/**
 * DELETE /v1/warninglists/:id/entries
 * Remove entries from a warninglist
 */
warninglistRoutes.delete('/:id/entries', requireRole('admin', 'analyst'), async (c) => {
    const { id } = c.req.param();
    const { values } = WarninglistEntriesSchema.parse(await c.req.json());

    const removed = await removeEntries(id, values);

    return c.json({
        success: true,
        data: { removed },
    });
});

// ============================================================================
// IOC Checking
// ============================================================================

/**
 * POST /v1/warninglists/check
 * Check a value against all enabled warninglists
 */
warninglistRoutes.post('/check', async (c) => {
    const { value, type } = WarninglistCheckSchema.parse(await c.req.json());

    const matches = await checkAgainstWarninglists(value, type);

    return c.json({
        success: true,
        data: {
            value,
            isWarningListed: matches.length > 0,
            matches,
        },
    });
});

// ============================================================================
// Seed Defaults
// ============================================================================

/**
 * POST /v1/warninglists/seed
 * Seed default warninglists (RFC1918, public DNS, CDNs, etc.)
 */
warninglistRoutes.post('/seed', requireRole('admin'), async (c) => {
    const result = await seedDefaults();

    return c.json({
        success: true,
        data: result,
    });
});

export default warninglistRoutes;
