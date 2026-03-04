/**
 * Playbooks API Routes
 *
 * CRUD and execution management for event-driven automation rules.
 */

import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../../middleware/auth';
import { ValidationError, NotFoundError } from '../../../lib/errors';
import { CreatePlaybookSchema, UpdatePlaybookSchema, ExecutePlaybookSchema, LimitOffsetSchema } from '../../../lib/schemas';
import { z } from 'zod';

/** API-key auth produces non-UUID ids like "key:xxx" — guard before FK insert */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
import {
    getPlaybooks,
    getPlaybookById,
    createPlaybook,
    updatePlaybook,
    deletePlaybook,
    executePlaybook,
    getExecutions,
} from '../../../services/playbooks';

const playbookRoutes = new Hono();

playbookRoutes.use('*', requireAuth);

// ============================================================================
// CRUD
// ============================================================================

/**
 * GET /v1/playbooks
 * List all playbooks
 */
playbookRoutes.get('/', async (c) => {
    const { enabled } = z.object({ enabled: z.enum(['true', 'false']).optional() }).parse(c.req.query());
    const enabledOnly = enabled === 'true';
    const items = await getPlaybooks(enabledOnly);

    return c.json({
        success: true,
        data: { items, count: items.length },
    });
});

/**
 * POST /v1/playbooks
 * Create a new playbook
 */
playbookRoutes.post('/', requireRole('admin', 'analyst'), async (c) => {
    const body = CreatePlaybookSchema.parse(await c.req.json());

    const userId = c.get('user')?.id;

    const pb = await createPlaybook({
        name: body.name,
        description: body.description,
        triggerEvent: body.triggerEvent,
        conditions: body.conditions,
        actions: body.actions,
        createdBy: userId && UUID_RE.test(userId) ? userId : undefined,
    });

    return c.json({
        success: true,
        data: pb,
    }, 201);
});

/**
 * GET /v1/playbooks/:id
 * Get playbook details
 */
playbookRoutes.get('/:id', async (c) => {
    const { id } = c.req.param();
    const pb = await getPlaybookById(id);

    if (!pb) throw new NotFoundError('Playbook', id);

    return c.json({
        success: true,
        data: pb,
    });
});

/**
 * PUT /v1/playbooks/:id
 * Update a playbook
 */
playbookRoutes.put('/:id', requireRole('admin', 'analyst'), async (c) => {
    const { id } = c.req.param();
    const body = UpdatePlaybookSchema.parse(await c.req.json());

    const pb = await updatePlaybook(id, body);
    if (!pb) throw new NotFoundError('Playbook', id);

    return c.json({
        success: true,
        data: pb,
    });
});

/**
 * DELETE /v1/playbooks/:id
 * Delete a playbook
 */
playbookRoutes.delete('/:id', requireRole('admin'), async (c) => {
    const { id } = c.req.param();
    const existing = await getPlaybookById(id);
    if (!existing) throw new NotFoundError('Playbook', id);

    await deletePlaybook(id);

    return c.json({
        success: true,
        message: 'Playbook deleted',
    });
});

// ============================================================================
// Execution
// ============================================================================

/**
 * POST /v1/playbooks/:id/execute
 * Manually trigger a playbook execution
 */
playbookRoutes.post('/:id/execute', requireRole('admin', 'analyst'), async (c) => {
    const { id } = c.req.param();
    const { triggerData } = ExecutePlaybookSchema.parse(await c.req.json().catch(() => ({})));

    const pb = await getPlaybookById(id);
    if (!pb) throw new NotFoundError('Playbook', id);

    const result = await executePlaybook(id, triggerData);

    return c.json({
        success: true,
        data: result,
    });
});

/**
 * GET /v1/playbooks/:id/executions
 * Get execution history for a playbook
 */
playbookRoutes.get('/:id/executions', async (c) => {
    const { id } = c.req.param();
    const { limit, offset } = LimitOffsetSchema.parse(c.req.query());

    const pb = await getPlaybookById(id);
    if (!pb) throw new NotFoundError('Playbook', id);

    const result = await getExecutions(id, limit, offset);

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

export default playbookRoutes;
