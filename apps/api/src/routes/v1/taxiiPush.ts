/**
 * Outbound TAXII 2.1 push management.
 *
 *   GET    /v1/taxii/remote-targets             List targets + last-push status
 *   GET    /v1/taxii/remote-targets/:id         Single target detail
 *   POST   /v1/taxii/remote-targets             Register a new target
 *   PUT    /v1/taxii/remote-targets/:id         Update a target (partial)
 *   DELETE /v1/taxii/remote-targets/:id         Remove a target
 *   POST   /v1/taxii/remote-targets/:id/push    Trigger a push to that target now
 *   POST   /v1/taxii/push-all                   Trigger a push to every enabled target
 *
 * Inbound is /taxii2/* (separate router); this is outbound only.
 */
import { Hono } from 'hono';
import { db, eq, desc } from '@rinjani/db';
import { taxiiRemoteTargets } from '@rinjani/db/schema';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError } from '../../lib/errors';
import {
    TaxiiRemoteTargetCreateSchema, TaxiiRemoteTargetUpdateSchema,
} from '../../lib/schemas';
import { pushToTarget, pushToAllEnabledTargets } from '../../services/taxiiPushClient';

const router = new Hono();

// ── List ────────────────────────────────────────────────────────────

router.get('/taxii/remote-targets', requireAuth, async (c) => {
    const rows = await db.select().from(taxiiRemoteTargets).orderBy(desc(taxiiRemoteTargets.updatedAt));
    return c.json({ success: true, data: rows });
});

router.get('/taxii/remote-targets/:id', requireAuth, async (c) => {
    const id = c.req.param('id')!;
    const [row] = await db.select().from(taxiiRemoteTargets).where(eq(taxiiRemoteTargets.id, id)).limit(1);
    if (!row) throw new NotFoundError('TAXII remote target', id);
    return c.json({ success: true, data: row });
});

// ── Mutations (admin) ───────────────────────────────────────────────

router.post('/taxii/remote-targets', requireAuth, requireRole('admin'), async (c) => {
    const body = TaxiiRemoteTargetCreateSchema.parse(await c.req.json());
    const [row] = await db.insert(taxiiRemoteTargets).values({
        name: body.name,
        discoveryUrl: body.discoveryUrl,
        apiRoot: body.apiRoot,
        collectionId: body.collectionId,
        apiKeyRef: body.apiKeyRef ?? null,
        enabled: body.enabled,
        pushFilter: body.pushFilter,
    }).returning();
    return c.json({ success: true, data: row }, 201);
});

router.put('/taxii/remote-targets/:id', requireAuth, requireRole('admin'), async (c) => {
    const id = c.req.param('id')!;
    const body = TaxiiRemoteTargetUpdateSchema.parse(await c.req.json());

    const patch: Record<string, unknown> = { updatedAt: new Date() };
    if (body.name !== undefined) patch.name = body.name;
    if (body.discoveryUrl !== undefined) patch.discoveryUrl = body.discoveryUrl;
    if (body.apiRoot !== undefined) patch.apiRoot = body.apiRoot;
    if (body.collectionId !== undefined) patch.collectionId = body.collectionId;
    if (body.apiKeyRef !== undefined) patch.apiKeyRef = body.apiKeyRef;
    if (body.enabled !== undefined) patch.enabled = body.enabled;
    if (body.pushFilter !== undefined) patch.pushFilter = body.pushFilter;

    const [row] = await db.update(taxiiRemoteTargets).set(patch).where(eq(taxiiRemoteTargets.id, id)).returning();
    if (!row) throw new NotFoundError('TAXII remote target', id);
    return c.json({ success: true, data: row });
});

router.delete('/taxii/remote-targets/:id', requireAuth, requireRole('admin'), async (c) => {
    const id = c.req.param('id')!;
    const removed = await db.delete(taxiiRemoteTargets).where(eq(taxiiRemoteTargets.id, id)).returning({ id: taxiiRemoteTargets.id });
    if (removed.length === 0) throw new NotFoundError('TAXII remote target', id);
    return c.json({ success: true, message: `TAXII remote target ${id} deleted` });
});

// ── Push ────────────────────────────────────────────────────────────

router.post('/taxii/remote-targets/:id/push', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const id = c.req.param('id')!;
    const result = await pushToTarget(id);
    return c.json({ success: result.success, data: result }, result.success ? 200 : 502);
});

router.post('/taxii/push-all', requireAuth, requireRole('admin'), async (c) => {
    const results = await pushToAllEnabledTargets();
    const successCount = results.filter(r => r.success).length;
    return c.json({
        success: successCount === results.length,
        data: {
            attempted: results.length,
            succeeded: successCount,
            failed: results.length - successCount,
            results,
        },
    }, successCount === results.length ? 200 : 207);
});

export default router;
