/**
 * IOC Comments & Annotations — Collaborative analyst notes
 *
 * Inspired by TheHive and Cortex comment systems.
 * Per-entity threaded comments with visibility controls and pinning.
 *
 * Mounts at: /v1/comments/*
 */

import { Hono } from 'hono';
import { rawQuery, sql } from '@rinjani/db';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError } from '../../lib/errors';
import { createLogger } from '../../lib/logger';
import { CreateCommentSchema, UpdateCommentSchema } from '../../lib/schemas';

const log = createLogger('Comments');
const router = new Hono();
router.use('*', requireAuth);

const ensureOnce = (() => {
    let done = false;
    return async () => {
        if (done) return;
        await rawQuery(sql.raw(`
            CREATE TABLE IF NOT EXISTS entity_comments (
                id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                content TEXT NOT NULL,
                visibility TEXT NOT NULL DEFAULT 'public',
                pinned BOOLEAN NOT NULL DEFAULT false,
                author_id TEXT,
                author_name TEXT,
                edited_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_comments_entity ON entity_comments(entity_type, entity_id);
        `));
        done = true;
    };
})();

const esc = (s: string) => s.replace(/'/g, "''");

// POST /comments — Create comment on any entity
router.post('/comments', async (c) => {
    await ensureOnce();
    const body = CreateCommentSchema.parse(await c.req.json().catch(() => ({})));
    const user = c.get('user') || {} as Record<string, unknown>;
    const result = await rawQuery(sql.raw(`
        INSERT INTO entity_comments (entity_type, entity_id, content, visibility, pinned, author_id, author_name)
        VALUES ('${esc(body.entityType)}', '${esc(body.entityId)}', '${esc(body.content)}',
                '${esc(body.visibility)}', ${body.pinned},
                '${esc(String(user.id || 'unknown'))}', '${esc(String(user.name || 'Unknown'))}')
        RETURNING *
    `));
    return c.json({ success: true, data: result.rows?.[0] }, 201);
});

// GET /comments?entityType=ioc&entityId=xxx — List comments for entity
router.get('/comments', async (c) => {
    await ensureOnce();
    const entityType = c.req.query('entityType') || '';
    const entityId = c.req.query('entityId') || '';
    if (!entityType || !entityId) {
        return c.json({ success: false, error: 'entityType and entityId required' }, 400);
    }
    const result = await rawQuery(sql.raw(`
        SELECT * FROM entity_comments
        WHERE entity_type = '${esc(entityType)}' AND entity_id = '${esc(entityId)}'
        ORDER BY pinned DESC, created_at DESC LIMIT 100
    `));
    return c.json({ success: true, data: result.rows || [] });
});

// PUT /comments/:id — Update comment
router.put('/comments/:id', async (c) => {
    await ensureOnce();
    const { id } = c.req.param();
    const body = UpdateCommentSchema.parse(await c.req.json().catch(() => ({})));
    const sets: string[] = ['edited_at = NOW()'];
    if (body.content) sets.push(`content = '${esc(body.content)}'`);
    if (body.visibility) sets.push(`visibility = '${esc(body.visibility)}'`);
    if (body.pinned !== undefined) sets.push(`pinned = ${body.pinned}`);
    const result = await rawQuery(sql.raw(`UPDATE entity_comments SET ${sets.join(', ')} WHERE id = '${esc(id)}' RETURNING *`));
    if (!result.rows?.[0]) throw new NotFoundError('Comment', id);
    return c.json({ success: true, data: result.rows[0] });
});

// DELETE /comments/:id — Delete comment
router.delete('/comments/:id', async (c) => {
    await ensureOnce();
    const { id } = c.req.param();
    const result = await rawQuery(sql.raw(`DELETE FROM entity_comments WHERE id = '${esc(id)}' RETURNING id`));
    if (!result.rows?.[0]) throw new NotFoundError('Comment', id);
    return c.json({ success: true, data: { id, deleted: true } });
});

// GET /comments/recent — Recent comments across all entities
router.get('/comments/recent', async (c) => {
    await ensureOnce();
    const limit = Math.min(parseInt(c.req.query('limit') || '20', 10), 100);
    const result = await rawQuery(sql.raw(`SELECT * FROM entity_comments ORDER BY created_at DESC LIMIT ${limit}`));
    return c.json({ success: true, data: result.rows || [] });
});

// GET /comments/stats — Comment statistics
router.get('/comments/stats', async (c) => {
    await ensureOnce();
    const [total, byType, pinned] = await Promise.all([
        rawQuery(sql.raw(`SELECT COUNT(*) AS total FROM entity_comments`)),
        rawQuery(sql.raw(`SELECT entity_type, COUNT(*) AS count FROM entity_comments GROUP BY entity_type ORDER BY count DESC`)),
        rawQuery(sql.raw(`SELECT COUNT(*) AS total FROM entity_comments WHERE pinned = true`)),
    ]);
    return c.json({
        success: true,
        data: {
            total: Number((total.rows?.[0] as Record<string, unknown>)?.total || 0),
            pinnedCount: Number((pinned.rows?.[0] as Record<string, unknown>)?.total || 0),
            byEntityType: byType.rows || [],
        },
    });
});

export default router;
