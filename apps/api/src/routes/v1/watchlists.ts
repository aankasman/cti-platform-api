/**
 * IOC Watchlists — Personal/Team observable tracking
 *
 * Inspired by Recorded Future watchlists and MISP warninglists.
 * Users create named watchlists, add IOC values, and check
 * incoming data against them for alerts.
 *
 * Mounts at: /v1/watchlists/*
 */

import { Hono } from 'hono';
import { rawQuery, sql } from '@rinjani/db';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError } from '../../lib/errors';
import { createLogger } from '../../lib/logger';
import {
    CreateWatchlistSchema, UpdateWatchlistSchema,
    WatchlistEntrySchema, WatchlistCheckSchema,
} from '../../lib/schemas';

const log = createLogger('Watchlists');
const router = new Hono();
router.use('*', requireAuth);

const ensureOnce = (() => {
    let done = false;
    return async () => {
        if (done) return;
        await rawQuery(sql.raw(`
            CREATE TABLE IF NOT EXISTS watchlists (
                id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
                name TEXT NOT NULL,
                description TEXT,
                visibility TEXT NOT NULL DEFAULT 'personal',
                notify_on_hit BOOLEAN NOT NULL DEFAULT false,
                tags TEXT[] DEFAULT '{}',
                owner_id TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            );
            CREATE TABLE IF NOT EXISTS watchlist_entries (
                id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
                watchlist_id TEXT NOT NULL REFERENCES watchlists(id) ON DELETE CASCADE,
                value TEXT NOT NULL,
                type TEXT NOT NULL,
                notes TEXT,
                expires_at TIMESTAMPTZ,
                added_by TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(watchlist_id, value, type)
            );
            CREATE INDEX IF NOT EXISTS idx_wl_entries_value ON watchlist_entries(value);
        `));
        done = true;
    };
})();

const esc = (s: string) => s.replace(/'/g, "''");

// POST /watchlists
router.post('/watchlists', requireRole('admin', 'analyst'), async (c) => {
    await ensureOnce();
    const body = CreateWatchlistSchema.parse(await c.req.json().catch(() => ({})));
    const userId = c.get('user')?.id || 'unknown';
    const result = await rawQuery(sql.raw(`
        INSERT INTO watchlists (name, description, visibility, notify_on_hit, tags, owner_id)
        VALUES ('${esc(body.name)}', ${body.description ? `'${esc(body.description)}'` : 'NULL'},
                '${esc(body.visibility)}', ${body.notifyOnHit},
                ${body.tags.length > 0 ? `ARRAY[${body.tags.map(t => `'${esc(t)}'`).join(',')}]` : `'{}'::TEXT[]`}, '${esc(userId)}')
        RETURNING *
    `));
    return c.json({ success: true, data: result.rows?.[0] }, 201);
});

// GET /watchlists
router.get('/watchlists', async (c) => {
    await ensureOnce();
    const userId = c.get('user')?.id || 'unknown';
    const result = await rawQuery(sql.raw(`
        SELECT w.*, (SELECT COUNT(*) FROM watchlist_entries WHERE watchlist_id = w.id) AS entry_count
        FROM watchlists w
        WHERE w.visibility = 'global' OR w.owner_id = '${esc(userId)}'
        ORDER BY w.updated_at DESC
    `));
    return c.json({ success: true, data: result.rows || [] });
});

// GET /watchlists/:id
router.get('/watchlists/:id', async (c) => {
    await ensureOnce();
    const { id } = c.req.param();
    const [wlResult, entries] = await Promise.all([
        rawQuery(sql.raw(`SELECT * FROM watchlists WHERE id = '${esc(id)}'`)),
        rawQuery(sql.raw(`SELECT * FROM watchlist_entries WHERE watchlist_id = '${esc(id)}' ORDER BY created_at DESC`)),
    ]);
    const wl = wlResult.rows?.[0];
    if (!wl) throw new NotFoundError('Watchlist', id);
    return c.json({ success: true, data: { ...wl, entries: entries.rows || [] } });
});

// PUT /watchlists/:id
router.put('/watchlists/:id', requireRole('admin', 'analyst'), async (c) => {
    await ensureOnce();
    const { id } = c.req.param();
    const body = UpdateWatchlistSchema.parse(await c.req.json().catch(() => ({})));
    const sets: string[] = ['updated_at = NOW()'];
    if (body.name) sets.push(`name = '${esc(body.name)}'`);
    if (body.description !== undefined) sets.push(`description = ${body.description ? `'${esc(body.description)}'` : 'NULL'}`);
    if (body.visibility) sets.push(`visibility = '${esc(body.visibility)}'`);
    if (body.notifyOnHit !== undefined) sets.push(`notify_on_hit = ${body.notifyOnHit}`);
    if (body.tags) sets.push(`tags = ARRAY[${body.tags.map(t => `'${esc(t)}'`).join(',')}]`);
    const result = await rawQuery(sql.raw(`UPDATE watchlists SET ${sets.join(', ')} WHERE id = '${esc(id)}' RETURNING *`));
    if (!result.rows?.[0]) throw new NotFoundError('Watchlist', id);
    return c.json({ success: true, data: result.rows[0] });
});

// DELETE /watchlists/:id
router.delete('/watchlists/:id', requireRole('admin'), async (c) => {
    await ensureOnce();
    const { id } = c.req.param();
    const result = await rawQuery(sql.raw(`DELETE FROM watchlists WHERE id = '${esc(id)}' RETURNING id`));
    if (!result.rows?.[0]) throw new NotFoundError('Watchlist', id);
    return c.json({ success: true, data: { id, deleted: true } });
});

// POST /watchlists/:id/entries
router.post('/watchlists/:id/entries', requireRole('admin', 'analyst'), async (c) => {
    await ensureOnce();
    const { id } = c.req.param();
    const body = WatchlistEntrySchema.parse(await c.req.json().catch(() => ({})));
    const userId = c.get('user')?.id || 'unknown';
    const check = await rawQuery(sql.raw(`SELECT id FROM watchlists WHERE id = '${esc(id)}'`));
    if (!check.rows?.[0]) throw new NotFoundError('Watchlist', id);
    const result = await rawQuery(sql.raw(`
        INSERT INTO watchlist_entries (watchlist_id, value, type, notes, expires_at, added_by)
        VALUES ('${esc(id)}', '${esc(body.value)}', '${esc(body.type)}',
                ${body.notes ? `'${esc(body.notes)}'` : 'NULL'},
                ${body.expiresAt ? `'${esc(body.expiresAt)}'` : 'NULL'}, '${esc(userId)}')
        ON CONFLICT (watchlist_id, value, type) DO UPDATE SET notes = EXCLUDED.notes, expires_at = EXCLUDED.expires_at
        RETURNING *
    `));
    return c.json({ success: true, data: result.rows?.[0] }, 201);
});

// DELETE /watchlists/:id/entries/:entryId
router.delete('/watchlists/:id/entries/:entryId', requireRole('admin', 'analyst'), async (c) => {
    await ensureOnce();
    const { id, entryId } = c.req.param();
    const result = await rawQuery(sql.raw(`DELETE FROM watchlist_entries WHERE id = '${esc(entryId)}' AND watchlist_id = '${esc(id)}' RETURNING id`));
    if (!result.rows?.[0]) throw new NotFoundError('Entry', entryId);
    return c.json({ success: true, data: { id: entryId, deleted: true } });
});

// POST /watchlists/check
router.post('/watchlists/check', async (c) => {
    await ensureOnce();
    const body = WatchlistCheckSchema.parse(await c.req.json().catch(() => ({})));
    const userId = c.get('user')?.id || 'unknown';
    const result = await rawQuery(sql.raw(`
        SELECT we.value, we.type, we.notes, w.id AS watchlist_id, w.name AS watchlist_name, w.notify_on_hit
        FROM watchlist_entries we JOIN watchlists w ON we.watchlist_id = w.id
        WHERE we.value = '${esc(body.value)}'
          AND (we.expires_at IS NULL OR we.expires_at > NOW())
          AND (w.visibility = 'global' OR w.owner_id = '${esc(userId)}')
    `));
    return c.json({
        success: true,
        data: { value: body.value, matched: (result.rows || []).length > 0, hits: result.rows || [] },
    });
});

export default router;
