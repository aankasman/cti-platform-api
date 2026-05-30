/**
 * /v1/watch — Personal "pinned entities" tracker.
 *
 * Distinct from /v1/watchlists (which is named curated lists with
 * IOC value+type entries — closer to Recorded Future watchlists or
 * MISP warninglists). This is the simpler primitive that backs the
 * dashboard's Watch button on entity drawers and the Indicators
 * page's bulk action bar:
 *
 *   • POST   /v1/watch                       — pin an entity
 *   • DELETE /v1/watch/:type/:id             — unpin
 *   • GET    /v1/watch                       — list current user's pins
 *   • GET    /v1/watch/check/:type/:id       — single-entity check
 *
 * Entity types covered today: `ioc`, `cve`, `actor`. The
 * `entity_id` is opaque (UUID for IOCs/actors, CVE id for vulns),
 * stored as TEXT to keep the table polymorphic.
 *
 * No JOIN to the entity row at write time — pins survive even if
 * the underlying entity is later revoked / merged / deleted (we
 * surface "this pin no longer resolves" on the read path rather than
 * silently dropping pins server-side).
 */

import { Hono } from 'hono';
import { rawQuery, sql } from '@rinjani/db';
import { requireAuth } from '../../middleware/auth';
import { createLogger } from '../../lib/logger';

const log = createLogger('Watch');
const router = new Hono();
router.use('*', requireAuth);

/** Bootstrap the watch table on first request — same pattern as
 *  /v1/watchlists. Once-per-process flag avoids the cost on hot path. */
const ensureOnce = (() => {
    let done = false;
    return async () => {
        if (done) return;
        await rawQuery(sql.raw(`
            CREATE TABLE IF NOT EXISTS user_watch_items (
                id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id      TEXT NOT NULL,
                entity_type  TEXT NOT NULL,
                entity_id    TEXT NOT NULL,
                note         TEXT,
                created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE (user_id, entity_type, entity_id)
            );
            CREATE INDEX IF NOT EXISTS idx_user_watch_user
                ON user_watch_items (user_id);
            CREATE INDEX IF NOT EXISTS idx_user_watch_user_type
                ON user_watch_items (user_id, entity_type);
        `));
        done = true;
    };
})();

const VALID_TYPES = new Set(['ioc', 'cve', 'actor']);

/* ────────────────────────────────────────────────────────────────────────
   POST /v1/watch — pin an entity to the current user's watchlist.

   Body: { entityType: 'ioc' | 'cve' | 'actor', entityId: string, note?: string }
   Idempotent: re-pinning an already-pinned entity 200s without error
   (and updates the `note` if provided). The frontend's Watch toggle
   relies on this — re-click after watching should not produce a 409.
   ──────────────────────────────────────────────────────────────────── */
router.post('/watch', async (c) => {
    await ensureOnce();
    const userId = c.get('user')?.id;
    if (!userId) return c.json({ success: false, error: { code: 'NO_USER', message: 'No authenticated user' } }, 401);

    const body = await c.req.json().catch(() => ({})) as {
        entityType?: string;
        entityId?: string;
        note?: string;
    };

    const entityType = String(body.entityType ?? '').toLowerCase();
    const entityId   = String(body.entityId ?? '').trim();
    const note       = body.note ? String(body.note).slice(0, 500) : null;

    if (!VALID_TYPES.has(entityType)) {
        return c.json({
            success: false,
            error: { code: 'INVALID_TYPE', message: `entityType must be one of: ${[...VALID_TYPES].join(', ')}` },
        }, 400);
    }
    if (!entityId) {
        return c.json({
            success: false,
            error: { code: 'MISSING_ID', message: 'entityId is required' },
        }, 400);
    }

    // ON CONFLICT … DO UPDATE so re-pinning refreshes the note rather
    // than 409ing the toggle. Updated `created_at` would be misleading
    // ("you pinned this just now" when actually you pinned it last
    // week and just re-clicked), so we leave it alone on conflict.
    const result = await rawQuery<{ id: string; created_at: string }>(sql`
        INSERT INTO user_watch_items (user_id, entity_type, entity_id, note)
        VALUES (${userId}, ${entityType}, ${entityId}, ${note})
        ON CONFLICT (user_id, entity_type, entity_id) DO UPDATE
            SET note = COALESCE(EXCLUDED.note, user_watch_items.note)
        RETURNING id, created_at
    `);

    const row = result.rows?.[0];
    log.debug('watch.pin', { userId, entityType, entityId });
    return c.json({
        success: true,
        data: {
            id: row?.id,
            entityType,
            entityId,
            note,
            createdAt: row?.created_at,
        },
    }, 201);
});

/* ────────────────────────────────────────────────────────────────────────
   DELETE /v1/watch/:type/:id — unpin.

   Idempotent: removing an unpinned entity 200s with `{ removed: false }`.
   This makes the Watch button toggle resilient to double-clicks and
   stale UI state.
   ──────────────────────────────────────────────────────────────────── */
router.delete('/watch/:type/:id', async (c) => {
    await ensureOnce();
    const userId = c.get('user')?.id;
    if (!userId) return c.json({ success: false, error: { code: 'NO_USER', message: 'No authenticated user' } }, 401);

    const entityType = String(c.req.param('type') ?? '').toLowerCase();
    const entityId   = decodeURIComponent(String(c.req.param('id') ?? ''));

    if (!VALID_TYPES.has(entityType)) {
        return c.json({
            success: false,
            error: { code: 'INVALID_TYPE', message: `entityType must be one of: ${[...VALID_TYPES].join(', ')}` },
        }, 400);
    }

    const result = await rawQuery<{ id: string }>(sql`
        DELETE FROM user_watch_items
        WHERE user_id = ${userId} AND entity_type = ${entityType} AND entity_id = ${entityId}
        RETURNING id
    `);

    return c.json({
        success: true,
        data: { removed: (result.rows?.length ?? 0) > 0 },
    });
});

/* ────────────────────────────────────────────────────────────────────────
   GET /v1/watch — list current user's watched entities.

   Query params:
     • type=ioc|cve|actor   filter by entity type (optional)
     • limit=N              default 100, max 500

   Returns watched items with their `entity_id` and `created_at`. The
   client can fetch entity details separately if it needs them (this
   endpoint stays cheap and JOIN-free). For the Actor Watchlist panel
   on the Command screen, the client hydrates by calling
   /v1/threats/:id per pinned actor — N+1 in theory, but the
   watchlist is small (single digits) and the panel polls infrequently.
   ──────────────────────────────────────────────────────────────────── */
router.get('/watch', async (c) => {
    await ensureOnce();
    const userId = c.get('user')?.id;
    if (!userId) return c.json({ success: false, error: { code: 'NO_USER', message: 'No authenticated user' } }, 401);

    const typeRaw = c.req.query('type');
    const limit = Math.min(Math.max(Number(c.req.query('limit')) || 100, 1), 500);

    const typeFilter = typeRaw && VALID_TYPES.has(typeRaw.toLowerCase())
        ? typeRaw.toLowerCase()
        : null;

    const rows = typeFilter
        ? (await rawQuery<{ id: string; entity_type: string; entity_id: string; note: string | null; created_at: string }>(sql`
            SELECT id, entity_type, entity_id, note, created_at
            FROM user_watch_items
            WHERE user_id = ${userId} AND entity_type = ${typeFilter}
            ORDER BY created_at DESC
            LIMIT ${limit}
        `)).rows
        : (await rawQuery<{ id: string; entity_type: string; entity_id: string; note: string | null; created_at: string }>(sql`
            SELECT id, entity_type, entity_id, note, created_at
            FROM user_watch_items
            WHERE user_id = ${userId}
            ORDER BY created_at DESC
            LIMIT ${limit}
        `)).rows;

    return c.json({
        success: true,
        data: {
            items: (rows ?? []).map(r => ({
                id: r.id,
                entityType: r.entity_type,
                entityId: r.entity_id,
                note: r.note,
                createdAt: r.created_at,
            })),
        },
    });
});

/* ────────────────────────────────────────────────────────────────────────
   GET /v1/watch/check/:type/:id — single-entity check.

   The Watch button's initial state ("Watching" vs "Watch") needs to
   know "is this entity already pinned by me?" without paginating
   the full list. This endpoint exists to avoid the client doing a
   linear scan of /v1/watch on every drawer open.
   ──────────────────────────────────────────────────────────────────── */
router.get('/watch/check/:type/:id', async (c) => {
    await ensureOnce();
    const userId = c.get('user')?.id;
    if (!userId) return c.json({ success: false, error: { code: 'NO_USER', message: 'No authenticated user' } }, 401);

    const entityType = String(c.req.param('type') ?? '').toLowerCase();
    const entityId   = decodeURIComponent(String(c.req.param('id') ?? ''));

    if (!VALID_TYPES.has(entityType)) {
        return c.json({
            success: false,
            error: { code: 'INVALID_TYPE', message: `entityType must be one of: ${[...VALID_TYPES].join(', ')}` },
        }, 400);
    }

    const result = await rawQuery<{ id: string; created_at: string }>(sql`
        SELECT id, created_at FROM user_watch_items
        WHERE user_id = ${userId} AND entity_type = ${entityType} AND entity_id = ${entityId}
        LIMIT 1
    `);

    const row = result.rows?.[0];
    return c.json({
        success: true,
        data: {
            watched: !!row,
            createdAt: row?.created_at ?? null,
        },
    });
});

export default router;
