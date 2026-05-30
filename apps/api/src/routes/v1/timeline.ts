/**
 * /v1/timeline/:type/:id — Per-entity activity timeline.
 *
 * Daily-bucketed counts of "this entity was talked about / seen" for
 * the last N days, driving the Sighting trend sparkline in the entity
 * drawer (replacing the Phase-1 placeholder).
 *
 * Signal source per type:
 *
 *   actor — pulses with `adversary` matching the actor's name OR any
 *           alias (case-insensitive). Bucketed by pulses.otx_modified.
 *           Same definition the dashboard uses for "active actors",
 *           kept consistent so the drawer's per-actor trend lines up
 *           with the platform-wide one in the KPI tile.
 *
 *   cve   — pulses whose `name` OR `description` mentions the CVE id
 *           (ILIKE '%CVE-YYYY-NNNN%'). Pulses don't have a structured
 *           cve_ids column today and the raw_data->indicators array
 *           ships empty in our import, so this text-match is the
 *           realistic fallback. Bucketed by pulses.otx_modified.
 *
 *   ioc   — sightings.observed_at, bucketed by day. The sightings
 *           table is empty in dev right now but the endpoint shape
 *           stays correct — once analysts start recording verdicts
 *           or feeds populate sightings, this lights up automatically.
 *
 * Response is the same zero-filled array shape as /stats/sparklines so
 * the frontend Sparkline component renders identically.
 *
 * Authenticated like the rest of /v1 (X-API-Key or Bearer); the
 * dashboard's fetch client attaches its session cookie automatically.
 * Read-only — no mutating verbs are exposed here.
 */

import { Hono } from 'hono';
import { rawQuery, sql } from '@rinjani/db';

const router = new Hono();

type EntityType = 'ioc' | 'cve' | 'actor';

function parseDays(raw: string | undefined, fallback = 14): number {
    const n = Number(raw ?? fallback);
    if (!Number.isFinite(n) || n <= 0) return fallback;
    return Math.min(Math.max(Math.floor(n), 1), 90);
}

router.get('/timeline/:type/:id', async (c) => {
    const type = c.req.param('type') as EntityType;
    const id   = c.req.param('id');
    const days = parseDays(c.req.query('days'));

    if (!['ioc', 'cve', 'actor'].includes(type)) {
        return c.json({ success: false, error: 'invalid entity type' }, 400);
    }

    let series: number[];
    let signal: string;

    if (type === 'actor') {
        series = await actorTimeline(id, days);
        signal = 'pulse_mentions';
    } else if (type === 'cve') {
        series = await cveTimeline(id, days);
        signal = 'pulse_mentions';
    } else {
        series = await iocTimeline(id, days);
        signal = 'sightings';
    }

    return c.json({
        success: true,
        data: {
            type,
            id,
            days,
            signal,
            series,
        },
    });
});

/**
 * Distinct pulse-IDs mentioning this actor per day. We use pulse-id
 * rather than COUNT(*) so a pulse with multiple `adversary` substring
 * matches (rare but possible) doesn't double-bump the bucket — every
 * day represents "how many distinct pulse stories talked about this
 * actor".
 */
async function actorTimeline(actorId: string, days: number): Promise<number[]> {
    const result = await rawQuery<{ day: string; n: number }>(sql`
        WITH d AS (
            SELECT generate_series(
                date_trunc('day', NOW()) - (${days - 1}::int * INTERVAL '1 day'),
                date_trunc('day', NOW()),
                INTERVAL '1 day'
            )::date AS day
        ),
        actor AS (
            SELECT name, (aliases #>> '{}')::jsonb AS aliases_array
            FROM threat_actors WHERE id = ${actorId}::uuid
        )
        SELECT
            d.day,
            COALESCE(COUNT(DISTINCT p.id), 0)::int AS n
        FROM d
        LEFT JOIN pulses p ON
            date_trunc('day', p.otx_modified)::date = d.day
            AND p.adversary IS NOT NULL AND p.adversary <> ''
            AND EXISTS (
                SELECT 1 FROM actor a
                WHERE LOWER(p.adversary) = LOWER(a.name)
                   OR (a.aliases_array IS NOT NULL AND LOWER(p.adversary) IN (
                       SELECT LOWER(elem::text)
                       FROM jsonb_array_elements_text(a.aliases_array) AS elem
                   ))
            )
        GROUP BY d.day
        ORDER BY d.day ASC
    `);
    return result.rows.map(r => Number(r.n));
}

/**
 * Pulses with `name` or `description` mentioning the CVE id. ILIKE
 * with a hard '%CVE-YYYY-NNNNN%' pattern — accepts CVE IDs of any
 * length and resists false positives because the prefix is specific.
 * Pulses without `cve_ids` structure today (see the file docstring
 * for why).
 */
async function cveTimeline(cveId: string, days: number): Promise<number[]> {
    const pattern = `%${cveId}%`;
    const result = await rawQuery<{ day: string; n: number }>(sql`
        WITH d AS (
            SELECT generate_series(
                date_trunc('day', NOW()) - (${days - 1}::int * INTERVAL '1 day'),
                date_trunc('day', NOW()),
                INTERVAL '1 day'
            )::date AS day
        )
        SELECT
            d.day,
            COALESCE(COUNT(DISTINCT p.id), 0)::int AS n
        FROM d
        LEFT JOIN pulses p ON
            date_trunc('day', p.otx_modified)::date = d.day
            AND (p.name ILIKE ${pattern} OR p.description ILIKE ${pattern})
        GROUP BY d.day
        ORDER BY d.day ASC
    `);
    return result.rows.map(r => Number(r.n));
}

/**
 * Sightings of this IOC, bucketed by observed_at. Returns flat zeros
 * while the sightings table is empty (current dev state) — the
 * sparkline label in the drawer says "No timeline data yet" in that
 * case. Once sightings populate, this lights up.
 */
async function iocTimeline(iocId: string, days: number): Promise<number[]> {
    const result = await rawQuery<{ day: string; n: number }>(sql`
        WITH d AS (
            SELECT generate_series(
                date_trunc('day', NOW()) - (${days - 1}::int * INTERVAL '1 day'),
                date_trunc('day', NOW()),
                INTERVAL '1 day'
            )::date AS day
        )
        SELECT
            d.day,
            COALESCE(COUNT(s.id), 0)::int AS n
        FROM d
        LEFT JOIN sightings s ON
            date_trunc('day', s.observed_at)::date = d.day
            AND s.ioc_id = ${iocId}::uuid
        GROUP BY d.day
        ORDER BY d.day ASC
    `);
    return result.rows.map(r => Number(r.n));
}

export default router;
