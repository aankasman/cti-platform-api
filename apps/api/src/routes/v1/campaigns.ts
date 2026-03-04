/**
 * Campaign Tracking — Named campaigns linking IOCs, actors, TTPs
 *
 * Uses the existing `campaigns` and `campaign_indicators` tables.
 * Extends with a new `campaign_entities` table for arbitrary entity linking.
 *
 * Mounts at: /v1/campaigns/*
 */

import { Hono } from 'hono';
import { rawQuery, sql } from '@rinjani/db';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError } from '../../lib/errors';
import { createLogger } from '../../lib/logger';
import {
    CreateCampaignSchema, UpdateCampaignSchema,
    CampaignLinkSchema, CampaignFilterSchema,
} from '../../lib/schemas';

const log = createLogger('Campaigns');
const router = new Hono();
router.use('*', requireAuth);

const ensureOnce = (() => {
    let done = false;
    return async () => {
        if (done) return;
        // Add missing columns to existing campaigns table safely
        const alterQueries = [
            `ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS threat_level TEXT DEFAULT 'unknown'`,
            `ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS attribution TEXT`,
            `ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS tags TEXT[] DEFAULT '{}'`,
            `ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS tlp TEXT DEFAULT 'green'`,
            `ALTER TABLE campaigns ADD COLUMN IF NOT EXISTS created_by TEXT`,
        ];
        for (const q of alterQueries) {
            try { await rawQuery(sql.raw(q)); } catch { /* column may already exist */ }
        }
        // Create entity linking table (separate from campaign_indicators)
        await rawQuery(sql.raw(`
            CREATE TABLE IF NOT EXISTS campaign_entities (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                campaign_id UUID NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
                entity_type TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'observed',
                notes TEXT,
                added_by TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                UNIQUE(campaign_id, entity_type, entity_id)
            );
            CREATE INDEX IF NOT EXISTS idx_campaign_entities_cid ON campaign_entities(campaign_id);
        `));
        done = true;
    };
})();

const esc = (s: string) => s.replace(/'/g, "''");

// POST /campaigns
router.post('/campaigns', requireRole('admin', 'analyst'), async (c) => {
    await ensureOnce();
    const body = CreateCampaignSchema.parse(await c.req.json().catch(() => ({})));
    const userId = c.get('user')?.id || 'unknown';
    const result = await rawQuery(sql.raw(`
        INSERT INTO campaigns (name, description, status, severity, threat_level, first_seen, last_seen, attribution, tags, tlp, created_by, metadata)
        VALUES ('${esc(body.name)}', ${body.description ? `'${esc(body.description)}'` : 'NULL'},
                '${esc(body.status)}', ${body.threatLevel !== 'unknown' ? `'${esc(body.threatLevel)}'` : 'NULL'},
                '${esc(body.threatLevel)}',
                ${body.firstSeen ? `'${esc(body.firstSeen)}'` : 'NULL'},
                ${body.lastSeen ? `'${esc(body.lastSeen)}'` : 'NULL'},
                ${body.attribution ? `'${esc(body.attribution)}'` : 'NULL'},
                ${body.tags.length > 0 ? `ARRAY[${body.tags.map(t => `'${esc(t)}'`).join(',')}]` : `'{}'::TEXT[]`},
                '${esc(body.tlp)}', '${esc(userId)}', '{}'::jsonb)
        RETURNING *
    `));
    return c.json({ success: true, data: result.rows?.[0] }, 201);
});

// GET /campaigns
router.get('/campaigns', async (c) => {
    await ensureOnce();
    const { page, pageSize, status, threatLevel, q } = CampaignFilterSchema.parse(c.req.query());
    const conds: string[] = ['1=1'];
    if (status) conds.push(`status = '${esc(status)}'`);
    if (threatLevel) conds.push(`threat_level = '${esc(threatLevel)}'`);
    if (q) conds.push(`(name ILIKE '%${esc(q)}%' OR description ILIKE '%${esc(q)}%' OR attribution ILIKE '%${esc(q)}%')`);
    const where = conds.join(' AND ');
    const offset = (page - 1) * pageSize;
    const [items, cnt] = await Promise.all([
        rawQuery(sql.raw(`SELECT c.*, (SELECT COUNT(*) FROM campaign_entities WHERE campaign_id = c.id) AS entity_count FROM campaigns c WHERE ${where} ORDER BY c.updated_at DESC LIMIT ${pageSize} OFFSET ${offset}`)),
        rawQuery(sql.raw(`SELECT COUNT(*) AS total FROM campaigns WHERE ${where}`)),
    ]);
    const total = Number((cnt.rows?.[0] as Record<string, unknown>)?.total || 0);
    return c.json({ success: true, data: { items: items.rows || [], pagination: { page, pageSize, total, totalPages: Math.ceil(total / pageSize) } } });
});

// GET /campaigns/:id
router.get('/campaigns/:id', async (c) => {
    await ensureOnce();
    const { id } = c.req.param();
    const [campaign, entities] = await Promise.all([
        rawQuery(sql.raw(`SELECT * FROM campaigns WHERE id = '${esc(id)}'`)),
        rawQuery(sql.raw(`SELECT * FROM campaign_entities WHERE campaign_id = '${esc(id)}' ORDER BY created_at DESC`)),
    ]);
    if (!campaign.rows?.[0]) throw new NotFoundError('Campaign', id);
    return c.json({ success: true, data: { ...campaign.rows[0], entities: entities.rows || [] } });
});

// PUT /campaigns/:id
router.put('/campaigns/:id', requireRole('admin', 'analyst'), async (c) => {
    await ensureOnce();
    const { id } = c.req.param();
    const body = UpdateCampaignSchema.parse(await c.req.json().catch(() => ({})));
    const sets: string[] = ['updated_at = NOW()'];
    if (body.name) sets.push(`name = '${esc(body.name)}'`);
    if (body.description !== undefined) sets.push(`description = ${body.description ? `'${esc(body.description)}'` : 'NULL'}`);
    if (body.status) sets.push(`status = '${esc(body.status)}'`);
    if (body.threatLevel) { sets.push(`threat_level = '${esc(body.threatLevel)}'`); sets.push(`severity = '${esc(body.threatLevel)}'`); }
    if (body.firstSeen) sets.push(`first_seen = '${esc(body.firstSeen)}'`);
    if (body.lastSeen) sets.push(`last_seen = '${esc(body.lastSeen)}'`);
    if (body.attribution !== undefined) sets.push(`attribution = ${body.attribution ? `'${esc(body.attribution)}'` : 'NULL'}`);
    if (body.tags) sets.push(`tags = ${body.tags.length > 0 ? `ARRAY[${body.tags.map(t => `'${esc(t)}'`).join(',')}]` : `'{}'::TEXT[]`}`);
    if (body.tlp) sets.push(`tlp = '${esc(body.tlp)}'`);
    const result = await rawQuery(sql.raw(`UPDATE campaigns SET ${sets.join(', ')} WHERE id = '${esc(id)}' RETURNING *`));
    if (!result.rows?.[0]) throw new NotFoundError('Campaign', id);
    return c.json({ success: true, data: result.rows[0] });
});

// DELETE /campaigns/:id
router.delete('/campaigns/:id', requireRole('admin'), async (c) => {
    await ensureOnce();
    const { id } = c.req.param();
    const result = await rawQuery(sql.raw(`DELETE FROM campaigns WHERE id = '${esc(id)}' RETURNING id`));
    if (!result.rows?.[0]) throw new NotFoundError('Campaign', id);
    return c.json({ success: true, data: { id, deleted: true } });
});

// POST /campaigns/:id/link
router.post('/campaigns/:id/link', requireRole('admin', 'analyst'), async (c) => {
    await ensureOnce();
    const { id } = c.req.param();
    const body = CampaignLinkSchema.parse(await c.req.json().catch(() => ({})));
    const userId = c.get('user')?.id || 'unknown';
    const check = await rawQuery(sql.raw(`SELECT id FROM campaigns WHERE id = '${esc(id)}'`));
    if (!check.rows?.[0]) throw new NotFoundError('Campaign', id);
    const result = await rawQuery(sql.raw(`
        INSERT INTO campaign_entities (campaign_id, entity_type, entity_id, role, notes, added_by)
        VALUES ('${esc(id)}', '${esc(body.entityType)}', '${esc(body.entityId)}',
                '${esc(body.role)}', ${body.notes ? `'${esc(body.notes)}'` : 'NULL'}, '${esc(userId)}')
        ON CONFLICT (campaign_id, entity_type, entity_id) DO UPDATE SET role = EXCLUDED.role, notes = EXCLUDED.notes
        RETURNING *
    `));
    return c.json({ success: true, data: result.rows?.[0] }, 201);
});

// DELETE /campaigns/:id/link/:linkId
router.delete('/campaigns/:id/link/:linkId', requireRole('admin', 'analyst'), async (c) => {
    await ensureOnce();
    const { id, linkId } = c.req.param();
    const result = await rawQuery(sql.raw(`DELETE FROM campaign_entities WHERE id = '${esc(linkId)}' AND campaign_id = '${esc(id)}' RETURNING id`));
    if (!result.rows?.[0]) throw new NotFoundError('CampaignLink', linkId);
    return c.json({ success: true, data: { id: linkId, deleted: true } });
});

// GET /campaigns/stats
router.get('/campaigns/stats', async (c) => {
    await ensureOnce();
    const [total, byStatus, byThreat] = await Promise.all([
        rawQuery(sql.raw(`SELECT COUNT(*) AS total FROM campaigns`)),
        rawQuery(sql.raw(`SELECT status, COUNT(*) AS count FROM campaigns GROUP BY status ORDER BY count DESC`)),
        rawQuery(sql.raw(`SELECT COALESCE(threat_level, severity, 'unknown') AS threat_level, COUNT(*) AS count FROM campaigns GROUP BY COALESCE(threat_level, severity, 'unknown') ORDER BY count DESC`)),
    ]);
    return c.json({
        success: true,
        data: {
            total: Number((total.rows?.[0] as Record<string, unknown>)?.total || 0),
            byStatus: byStatus.rows || [],
            byThreatLevel: byThreat.rows || [],
        },
    });
});

export default router;
