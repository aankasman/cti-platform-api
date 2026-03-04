/**
 * Data Retention Policies — Configurable TTL-based auto-purging
 *
 * Inspired by CrowdSec and MISP retention.
 * Define policies per entity type with optional severity/source filters.
 *
 * Mounts at: /v1/retention/*
 */

import { Hono } from 'hono';
import { rawQuery, sql } from '@rinjani/db';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError } from '../../lib/errors';
import { createLogger } from '../../lib/logger';
import { CreateRetentionPolicySchema, UpdateRetentionPolicySchema } from '../../lib/schemas';

const log = createLogger('Retention');
const router = new Hono();
router.use('*', requireAuth);

const TABLE_MAP: Record<string, string> = {
    ioc: 'iocs',
    vulnerability: 'vulnerabilities',
    alert: 'alerts',
    sighting: 'sightings',
    audit_log: 'audit_logs',
    notification: 'notifications',
};

const ensureOnce = (() => {
    let done = false;
    return async () => {
        if (done) return;
        await rawQuery(sql.raw(`
            CREATE TABLE IF NOT EXISTS retention_policies (
                id TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
                name TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                retention_days INT NOT NULL,
                action TEXT NOT NULL DEFAULT 'delete',
                filters JSONB DEFAULT '{}',
                enabled BOOLEAN DEFAULT true,
                last_run_at TIMESTAMPTZ,
                last_purged INT DEFAULT 0,
                created_by TEXT,
                created_at TIMESTAMPTZ DEFAULT NOW(),
                updated_at TIMESTAMPTZ DEFAULT NOW()
            );
        `));
        done = true;
    };
})();

const esc = (s: string) => s.replace(/'/g, "''");

// POST /retention/policies
router.post('/retention/policies', requireRole('admin'), async (c) => {
    await ensureOnce();
    const body = CreateRetentionPolicySchema.parse(await c.req.json().catch(() => ({})));
    const userId = c.get('user')?.id || 'unknown';
    const result = await rawQuery(sql.raw(`
        INSERT INTO retention_policies (name, entity_type, retention_days, action, filters, enabled, created_by)
        VALUES ('${esc(body.name)}', '${esc(body.entityType)}', ${body.retentionDays},
                '${esc(body.action)}', '${JSON.stringify(body.filters).replace(/'/g, "''")}'::jsonb,
                ${body.enabled}, '${esc(userId)}')
        RETURNING *
    `));
    return c.json({ success: true, data: result.rows?.[0] }, 201);
});

// GET /retention/policies
router.get('/retention/policies', async (c) => {
    await ensureOnce();
    const result = await rawQuery(sql.raw(`SELECT * FROM retention_policies ORDER BY created_at DESC`));
    return c.json({ success: true, data: result.rows || [] });
});

// GET /retention/policies/:id
router.get('/retention/policies/:id', async (c) => {
    await ensureOnce();
    const { id } = c.req.param();
    const result = await rawQuery(sql.raw(`SELECT * FROM retention_policies WHERE id = '${esc(id)}'`));
    if (!result.rows?.[0]) throw new NotFoundError('RetentionPolicy', id);
    return c.json({ success: true, data: result.rows[0] });
});

// PUT /retention/policies/:id
router.put('/retention/policies/:id', requireRole('admin'), async (c) => {
    await ensureOnce();
    const { id } = c.req.param();
    const body = UpdateRetentionPolicySchema.parse(await c.req.json().catch(() => ({})));
    const sets: string[] = ['updated_at = NOW()'];
    if (body.name) sets.push(`name = '${esc(body.name)}'`);
    if (body.retentionDays) sets.push(`retention_days = ${body.retentionDays}`);
    if (body.action) sets.push(`action = '${esc(body.action)}'`);
    if (body.filters) sets.push(`filters = '${JSON.stringify(body.filters).replace(/'/g, "''")}'::jsonb`);
    if (body.enabled !== undefined) sets.push(`enabled = ${body.enabled}`);
    const result = await rawQuery(sql.raw(`UPDATE retention_policies SET ${sets.join(', ')} WHERE id = '${esc(id)}' RETURNING *`));
    if (!result.rows?.[0]) throw new NotFoundError('RetentionPolicy', id);
    return c.json({ success: true, data: result.rows[0] });
});

// DELETE /retention/policies/:id
router.delete('/retention/policies/:id', requireRole('admin'), async (c) => {
    await ensureOnce();
    const { id } = c.req.param();
    const result = await rawQuery(sql.raw(`DELETE FROM retention_policies WHERE id = '${esc(id)}' RETURNING id`));
    if (!result.rows?.[0]) throw new NotFoundError('RetentionPolicy', id);
    return c.json({ success: true, data: { id, deleted: true } });
});

// POST /retention/policies/:id/execute — Execute a policy (dry-run or live)
router.post('/retention/policies/:id/execute', requireRole('admin'), async (c) => {
    await ensureOnce();
    const { id } = c.req.param();
    const dryRun = c.req.query('dryRun') !== 'false';
    const policy = await rawQuery(sql.raw(`SELECT * FROM retention_policies WHERE id = '${esc(id)}'`));
    const p = policy.rows?.[0] as Record<string, unknown>;
    if (!p) throw new NotFoundError('RetentionPolicy', id);

    const table = TABLE_MAP[String(p.entity_type)] || String(p.entity_type);
    const conds = [`created_at < NOW() - INTERVAL '${Number(p.retention_days)} days'`];
    const filters = (p.filters as Record<string, unknown>) || {};
    if (filters.severity) conds.push(`severity = '${esc(String(filters.severity))}'`);
    if (filters.source) conds.push(`source = '${esc(String(filters.source))}'`);
    if (filters.maxRiskScore != null) conds.push(`risk_score <= ${Number(filters.maxRiskScore)}`);
    const where = conds.join(' AND ');

    if (dryRun) {
        const count = await rawQuery(sql.raw(`SELECT COUNT(*) AS affected FROM ${table} WHERE ${where}`));
        return c.json({
            success: true,
            data: { dryRun: true, affected: Number((count.rows?.[0] as Record<string, unknown>)?.affected || 0), policy: p },
        });
    }

    const action = String(p.action);
    let purged = 0;
    if (action === 'delete') {
        const result = await rawQuery(sql.raw(`DELETE FROM ${table} WHERE ${where} RETURNING id`));
        purged = result.rows?.length || 0;
    } else if (action === 'archive') {
        // For archive: prefix source with "archived:" to soft-archive
        const result = await rawQuery(sql.raw(`UPDATE ${table} SET source = 'archived:' || source WHERE ${where} AND source NOT LIKE 'archived:%' RETURNING id`));
        purged = result.rows?.length || 0;
    }

    await rawQuery(sql.raw(`UPDATE retention_policies SET last_run_at = NOW(), last_purged = ${purged} WHERE id = '${esc(id)}'`));
    log.info('Retention policy executed', { policyId: id, action, purged });
    return c.json({ success: true, data: { dryRun: false, purged, action, policy: p } });
});

// GET /retention/preview — Preview what each enabled policy would affect
router.get('/retention/preview', requireRole('admin'), async (c) => {
    await ensureOnce();
    const policies = await rawQuery(sql.raw(`SELECT * FROM retention_policies WHERE enabled = true`));
    const previews = [];
    for (const p of (policies.rows || []) as Array<Record<string, unknown>>) {
        const table = TABLE_MAP[String(p.entity_type)] || String(p.entity_type);
        const conds = [`created_at < NOW() - INTERVAL '${Number(p.retention_days)} days'`];
        const filters = (p.filters as Record<string, unknown>) || {};
        if (filters.severity) conds.push(`severity = '${esc(String(filters.severity))}'`);
        if (filters.source) conds.push(`source = '${esc(String(filters.source))}'`);
        if (filters.maxRiskScore != null) conds.push(`risk_score <= ${Number(filters.maxRiskScore)}`);
        try {
            const count = await rawQuery(sql.raw(`SELECT COUNT(*) AS affected FROM ${table} WHERE ${conds.join(' AND ')}`));
            previews.push({ policyId: p.id, name: p.name, entityType: p.entity_type, action: p.action, affected: Number((count.rows?.[0] as Record<string, unknown>)?.affected || 0) });
        } catch {
            previews.push({ policyId: p.id, name: p.name, entityType: p.entity_type, action: p.action, affected: 0, error: 'Table not found' });
        }
    }
    return c.json({ success: true, data: previews });
});

export default router;
