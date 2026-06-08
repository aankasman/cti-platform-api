/**
 * Sigma rule routes.
 *
 *   GET    /v1/sigma/rules                       List + filter
 *   GET    /v1/sigma/rules/:uuid                 Rule detail (full YAML-equiv JSON)
 *   GET    /v1/sigma/by-technique/:techniqueId   Rules tagged with `attack.tNNNN`
 *   GET    /v1/sigma/stats                       Aggregate counts
 *   POST   /v1/sigma/rules                       Ingest YAML (single or `---`-separated bundle)
 *   POST   /v1/sigma/import/url                  Ingest from a Sigma YAML URL (raw.githubusercontent.com etc.)
 *   DELETE /v1/sigma/rules/:uuid                 Remove a rule (admin)
 *
 * Storage is the same `detection_rules` table that MISP-Galaxy populates,
 * but with `rule_type = 'sigma'` and the full detection block stored in
 * the `detection` JSONB column. The MITRE technique/tactic tags are
 * lifted into `meta.mitre_techniques` / `meta.mitre_tactics` so the
 * by-technique route can filter at the DB layer without re-parsing tags.
 */
import { Hono } from 'hono';
import { db, eq, and, sql, desc } from '@rinjani/db';
import { detectionRules } from '@rinjani/db/schema';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError, ValidationError } from '../../lib/errors';
import {
    SigmaIngestSchema, SigmaImportUrlSchema, SigmaListSchema,
} from '../../lib/schemas';
import { ingestSigmaBundle, ingestSigmaFromUrl } from '../../services/sigmaIngester';

const router = new Hono();

// ── List ────────────────────────────────────────────────────────────

router.get('/sigma/rules', requireAuth, async (c) => {
    const filters = SigmaListSchema.parse(c.req.query());
    const wheres = [eq(detectionRules.ruleType, 'sigma')];

    if (filters.severity) wheres.push(eq(detectionRules.severity, filters.severity));
    if (filters.status) wheres.push(eq(detectionRules.status, filters.status));
    if (filters.source) wheres.push(eq(detectionRules.source, filters.source));
    if (filters.q) {
        wheres.push(sql`(${detectionRules.name} ILIKE ${'%' + filters.q + '%'} OR ${detectionRules.description} ILIKE ${'%' + filters.q + '%'})`);
    }
    if (filters.technique) {
        wheres.push(sql`${detectionRules.meta}->'mitre_techniques' @> ${JSON.stringify([filters.technique.toUpperCase()])}::jsonb`);
    }
    if (filters.tactic) {
        wheres.push(sql`${detectionRules.meta}->'mitre_tactics' @> ${JSON.stringify([filters.tactic.toLowerCase()])}::jsonb`);
    }

    const where = wheres.length === 1 ? wheres[0] : and(...wheres);
    const offset = (filters.page - 1) * filters.pageSize;

    const [rows, [{ total }]] = await Promise.all([
        db.select({
            uuid: detectionRules.uuid,
            name: detectionRules.name,
            description: detectionRules.description,
            severity: detectionRules.severity,
            status: detectionRules.status,
            tags: detectionRules.tags,
            source: detectionRules.source,
            externalReferences: detectionRules.externalReferences,
            syncedAt: detectionRules.syncedAt,
            updatedAt: detectionRules.updatedAt,
        })
            .from(detectionRules)
            .where(where)
            .orderBy(desc(detectionRules.updatedAt))
            .limit(filters.pageSize)
            .offset(offset),
        db.select({ total: sql<number>`count(*)::int` })
            .from(detectionRules)
            .where(where),
    ]);

    return c.json({
        success: true,
        data: rows,
        pagination: { page: filters.page, pageSize: filters.pageSize, total },
    });
});

// ── Detail ──────────────────────────────────────────────────────────

router.get('/sigma/rules/:uuid', requireAuth, async (c) => {
    const uuid = c.req.param('uuid')!;
    const [row] = await db.select().from(detectionRules)
        .where(and(eq(detectionRules.uuid, uuid), eq(detectionRules.ruleType, 'sigma')))
        .limit(1);
    if (!row) throw new NotFoundError('Sigma rule', uuid);
    return c.json({ success: true, data: row });
});

// ── By MITRE technique ──────────────────────────────────────────────

router.get('/sigma/by-technique/:techniqueId', requireAuth, async (c) => {
    const techniqueId = c.req.param('techniqueId')!.toUpperCase();
    if (!/^T\d{4}(\.\d{3})?$/.test(techniqueId)) {
        throw new ValidationError('techniqueId must look like T1059 or T1059.001');
    }
    const rows = await db.select({
        uuid: detectionRules.uuid,
        name: detectionRules.name,
        severity: detectionRules.severity,
        status: detectionRules.status,
        tags: detectionRules.tags,
        source: detectionRules.source,
    })
        .from(detectionRules)
        .where(and(
            eq(detectionRules.ruleType, 'sigma'),
            sql`${detectionRules.meta}->'mitre_techniques' @> ${JSON.stringify([techniqueId])}::jsonb`,
        ))
        // Sort by criticality, not string severity (alpha order would put
        // `critical` before `high` but `informational` before `low`).
        .orderBy(sql`CASE ${detectionRules.severity}
            WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
            WHEN 'low' THEN 3 WHEN 'informational' THEN 4 ELSE 5 END`);

    return c.json({ success: true, data: { techniqueId, count: rows.length, rules: rows } });
});

// ── Stats ───────────────────────────────────────────────────────────

router.get('/sigma/stats', requireAuth, async (c) => {
    const [bySeverity, byStatus, bySource, [{ total }]] = await Promise.all([
        db.select({ severity: detectionRules.severity, count: sql<number>`count(*)::int` })
            .from(detectionRules)
            .where(eq(detectionRules.ruleType, 'sigma'))
            .groupBy(detectionRules.severity),
        db.select({ status: detectionRules.status, count: sql<number>`count(*)::int` })
            .from(detectionRules)
            .where(eq(detectionRules.ruleType, 'sigma'))
            .groupBy(detectionRules.status),
        db.select({ source: detectionRules.source, count: sql<number>`count(*)::int` })
            .from(detectionRules)
            .where(eq(detectionRules.ruleType, 'sigma'))
            .groupBy(detectionRules.source),
        db.select({ total: sql<number>`count(*)::int` })
            .from(detectionRules)
            .where(eq(detectionRules.ruleType, 'sigma')),
    ]);
    return c.json({ success: true, data: { total, bySeverity, byStatus, bySource } });
});

// ── Ingest ──────────────────────────────────────────────────────────

router.post('/sigma/rules', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    // Accept either application/json {"yaml": "..."} or raw text/yaml body.
    const ct = c.req.header('content-type') || '';
    let yamlText: string;
    if (ct.includes('application/json')) {
        const body = SigmaIngestSchema.parse(await c.req.json());
        yamlText = body.yaml;
    } else {
        yamlText = await c.req.text();
        if (!yamlText || yamlText.length > 5 * 1024 * 1024) {
            throw new ValidationError('YAML body required (≤ 5 MiB)');
        }
    }

    const stats = await ingestSigmaBundle(yamlText, 'user-upload');
    return c.json({ success: stats.errors.length === 0, data: stats }, stats.inserted + stats.updated > 0 ? 201 : 400);
});

router.post('/sigma/import/url', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const { url } = SigmaImportUrlSchema.parse(await c.req.json());
    const stats = await ingestSigmaFromUrl(url);
    return c.json({ success: stats.errors.length === 0, data: stats }, stats.inserted + stats.updated > 0 ? 201 : 400);
});

router.delete('/sigma/rules/:uuid', requireAuth, requireRole('admin'), async (c) => {
    const uuid = c.req.param('uuid')!;
    const result = await db.delete(detectionRules)
        .where(and(eq(detectionRules.uuid, uuid), eq(detectionRules.ruleType, 'sigma')))
        .returning({ uuid: detectionRules.uuid });
    if (result.length === 0) throw new NotFoundError('Sigma rule', uuid);
    return c.json({ success: true, message: `Sigma rule ${uuid} deleted` });
});

export default router;
