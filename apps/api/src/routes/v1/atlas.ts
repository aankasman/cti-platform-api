/**
 * MITRE ATLAS Routes (Adversarial Threat Landscape for AI Systems)
 *
 * Endpoints for ATLAS framework data: techniques, tactics, mitigations, case studies, and matrix.
 */

import { Hono } from 'hono';
import { db, sql } from '@rinjani/db';

const router = new Hono();

// ============================================================================
// ATLAS Matrix — Full matrix data for the /atlas page
// ============================================================================

router.get('/matrix', async (c) => {
    const [tacticsRes, techniquesRes, mitigationsRes, caseStudiesRes] = await Promise.all([
        db.execute(sql`SELECT * FROM atlas_tactics ORDER BY atlas_id`),
        db.execute(sql`SELECT * FROM atlas_techniques ORDER BY atlas_id`),
        db.execute(sql`SELECT * FROM atlas_mitigations ORDER BY atlas_id`),
        db.execute(sql`SELECT * FROM atlas_case_studies ORDER BY atlas_id`),
    ]);

    const tactics = (tacticsRes as any[]).map(t => ({
        id: t.id,
        atlasId: t.atlas_id,
        name: t.name,
        description: t.description,
        attackReferenceId: t.attack_reference_id,
        attackReferenceUrl: t.attack_reference_url,
    }));

    const techniques = (techniquesRes as any[]).map(t => {
        let tacticIds: string[] = [];
        try { tacticIds = typeof t.tactic_ids === 'string' ? JSON.parse(t.tactic_ids) : t.tactic_ids || []; } catch { }

        return {
            id: t.id,
            atlasId: t.atlas_id,
            name: t.name,
            description: t.description,
            maturity: t.maturity,
            subtechniqueOf: t.subtechnique_of,
            tacticIds,
            attackReferenceId: t.attack_reference_id,
            attackReferenceUrl: t.attack_reference_url,
            url: t.url,
        };
    });

    const mitigations = (mitigationsRes as any[]).map(m => {
        let techniqueIds: string[] = [];
        let mlLifecycle: string[] = [];
        let category: string[] = [];
        try { techniqueIds = typeof m.technique_ids === 'string' ? JSON.parse(m.technique_ids) : m.technique_ids || []; } catch { }
        try { mlLifecycle = typeof m.ml_lifecycle === 'string' ? JSON.parse(m.ml_lifecycle) : m.ml_lifecycle || []; } catch { }
        try { category = typeof m.category === 'string' ? JSON.parse(m.category) : m.category || []; } catch { }

        return {
            id: m.id,
            atlasId: m.atlas_id,
            name: m.name,
            description: m.description,
            techniqueIds,
            mlLifecycle,
            category,
        };
    });

    const caseStudies = (caseStudiesRes as any[]).map(cs => {
        let techniqueIds: string[] = [];
        let procedureSteps: any[] = [];
        let references: any[] = [];
        try { techniqueIds = typeof cs.technique_ids === 'string' ? JSON.parse(cs.technique_ids) : cs.technique_ids || []; } catch { }
        try { procedureSteps = typeof cs.procedure_steps === 'string' ? JSON.parse(cs.procedure_steps) : cs.procedure_steps || []; } catch { }
        try { references = typeof cs.references === 'string' ? JSON.parse(cs.references) : cs.references || []; } catch { }

        return {
            id: cs.id,
            atlasId: cs.atlas_id,
            name: cs.name,
            summary: cs.summary,
            incidentDate: cs.incident_date,
            reporter: cs.reporter,
            target: cs.target,
            actor: cs.actor,
            techniqueIds,
            procedureSteps,
            references,
            url: cs.url,
        };
    });

    // Build mitigation map: technique_id → [mitigation_ids]
    const mitigationMap: Record<string, string[]> = {};
    for (const m of mitigations) {
        for (const techId of m.techniqueIds) {
            if (!mitigationMap[techId]) mitigationMap[techId] = [];
            mitigationMap[techId].push(m.atlasId);
        }
    }

    return c.json({
        success: true,
        data: {
            tactics,
            techniques,
            mitigations,
            caseStudies,
            mitigationMap,
            stats: {
                tactics: tactics.length,
                techniques: techniques.length,
                mitigations: mitigations.length,
                caseStudies: caseStudies.length,
            },
        },
    });
});

// ============================================================================
// ATLAS Techniques — List with filtering
// ============================================================================

router.get('/techniques', async (c) => {
    const { tactic, maturity, q, limit = '50' } = c.req.query();
    const lim = Math.min(parseInt(limit) || 50, 200);

    const conditions: ReturnType<typeof sql>[] = [];

    if (tactic) {
        conditions.push(sql`tactic_ids::text LIKE ${'%"' + tactic + '"%'}`);
    }
    if (maturity) {
        conditions.push(sql`maturity = ${maturity}`);
    }
    if (q) {
        conditions.push(sql`(name ILIKE ${'%' + q + '%'} OR atlas_id ILIKE ${'%' + q + '%'} OR description ILIKE ${'%' + q + '%'})`);
    }

    const whereClause = conditions.length > 0
        ? sql`WHERE ${sql.join(conditions, sql` AND `)}`
        : sql``;

    const result = await db.execute(sql`SELECT * FROM atlas_techniques ${whereClause} ORDER BY atlas_id LIMIT ${lim}`) as any[];

    const items = result.map(t => {
        let tacticIds: string[] = [];
        try { tacticIds = typeof t.tactic_ids === 'string' ? JSON.parse(t.tactic_ids) : t.tactic_ids || []; } catch { }
        return {
            id: t.id,
            atlasId: t.atlas_id,
            name: t.name,
            description: t.description,
            maturity: t.maturity,
            subtechniqueOf: t.subtechnique_of,
            tacticIds,
            url: t.url,
        };
    });

    return c.json({ success: true, data: items, total: items.length });
});

// ============================================================================
// ATLAS Technique Detail
// ============================================================================

router.get('/techniques/:atlasId', async (c) => {
    const { atlasId } = c.req.param();
    const result = await db.execute(
        sql`SELECT * FROM atlas_techniques WHERE atlas_id = ${atlasId}`
    ) as any[];

    if (!result.length) {
        return c.json({ success: false, error: 'Not found' }, 404);
    }

    const t = result[0];
    const parseJson = (v: any) => { try { return typeof v === 'string' ? JSON.parse(v) : v || []; } catch { return []; } };

    return c.json({
        success: true,
        data: {
            id: t.id,
            atlasId: t.atlas_id,
            name: t.name,
            description: t.description,
            maturity: t.maturity,
            subtechniqueOf: t.subtechnique_of,
            tacticIds: parseJson(t.tactic_ids),
            attackReferenceId: t.attack_reference_id,
            attackReferenceUrl: t.attack_reference_url,
            url: t.url,
        },
    });
});

// ============================================================================
// ATLAS Tactics
// ============================================================================

router.get('/tactics', async (c) => {
    const result = await db.execute(
        sql`SELECT * FROM atlas_tactics ORDER BY atlas_id`
    ) as any[];

    return c.json({
        success: true,
        data: result.map(t => ({
            id: t.id,
            atlasId: t.atlas_id,
            name: t.name,
            description: t.description,
            attackReferenceId: t.attack_reference_id,
        })),
    });
});

// ============================================================================
// ATLAS Mitigations
// ============================================================================

router.get('/mitigations', async (c) => {
    const result = await db.execute(
        sql`SELECT * FROM atlas_mitigations ORDER BY atlas_id`
    ) as any[];

    const parseJson = (v: any) => { try { return typeof v === 'string' ? JSON.parse(v) : v || []; } catch { return []; } };

    return c.json({
        success: true,
        data: result.map(m => ({
            id: m.id,
            atlasId: m.atlas_id,
            name: m.name,
            description: m.description,
            techniqueIds: parseJson(m.technique_ids),
            mlLifecycle: parseJson(m.ml_lifecycle),
            category: parseJson(m.category),
        })),
    });
});

// ============================================================================
// ATLAS Case Studies
// ============================================================================

router.get('/case-studies', async (c) => {
    const result = await db.execute(
        sql`SELECT * FROM atlas_case_studies ORDER BY atlas_id`
    ) as any[];

    const parseJson = (v: any) => { try { return typeof v === 'string' ? JSON.parse(v) : v || []; } catch { return []; } };

    return c.json({
        success: true,
        data: result.map(cs => ({
            id: cs.id,
            atlasId: cs.atlas_id,
            name: cs.name,
            summary: cs.summary,
            incidentDate: cs.incident_date,
            reporter: cs.reporter,
            target: cs.target,
            actor: cs.actor,
            techniqueIds: parseJson(cs.technique_ids),
            procedureSteps: parseJson(cs.procedure_steps),
            url: cs.url,
        })),
    });
});

// ============================================================================
// ATLAS Stats
// ============================================================================

router.get('/stats', async (c) => {
    const [tactics, techniques, mitigations, caseStudies, demonstrated, feasible, theoretical] = await Promise.all([
        db.execute(sql`SELECT COUNT(*) as count FROM atlas_tactics`),
        db.execute(sql`SELECT COUNT(*) as count FROM atlas_techniques`),
        db.execute(sql`SELECT COUNT(*) as count FROM atlas_mitigations`),
        db.execute(sql`SELECT COUNT(*) as count FROM atlas_case_studies`),
        db.execute(sql`SELECT COUNT(*) as count FROM atlas_techniques WHERE maturity = 'demonstrated'`),
        db.execute(sql`SELECT COUNT(*) as count FROM atlas_techniques WHERE maturity = 'feasible'`),
        db.execute(sql`SELECT COUNT(*) as count FROM atlas_techniques WHERE maturity = 'theoretical'`),
    ]);

    return c.json({
        success: true,
        data: {
            tactics: Number((tactics as any[])[0]?.count || 0),
            techniques: Number((techniques as any[])[0]?.count || 0),
            mitigations: Number((mitigations as any[])[0]?.count || 0),
            caseStudies: Number((caseStudies as any[])[0]?.count || 0),
            demonstrated: Number((demonstrated as any[])[0]?.count || 0),
            feasible: Number((feasible as any[])[0]?.count || 0),
            theoretical: Number((theoretical as any[])[0]?.count || 0),
        },
    });
});

export default router;
