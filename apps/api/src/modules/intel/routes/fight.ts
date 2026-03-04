/**
 * MITRE FiGHT Routes (5G Hierarchy of Threats)
 *
 * Endpoints for FiGHT framework data: techniques, tactics, mitigations, and matrix.
 */

import { Hono } from 'hono';
import { db, sql } from '@rinjani/db';

const router = new Hono();

// ============================================================================
// FiGHT Matrix — Full matrix data for the /fight page
// ============================================================================

router.get('/matrix', async (c) => {
    // Fetch all tactics, techniques, and group mappings in parallel
    const [tacticsRes, techniquesRes, groupsRes, mitigationsRes] = await Promise.all([
        db.execute(sql`SELECT * FROM fight_tactics ORDER BY mitre_id`),
        db.execute(sql`SELECT * FROM fight_techniques ORDER BY fight_id`),
        db.execute(sql`
            SELECT gt.group_name, gt.fight_technique_id, gt.technique_name, gt.description,
                   ta.stix_id AS actor_stix_id
            FROM fight_group_techniques gt
            LEFT JOIN threat_actors ta ON ta.name = gt.group_name
            ORDER BY gt.group_name
        `),
        db.execute(sql`SELECT fight_id, name, technique_ids FROM fight_mitigations ORDER BY fight_id`),
    ]);

    // Parse JSONB fields
    const tactics = (tacticsRes as any[]).map(t => ({
        id: t.id,
        mitreId: t.mitre_id,
        name: t.name,
        description: t.description,
        shortName: t.short_name,
    }));

    const techniques = (techniquesRes as any[]).map(t => {
        let tacticIds: string[] = [];
        let platforms: string[] = [];
        let criticalAssets: any[] = [];
        let preconditions: any[] = [];
        let detections: any[] = [];
        try { tacticIds = typeof t.tactic_ids === 'string' ? JSON.parse(t.tactic_ids) : t.tactic_ids || []; } catch { }
        try { platforms = typeof t.platforms === 'string' ? JSON.parse(t.platforms) : t.platforms || []; } catch { }
        try { criticalAssets = typeof t.critical_assets === 'string' ? JSON.parse(t.critical_assets) : t.critical_assets || []; } catch { }
        try { preconditions = typeof t.preconditions === 'string' ? JSON.parse(t.preconditions) : t.preconditions || []; } catch { }
        try { detections = typeof t.detections === 'string' ? JSON.parse(t.detections) : t.detections || []; } catch { }

        return {
            id: t.id,
            fightId: t.fight_id,
            name: t.name,
            description: t.description,
            bluf: t.bluf,
            status: t.status,
            architectureSegment: t.architecture_segment,
            typecode: t.typecode,
            tacticIds,
            platforms,
            criticalAssets,
            preconditions,
            detections,
            url: t.url,
        };
    });

    // Build group→techniques lookup
    const groupMap = new Map<string, { name: string; techniques: string[] }>();
    for (const g of (groupsRes as any[])) {
        if (!groupMap.has(g.group_name)) {
            groupMap.set(g.group_name, { name: g.group_name, techniques: [] });
        }
        groupMap.get(g.group_name)!.techniques.push(g.fight_technique_id);
    }

    // Build mitigation lookup
    const mitigationMap: Record<string, string[]> = {};
    for (const m of (mitigationsRes as any[])) {
        let techIds: string[] = [];
        try { techIds = typeof m.technique_ids === 'string' ? JSON.parse(m.technique_ids) : m.technique_ids || []; } catch { }
        for (const tid of techIds) {
            const id = typeof tid === 'string' ? tid : (tid as any)?.id || '';
            if (!mitigationMap[id]) mitigationMap[id] = [];
            mitigationMap[id].push(m.fight_id);
        }
    }

    return c.json({
        success: true,
        data: {
            tactics,
            techniques,
            groups: Array.from(groupMap.values()),
            mitigationMap,
            stats: {
                tactics: tactics.length,
                techniques: techniques.length,
                groups: groupMap.size,
                mitigations: (mitigationsRes as any[]).length,
            },
        },
    });
});

// ============================================================================
// FiGHT Techniques — List with filtering
// ============================================================================

router.get('/techniques', async (c) => {
    const { tactic, status, segment, q, limit = '50' } = c.req.query();
    const lim = Math.min(parseInt(limit) || 50, 200);

    const conditions: ReturnType<typeof sql>[] = [];

    if (tactic) {
        conditions.push(sql`tactic_ids::text ILIKE ${'%' + tactic + '%'}`);
    }
    if (status) {
        conditions.push(sql`status ILIKE ${'%' + status + '%'}`);
    }
    if (segment) {
        conditions.push(sql`architecture_segment ILIKE ${'%' + segment + '%'}`);
    }
    if (q) {
        conditions.push(sql`(name ILIKE ${'%' + q + '%'} OR description ILIKE ${'%' + q + '%'} OR bluf ILIKE ${'%' + q + '%'})`);
    }

    const whereClause = conditions.length > 0
        ? sql`WHERE ${sql.join(conditions, sql` AND `)}`
        : sql``;

    const result = await db.execute(sql`SELECT * FROM fight_techniques ${whereClause} ORDER BY fight_id LIMIT ${lim}`) as any[];

    const items = result.map(t => {
        let tacticIds: string[] = [];
        let platforms: string[] = [];
        try { tacticIds = typeof t.tactic_ids === 'string' ? JSON.parse(t.tactic_ids) : t.tactic_ids || []; } catch { }
        try { platforms = typeof t.platforms === 'string' ? JSON.parse(t.platforms) : t.platforms || []; } catch { }

        return {
            id: t.id,
            fightId: t.fight_id,
            name: t.name,
            bluf: t.bluf,
            status: t.status,
            architectureSegment: t.architecture_segment,
            tacticIds,
            platforms,
            url: t.url,
        };
    });

    return c.json({ success: true, data: items, total: items.length });
});

// ============================================================================
// FiGHT Technique Detail
// ============================================================================

router.get('/techniques/:fightId', async (c) => {
    const { fightId } = c.req.param();
    const result = await db.execute(
        sql`SELECT * FROM fight_techniques WHERE fight_id = ${fightId}`
    ) as any[];

    if (!result.length) {
        return c.json({ success: false, error: 'Not found' }, 404);
    }

    const t = result[0];
    const parseJson = (v: any) => {
        try { return typeof v === 'string' ? JSON.parse(v) : v || []; } catch { return []; }
    };

    return c.json({
        success: true,
        data: {
            id: t.id,
            fightId: t.fight_id,
            name: t.name,
            description: t.description,
            bluf: t.bluf,
            status: t.status,
            architectureSegment: t.architecture_segment,
            typecode: t.typecode,
            tacticIds: parseJson(t.tactic_ids),
            platforms: parseJson(t.platforms),
            criticalAssets: parseJson(t.critical_assets),
            preconditions: parseJson(t.preconditions),
            postconditions: parseJson(t.postconditions),
            detections: parseJson(t.detections),
            procedureExamples: parseJson(t.procedure_examples),
            references: parseJson(t.references),
            url: t.url,
        },
    });
});

// ============================================================================
// FiGHT Tactics
// ============================================================================

router.get('/tactics', async (c) => {
    const result = await db.execute(
        sql`SELECT * FROM fight_tactics ORDER BY mitre_id`
    ) as any[];

    return c.json({
        success: true,
        data: result.map(t => ({
            id: t.id,
            mitreId: t.mitre_id,
            name: t.name,
            description: t.description,
            shortName: t.short_name,
        })),
    });
});

// ============================================================================
// FiGHT Mitigations
// ============================================================================

router.get('/mitigations', async (c) => {
    const result = await db.execute(
        sql`SELECT * FROM fight_mitigations ORDER BY fight_id`
    ) as any[];

    return c.json({
        success: true,
        data: result.map(m => {
            let techIds: string[] = [];
            try { techIds = typeof m.technique_ids === 'string' ? JSON.parse(m.technique_ids) : m.technique_ids || []; } catch { }
            return {
                id: m.id,
                fightId: m.fight_id,
                name: m.name,
                description: m.description,
                techniqueIds: techIds,
            };
        }),
    });
});

// ============================================================================
// FiGHT Stats
// ============================================================================

router.get('/stats', async (c) => {
    const [tactics, techniques, mitigations, groups, observed, poc, theoretical] = await Promise.all([
        db.execute(sql`SELECT COUNT(*) as count FROM fight_tactics`),
        db.execute(sql`SELECT COUNT(*) as count FROM fight_techniques`),
        db.execute(sql`SELECT COUNT(*) as count FROM fight_mitigations`),
        db.execute(sql`SELECT COUNT(DISTINCT group_name) as count FROM fight_group_techniques`),
        db.execute(sql`SELECT COUNT(*) as count FROM fight_techniques WHERE status ILIKE '%observed%'`),
        db.execute(sql`SELECT COUNT(*) as count FROM fight_techniques WHERE status ILIKE '%poc%' OR status ILIKE '%proof%'`),
        db.execute(sql`SELECT COUNT(*) as count FROM fight_techniques WHERE status ILIKE '%theoretical%'`),
    ]);

    return c.json({
        success: true,
        data: {
            tactics: Number((tactics as any[])[0]?.count || 0),
            techniques: Number((techniques as any[])[0]?.count || 0),
            mitigations: Number((mitigations as any[])[0]?.count || 0),
            groups: Number((groups as any[])[0]?.count || 0),
            observed: Number((observed as any[])[0]?.count || 0),
            poc: Number((poc as any[])[0]?.count || 0),
            theoretical: Number((theoretical as any[])[0]?.count || 0),
        },
    });
});

export default router;
