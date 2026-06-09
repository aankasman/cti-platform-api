/**
 * Hypothesis tracking routes — Phase 3 #5.
 *
 *   POST   /v1/hypotheses                       Create
 *   GET    /v1/hypotheses                       List (filterable)
 *   GET    /v1/hypotheses/:id                   Detail + evidence + last grading
 *   PATCH  /v1/hypotheses/:id                   Update title/claim/status
 *   POST   /v1/hypotheses/:id/evidence          Append evidence
 *   GET    /v1/hypotheses/:id/evidence          List evidence
 *   POST   /v1/hypotheses/:id/grade             Re-grade via LLM
 */
import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../middleware/auth';
import { NotFoundError } from '../../lib/errors';
import {
    HypothesisCreateSchema, HypothesisListSchema, HypothesisUpdateSchema,
    EvidenceAppendSchema, HypothesisGradeSchema,
} from '../../lib/schemas';
import { db, eq, and, desc, asc, sql } from '@rinjani/db';
import {
    hypotheses, hypothesisEvidence,
    type HypothesisSubjectType,
} from '@rinjani/db/schema';
import { gradeHypothesis } from '../../services/hypothesisGrading';
import { createLogger } from '../../lib/logger';

const log = createLogger('Hypotheses');
const router = new Hono();

// ── Create + list ──────────────────────────────────────────────────

router.post('/hypotheses', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const body = HypothesisCreateSchema.parse(await c.req.json());
    const userId = c.get('user')?.id || 'unknown';
    const [row] = await db.insert(hypotheses).values({
        title: body.title,
        claim: body.claim,
        subjectType: body.subjectType ?? null,
        subjectId: body.subjectId ?? null,
        confidenceScore: body.confidenceScore,
        createdBy: userId,
    }).returning();
    log.info('Hypothesis created', { id: row.id, title: body.title });
    return c.json({ success: true, data: row }, 201);
});

router.get('/hypotheses', requireAuth, async (c) => {
    const f = HypothesisListSchema.parse(c.req.query());
    const conds = [];
    if (f.status) conds.push(eq(hypotheses.status, f.status));
    if (f.subjectType) conds.push(eq(hypotheses.subjectType, f.subjectType as HypothesisSubjectType));
    if (f.subjectId) conds.push(eq(hypotheses.subjectId, f.subjectId));
    const where = conds.length === 0 ? undefined : conds.length === 1 ? conds[0] : and(...conds);
    const offset = (f.page - 1) * f.pageSize;

    const [items, totals] = await Promise.all([
        db.select().from(hypotheses)
            .where(where ?? sql`true`)
            .orderBy(desc(hypotheses.createdAt))
            .limit(f.pageSize).offset(offset),
        db.select({ c: sql<number>`count(*)::int` }).from(hypotheses).where(where ?? sql`true`),
    ]);
    return c.json({
        success: true,
        data: items,
        pagination: { page: f.page, pageSize: f.pageSize, total: totals[0]?.c ?? 0 },
    });
});

// ── Detail + lifecycle ─────────────────────────────────────────────

router.get('/hypotheses/:id', requireAuth, async (c) => {
    const id = c.req.param('id')!;
    const [row] = await db.select().from(hypotheses).where(eq(hypotheses.id, id)).limit(1);
    if (!row) throw new NotFoundError('Hypothesis', id);
    const evidence = await db.select().from(hypothesisEvidence)
        .where(eq(hypothesisEvidence.hypothesisId, id))
        .orderBy(asc(hypothesisEvidence.createdAt));
    return c.json({
        success: true,
        data: {
            ...row,
            evidence,
            stats: {
                supports: evidence.filter(e => e.kind === 'supports').length,
                refutes: evidence.filter(e => e.kind === 'refutes').length,
            },
        },
    });
});

router.patch('/hypotheses/:id', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const id = c.req.param('id')!;
    const body = HypothesisUpdateSchema.parse(await c.req.json());
    const patch: Record<string, unknown> = { updatedAt: new Date() };
    if (body.status !== undefined) patch.status = body.status;
    if (body.title !== undefined) patch.title = body.title;
    if (body.claim !== undefined) patch.claim = body.claim;
    const [row] = await db.update(hypotheses).set(patch).where(eq(hypotheses.id, id)).returning();
    if (!row) throw new NotFoundError('Hypothesis', id);
    return c.json({ success: true, data: row });
});

// ── Evidence ──────────────────────────────────────────────────────

router.post('/hypotheses/:id/evidence', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const id = c.req.param('id')!;
    const body = EvidenceAppendSchema.parse(await c.req.json());
    const [parent] = await db.select({ id: hypotheses.id, status: hypotheses.status })
        .from(hypotheses).where(eq(hypotheses.id, id)).limit(1);
    if (!parent) throw new NotFoundError('Hypothesis', id);
    if (parent.status !== 'active') {
        return c.json({
            success: false,
            error: { code: 'NOT_ACTIVE', message: `hypothesis is ${parent.status}; reopen it before adding evidence` },
        }, 409);
    }
    const userId = c.get('user')?.id || 'unknown';
    const [row] = await db.insert(hypothesisEvidence).values({
        hypothesisId: id,
        evidenceType: body.evidenceType,
        entityId: body.entityId ?? null,
        kind: body.kind,
        weight: body.weight,
        note: body.note ?? null,
        createdBy: userId,
    }).returning();
    return c.json({ success: true, data: row }, 201);
});

router.get('/hypotheses/:id/evidence', requireAuth, async (c) => {
    const id = c.req.param('id')!;
    const rows = await db.select().from(hypothesisEvidence)
        .where(eq(hypothesisEvidence.hypothesisId, id))
        .orderBy(asc(hypothesisEvidence.createdAt));
    return c.json({ success: true, data: rows });
});

// ── Grading ───────────────────────────────────────────────────────

router.post('/hypotheses/:id/grade', requireAuth, requireRole('admin', 'analyst'), async (c) => {
    const id = c.req.param('id')!;
    const body = HypothesisGradeSchema.parse(await c.req.json().catch(() => ({})));
    const [row] = await db.select().from(hypotheses).where(eq(hypotheses.id, id)).limit(1);
    if (!row) throw new NotFoundError('Hypothesis', id);

    const evidence = await db.select().from(hypothesisEvidence)
        .where(eq(hypothesisEvidence.hypothesisId, id))
        .orderBy(asc(hypothesisEvidence.createdAt));

    const result = await gradeHypothesis(row, evidence, {
        provider: body.provider,
        skipLlm: body.skipLlm,
    });

    let updated = row;
    if (body.persist !== false) {
        const [persisted] = await db.update(hypotheses).set({
            confidenceScore: result.confidence,
            lastGradedAt: new Date(),
            lastGradingReason: result.reasoning,
            lastGradingProvider: result.provider,
            updatedAt: new Date(),
        }).where(eq(hypotheses.id, id)).returning();
        if (persisted) updated = persisted;
    }

    return c.json({
        success: true,
        data: {
            confidence: result.confidence,
            reasoning: result.reasoning,
            provider: result.provider,
            fallback: result.fallback,
            evidenceCount: evidence.length,
            hypothesis: updated,
        },
    });
});

export default router;
