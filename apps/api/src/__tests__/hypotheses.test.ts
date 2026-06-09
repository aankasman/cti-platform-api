/**
 * Hypothesis tracking tests — Phase 3 #5.
 *
 * The LLM-grading happy path needs a real provider key (covered in the
 * PR live test plan). These unit tests cover the deterministic parts:
 *
 *   - Zod schemas (subject pair rule, freeform-needs-note, ranges)
 *   - Grading prompt builder (shape + ordering + cap)
 *   - LLM response parser (JSON extraction + clamping + malformed fallback)
 *   - Deterministic fallback grader (weighted avg, edge cases)
 */
import { describe, it, expect } from 'vitest';
import {
    HypothesisCreateSchema, HypothesisListSchema, HypothesisUpdateSchema,
    EvidenceAppendSchema, HypothesisGradeSchema,
} from '../lib/schemas';
import {
    buildGradingPrompt, parseGradingResponse, deterministicGrade,
} from '../services/hypothesisGrading';
import type { Hypothesis, HypothesisEvidence } from '@rinjani/db/schema';

// ── Schemas ────────────────────────────────────────────────────────

describe('HypothesisCreateSchema', () => {
    it('accepts a minimal payload', () => {
        const r = HypothesisCreateSchema.parse({
            title: 'APT99 attribution', claim: 'Group X is using infra Y',
        });
        expect(r.confidenceScore).toBe(50);
        expect(r.subjectType).toBeUndefined();
    });

    it('accepts a typed subject pair', () => {
        const r = HypothesisCreateSchema.parse({
            title: 'x', claim: 'y',
            subjectType: 'threat_actor',
            subjectId: '7e16d3c1-0000-4000-8000-000000000001',
        });
        expect(r.subjectType).toBe('threat_actor');
    });

    it('rejects subjectType without subjectId', () => {
        expect(() => HypothesisCreateSchema.parse({
            title: 'x', claim: 'y', subjectType: 'threat_actor',
        })).toThrow();
    });

    it('rejects subjectId without subjectType', () => {
        expect(() => HypothesisCreateSchema.parse({
            title: 'x', claim: 'y', subjectId: '7e16d3c1-0000-4000-8000-000000000001',
        })).toThrow();
    });

    it('rejects out-of-range initial confidence', () => {
        expect(() => HypothesisCreateSchema.parse({
            title: 'x', claim: 'y', confidenceScore: 101,
        })).toThrow();
    });
});

describe('EvidenceAppendSchema', () => {
    it('accepts a typical entity-pinned evidence row', () => {
        const r = EvidenceAppendSchema.parse({
            evidenceType: 'ioc',
            entityId: 'ioc-uuid-1',
            kind: 'supports',
            weight: 80,
            note: 'observed in C2 traffic',
        });
        expect(r.kind).toBe('supports');
        expect(r.weight).toBe(80);
    });

    it('requires a note for freeform evidence', () => {
        expect(() => EvidenceAppendSchema.parse({
            evidenceType: 'freeform',
            kind: 'refutes',
        })).toThrow();
    });

    it('accepts freeform with note + no entityId', () => {
        const r = EvidenceAppendSchema.parse({
            evidenceType: 'freeform',
            kind: 'refutes',
            note: 'team manually verified the infra is not theirs',
        });
        expect(r.evidenceType).toBe('freeform');
        expect(r.entityId).toBeUndefined();
    });

    it('requires an entityId for non-freeform evidence', () => {
        expect(() => EvidenceAppendSchema.parse({
            evidenceType: 'ioc',
            kind: 'supports',
        })).toThrow();
    });

    it('defaults weight to 50', () => {
        const r = EvidenceAppendSchema.parse({
            evidenceType: 'sighting', entityId: 's-1', kind: 'supports',
        });
        expect(r.weight).toBe(50);
    });
});

describe('HypothesisListSchema', () => {
    it('coerces numeric query strings', () => {
        const r = HypothesisListSchema.parse({ page: '3', pageSize: '25', status: 'active' });
        expect(r.page).toBe(3);
        expect(r.pageSize).toBe(25);
        expect(r.status).toBe('active');
    });

    it('rejects pageSize > 200', () => {
        expect(() => HypothesisListSchema.parse({ pageSize: '500' })).toThrow();
    });
});

describe('HypothesisUpdateSchema + HypothesisGradeSchema', () => {
    it('update accepts a status flip', () => {
        const r = HypothesisUpdateSchema.parse({ status: 'confirmed' });
        expect(r.status).toBe('confirmed');
    });

    it('grade accepts all defaults', () => {
        const r = HypothesisGradeSchema.parse({});
        expect(r.skipLlm).toBeUndefined();
        expect(r.persist).toBeUndefined();
    });
});

// ── Prompt builder ─────────────────────────────────────────────────

const HYP: Hypothesis = {
    id: 'h1',
    title: 'APT99 is using infra X',
    claim: 'Group APT99 controls 198.51.100.0/24',
    status: 'active',
    confidenceScore: 50,
    subjectType: 'threat_actor',
    subjectId: '00000000-0000-4000-8000-000000000001',
    lastGradedAt: null,
    lastGradingReason: null,
    lastGradingProvider: null,
    createdBy: 'analyst-1',
    createdAt: new Date('2026-06-09T00:00:00Z'),
    updatedAt: new Date('2026-06-09T00:00:00Z'),
} as unknown as Hypothesis;

function mkEv(opts: Partial<HypothesisEvidence>): HypothesisEvidence {
    return {
        id: opts.id ?? 'e-' + Math.random().toString(36).slice(2, 8),
        hypothesisId: 'h1',
        evidenceType: opts.evidenceType ?? 'ioc',
        entityId: opts.entityId ?? null,
        kind: opts.kind ?? 'supports',
        weight: opts.weight ?? 50,
        note: opts.note ?? null,
        createdBy: 'analyst-1',
        createdAt: new Date(),
    } as HypothesisEvidence;
}

describe('buildGradingPrompt', () => {
    it('renders the claim + the support/refute split with item counts', () => {
        const prompt = buildGradingPrompt(HYP, [
            mkEv({ kind: 'supports', entityId: 'ioc-1', weight: 80, note: 'C2 beacon observed' }),
            mkEv({ kind: 'refutes', entityId: 'ioc-2', weight: 60, note: 'IP is a known CDN' }),
        ]);
        expect(prompt).toContain('APT99 is using infra X');
        expect(prompt).toContain('Group APT99 controls 198.51.100.0/24');
        expect(prompt).toContain('SUPPORTING (1 item');
        expect(prompt).toContain('REFUTING (1 item');
        expect(prompt).toContain('weight=80');
        expect(prompt).toContain('C2 beacon observed');
        expect(prompt).toContain('IP is a known CDN');
    });

    it('sorts evidence by weight descending so the strongest signals survive the cap', () => {
        const items = [
            mkEv({ kind: 'supports', entityId: 'a', weight: 10, note: 'weak' }),
            mkEv({ kind: 'supports', entityId: 'b', weight: 90, note: 'strongest' }),
            mkEv({ kind: 'supports', entityId: 'c', weight: 50, note: 'middling' }),
        ];
        const prompt = buildGradingPrompt(HYP, items);
        // Strongest appears before middling, which appears before weak
        expect(prompt.indexOf('strongest')).toBeLessThan(prompt.indexOf('middling'));
        expect(prompt.indexOf('middling')).toBeLessThan(prompt.indexOf('weak'));
    });

    it('caps each side at 25 items', () => {
        const huge = Array.from({ length: 50 }, (_, i) =>
            mkEv({ kind: 'supports', entityId: `s-${i}`, weight: i, note: `item-${i}` }),
        );
        const prompt = buildGradingPrompt(HYP, huge);
        // item-49 should appear (highest weight), item-24 (25th highest) should appear,
        // item-23 (26th highest) should NOT appear in the rendered list.
        expect(prompt).toContain('item-49');
        expect(prompt).toContain('item-25');
        expect(prompt).not.toContain('item-23');
    });

    it('renders the empty case with "(none)" placeholders', () => {
        const prompt = buildGradingPrompt(HYP, []);
        expect(prompt).toMatch(/SUPPORTING \(0 items\):\s*\(none\)/);
        expect(prompt).toMatch(/REFUTING \(0 items\):\s*\(none\)/);
    });

    it('marks "(no note)" when an evidence row has no note text', () => {
        const prompt = buildGradingPrompt(HYP, [mkEv({ kind: 'supports', entityId: 'x', note: null })]);
        expect(prompt).toContain('(no note)');
    });
});

// ── Response parser ────────────────────────────────────────────────

describe('parseGradingResponse', () => {
    it('parses a clean JSON envelope', () => {
        const r = parseGradingResponse('{"confidence":72,"reasoning":"two strong supports, one weak refute"}');
        expect(r?.confidence).toBe(72);
        expect(r?.reasoning).toContain('strong supports');
    });

    it('handles JSON wrapped in stray prose', () => {
        const r = parseGradingResponse('Here is my grade: {"confidence":35,"reasoning":"more refute than support"} done.');
        expect(r?.confidence).toBe(35);
    });

    it('rounds non-integer confidence', () => {
        const r = parseGradingResponse('{"confidence":50.7,"reasoning":"x"}');
        expect(r?.confidence).toBe(51);
    });

    it('rejects out-of-range confidence', () => {
        expect(parseGradingResponse('{"confidence":150,"reasoning":"x"}')).toBeNull();
        expect(parseGradingResponse('{"confidence":-10,"reasoning":"x"}')).toBeNull();
    });

    it('rejects missing JSON', () => {
        expect(parseGradingResponse('just plain prose no json')).toBeNull();
    });

    it('rejects malformed JSON', () => {
        expect(parseGradingResponse('{confidence: 50}')).toBeNull();
    });
});

// ── Deterministic fallback ────────────────────────────────────────

describe('deterministicGrade', () => {
    it('returns neutral 50 with no evidence', () => {
        const r = deterministicGrade([]);
        expect(r.confidence).toBe(50);
        expect(r.reasoning).toMatch(/no evidence/i);
    });

    it('returns 100 when all evidence supports with positive weight', () => {
        const r = deterministicGrade([
            mkEv({ kind: 'supports', weight: 80 }),
            mkEv({ kind: 'supports', weight: 60 }),
        ]);
        expect(r.confidence).toBe(100);
    });

    it('returns 0 when all evidence refutes', () => {
        const r = deterministicGrade([
            mkEv({ kind: 'refutes', weight: 70 }),
        ]);
        expect(r.confidence).toBe(0);
    });

    it('weights evidence proportionally', () => {
        // 60% support, 40% refute → 60
        const r = deterministicGrade([
            mkEv({ kind: 'supports', weight: 60 }),
            mkEv({ kind: 'refutes', weight: 40 }),
        ]);
        expect(r.confidence).toBe(60);
    });

    it('returns neutral 50 when all evidence has weight 0', () => {
        const r = deterministicGrade([
            mkEv({ kind: 'supports', weight: 0 }),
            mkEv({ kind: 'refutes', weight: 0 }),
        ]);
        expect(r.confidence).toBe(50);
    });
});
