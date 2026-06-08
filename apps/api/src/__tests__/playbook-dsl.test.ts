/**
 * Playbook condition DSL tests — Phase 4 #3.
 *
 * Locks the legacy-shape compatibility AND the operator vocabulary.
 * The engine wiring lives in apps/api/src/services/playbooks.ts and
 * needs a DB to test E2E; this file covers the deterministic core.
 */
import { describe, it, expect } from 'vitest';
import { evaluateCondition } from '@rinjani/core/playbookDsl';

const event = {
    severity: 'critical',
    type: 'ioc',
    source: 'urlhaus',
    inKev: true,
    revoked: false,
    confidence: 87,
    enrichment: { score: 92, riskLevel: 'high', tags: ['ransomware'] },
    tags: ['c2', 'malware'],
};

describe('evaluateCondition — legacy flat shape', () => {
    it('matches empty/missing condition', () => {
        expect(evaluateCondition(undefined, event)).toBe(true);
        expect(evaluateCondition(null, event)).toBe(true);
        expect(evaluateCondition({}, event)).toBe(true);
    });

    it('matches exact value', () => {
        expect(evaluateCondition({ source: 'urlhaus' }, event)).toBe(true);
        expect(evaluateCondition({ source: 'misp' }, event)).toBe(false);
    });

    it('matches any-of array', () => {
        expect(evaluateCondition({ severity: ['critical', 'high'] }, event)).toBe(true);
        expect(evaluateCondition({ severity: ['low', 'medium'] }, event)).toBe(false);
    });

    it('rejects when an expected key is absent (fixes legacy silent-skip bug)', () => {
        expect(evaluateCondition({ neverPresent: 'x' }, event)).toBe(false);
    });

    it('all top-level keys must hold (implicit AND)', () => {
        expect(evaluateCondition({ severity: 'critical', source: 'urlhaus' }, event)).toBe(true);
        expect(evaluateCondition({ severity: 'critical', source: 'misp' }, event)).toBe(false);
    });
});

describe('evaluateCondition — operators', () => {
    it('$in / $nin', () => {
        expect(evaluateCondition({ severity: { $in: ['critical', 'high'] } }, event)).toBe(true);
        expect(evaluateCondition({ severity: { $nin: ['critical', 'high'] } }, event)).toBe(false);
    });

    it('$eq / $ne', () => {
        expect(evaluateCondition({ source: { $eq: 'urlhaus' } }, event)).toBe(true);
        expect(evaluateCondition({ source: { $ne: 'misp' } }, event)).toBe(true);
        expect(evaluateCondition({ source: { $ne: 'urlhaus' } }, event)).toBe(false);
    });

    it('$gt / $gte / $lt / $lte (numeric)', () => {
        expect(evaluateCondition({ confidence: { $gte: 80 } }, event)).toBe(true);
        expect(evaluateCondition({ confidence: { $gt: 87 } }, event)).toBe(false);
        expect(evaluateCondition({ confidence: { $lt: 100 } }, event)).toBe(true);
        expect(evaluateCondition({ confidence: { $lte: 87 } }, event)).toBe(true);
    });

    it('$exists', () => {
        expect(evaluateCondition({ inKev: { $exists: true } }, event)).toBe(true);
        expect(evaluateCondition({ neverPresent: { $exists: false } }, event)).toBe(true);
        expect(evaluateCondition({ neverPresent: { $exists: true } }, event)).toBe(false);
    });

    it('$regex', () => {
        expect(evaluateCondition({ source: { $regex: '^url' } }, event)).toBe(true);
        expect(evaluateCondition({ source: { $regex: '^misp' } }, event)).toBe(false);
        // Invalid regex → false, never throw
        expect(evaluateCondition({ source: { $regex: '(' } }, event)).toBe(false);
    });

    it('rejects unknown operators (no silent acceptance)', () => {
        expect(evaluateCondition({ source: { $contains: 'url' } }, event)).toBe(false);
    });
});

describe('evaluateCondition — composition', () => {
    it('$and (all must hold)', () => {
        expect(evaluateCondition({
            $and: [
                { severity: 'critical' },
                { inKev: true },
            ],
        }, event)).toBe(true);

        expect(evaluateCondition({
            $and: [
                { severity: 'critical' },
                { inKev: false },
            ],
        }, event)).toBe(false);
    });

    it('$or (any must hold)', () => {
        expect(evaluateCondition({
            $or: [
                { severity: 'low' },
                { inKev: true },
            ],
        }, event)).toBe(true);

        expect(evaluateCondition({
            $or: [
                { severity: 'low' },
                { source: 'misp' },
            ],
        }, event)).toBe(false);
    });

    it('$not', () => {
        expect(evaluateCondition({ $not: { revoked: true } }, event)).toBe(true);
        expect(evaluateCondition({ $not: { severity: 'critical' } }, event)).toBe(false);
    });

    it('nested $and inside $or', () => {
        expect(evaluateCondition({
            $or: [
                { $and: [{ severity: 'critical' }, { inKev: true }] },
                { revoked: true },
            ],
        }, event)).toBe(true);
    });

    it('bare operator at root rejects (no field to bind)', () => {
        expect(evaluateCondition({ $eq: 'critical' } as never, event)).toBe(false);
    });
});

describe('evaluateCondition — dotted-key nested traversal', () => {
    it('reads nested fields', () => {
        expect(evaluateCondition({ 'enrichment.score': { $gte: 90 } }, event)).toBe(true);
        expect(evaluateCondition({ 'enrichment.riskLevel': 'high' }, event)).toBe(true);
    });

    it('rejects on missing nested field', () => {
        expect(evaluateCondition({ 'enrichment.nope': 'x' }, event)).toBe(false);
    });

    it('treats missing parent as missing field', () => {
        expect(evaluateCondition({ 'absent.deep': 'x' }, event)).toBe(false);
    });
});

describe('evaluateCondition — real-world rules', () => {
    it('"severity=critical AND inKev=true" matches', () => {
        const rule = { $and: [{ severity: 'critical' }, { inKev: true }] };
        expect(evaluateCondition(rule, event)).toBe(true);
    });

    it('"high+ severity AND (urlhaus OR threatfox source) AND not revoked"', () => {
        const rule = {
            $and: [
                { severity: { $in: ['critical', 'high'] } },
                { source: { $in: ['urlhaus', 'threatfox'] } },
                { $not: { revoked: true } },
            ],
        };
        expect(evaluateCondition(rule, event)).toBe(true);
        expect(evaluateCondition(rule, { ...event, revoked: true })).toBe(false);
        expect(evaluateCondition(rule, { ...event, source: 'misp' })).toBe(false);
    });
});
