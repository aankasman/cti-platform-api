/**
 * Sandbox scaffold tests — Phase 4 #5.
 *
 * Network-side submit/poll integration needs a real ANY.RUN account,
 * so those paths get manual verification per the PR's test plan. These
 * unit tests cover the deterministic core:
 *   - the ANY.RUN report mapper (status / verdict / score normalisation)
 *   - the Zod schemas (vendor / type / status enums; UUID + size caps)
 */
import { describe, it, expect } from 'vitest';
import { mapAnyRunReport } from '../services/sandbox/anyrun';
import { SandboxSubmitSchema, SandboxListFiltersSchema } from '../lib/schemas';

describe('mapAnyRunReport', () => {
    it('maps a completed-malicious report', () => {
        const r = mapAnyRunReport({
            analysis: {
                status: 'done',
                scores: { verdict: { threat_level: 3, score: 92 } },
            },
        });
        expect(r.status).toBe('completed');
        expect(r.verdict).toBe('malicious');
        expect(r.score).toBe(92);
    });

    it('maps a suspicious verdict (threat_level=2)', () => {
        const r = mapAnyRunReport({
            analysis: { status: 'done', scores: { verdict: { threat_level: 2, score: 55 } } },
        });
        expect(r.verdict).toBe('suspicious');
    });

    it('maps a benign verdict (threat_level=0)', () => {
        const r = mapAnyRunReport({
            analysis: { status: 'done', scores: { verdict: { threat_level: 0, score: 5 } } },
        });
        expect(r.verdict).toBe('benign');
    });

    it('returns no verdict while still running', () => {
        const r = mapAnyRunReport({ analysis: { status: 'running' } });
        expect(r.status).toBe('running');
        expect(r.verdict).toBeUndefined();
    });

    it('normalises ANY.RUN status synonyms', () => {
        expect(mapAnyRunReport({ analysis: { status: 'preparing' } }).status).toBe('queued');
        expect(mapAnyRunReport({ analysis: { status: 'processing' } }).status).toBe('running');
        expect(mapAnyRunReport({ analysis: { status: 'error' } }).status).toBe('failed');
        expect(mapAnyRunReport({ analysis: { status: 'timed_out' } }).status).toBe('timeout');
    });

    it('clamps score to 0-100', () => {
        const r1 = mapAnyRunReport({
            analysis: { status: 'done', scores: { verdict: { threat_level: 3, score: 250 } } },
        });
        expect(r1.score).toBe(100);
        const r2 = mapAnyRunReport({
            analysis: { status: 'done', scores: { verdict: { threat_level: 0, score: -5 } } },
        });
        expect(r2.score).toBe(0);
    });

    it('falls back gracefully on missing fields', () => {
        const r = mapAnyRunReport({});
        expect(r.status).toBeUndefined();
        expect(r.verdict).toBeUndefined();
        expect(r.score).toBeUndefined();
    });
});

describe('SandboxSubmitSchema', () => {
    const valid = { vendor: 'anyrun', value: 'https://evil.test/payload.exe', type: 'url' };

    it('accepts minimal valid payload', () => {
        const r = SandboxSubmitSchema.parse(valid);
        expect(r.vendor).toBe('anyrun');
    });

    it('rejects unknown vendor', () => {
        expect(() => SandboxSubmitSchema.parse({ ...valid, vendor: 'cuckoo' })).toThrow();
    });

    it('rejects unknown type', () => {
        expect(() => SandboxSubmitSchema.parse({ ...valid, type: 'dns' })).toThrow();
    });

    it('rejects values that are too long', () => {
        expect(() => SandboxSubmitSchema.parse({ ...valid, value: 'x'.repeat(3000) })).toThrow();
    });

    it('requires iocId to be a UUID when provided', () => {
        expect(() => SandboxSubmitSchema.parse({ ...valid, iocId: 'not-a-uuid' })).toThrow();
        const ok = SandboxSubmitSchema.parse({ ...valid, iocId: '11111111-2222-3333-4444-555555555555' });
        expect(ok.iocId).toBe('11111111-2222-3333-4444-555555555555');
    });

    it('accepts vendor-passthrough options', () => {
        const r = SandboxSubmitSchema.parse({ ...valid, options: { env: 'win10', locale: 'en' } });
        expect(r.options).toMatchObject({ env: 'win10', locale: 'en' });
    });
});

describe('SandboxListFiltersSchema', () => {
    it('defaults page/pageSize', () => {
        const r = SandboxListFiltersSchema.parse({});
        expect(r.page).toBe(1);
        expect(r.pageSize).toBe(50);
    });

    it('coerces numeric query strings', () => {
        const r = SandboxListFiltersSchema.parse({ page: '3', pageSize: '25', status: 'completed' });
        expect(r.page).toBe(3);
        expect(r.pageSize).toBe(25);
        expect(r.status).toBe('completed');
    });

    it('rejects unknown status', () => {
        expect(() => SandboxListFiltersSchema.parse({ status: 'submitted' })).toThrow();
    });
});
