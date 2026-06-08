/**
 * Joe Sandbox + Hybrid Analysis mapper tests.
 *
 * The HTTP submit + poll paths need real API keys to verify end-to-end;
 * those land in the PR's test plan as manual checks. These unit tests
 * lock the deterministic shape mappers so a vendor's response shape
 * change shows up loudly in CI.
 */
import { describe, it, expect } from 'vitest';
import { mapJoeReport } from '../services/sandbox/joesandbox';
import { mapHaState, mapHaSummary } from '../services/sandbox/hybridanalysis';

describe('mapJoeReport', () => {
    it('maps a finished + malicious response', () => {
        const r = mapJoeReport({
            data: {
                status: 'finished',
                analyses: [{ detection: 'malicious', score: 88 }],
            },
        });
        expect(r.status).toBe('completed');
        expect(r.verdict).toBe('malicious');
        expect(r.score).toBe(88);
    });

    it('maps a suspicious analysis', () => {
        const r = mapJoeReport({
            data: { status: 'finished', analyses: [{ detection: 'suspicious', score: 55 }] },
        });
        expect(r.verdict).toBe('suspicious');
    });

    it('maps clean → benign', () => {
        const r = mapJoeReport({
            data: { status: 'finished', analyses: [{ detection: 'clean', score: 5 }] },
        });
        expect(r.verdict).toBe('benign');
    });

    it('returns no verdict while still running', () => {
        const r = mapJoeReport({ data: { status: 'running' } });
        expect(r.status).toBe('running');
        expect(r.verdict).toBeUndefined();
    });

    it('normalises status synonyms', () => {
        expect(mapJoeReport({ data: { status: 'submitted' } }).status).toBe('queued');
        expect(mapJoeReport({ data: { status: 'error' } }).status).toBe('failed');
        expect(mapJoeReport({ data: { status: 'timed_out' } }).status).toBe('timeout');
    });

    it('clamps score to 0-100', () => {
        const big = mapJoeReport({ data: { status: 'finished', analyses: [{ detection: 'malicious', score: 250 }] } });
        expect(big.score).toBe(100);
        const negative = mapJoeReport({ data: { status: 'finished', analyses: [{ detection: 'clean', score: -3 }] } });
        expect(negative.score).toBe(0);
    });

    it('falls back gracefully on a malformed payload', () => {
        expect(mapJoeReport({}).status).toBeUndefined();
        expect(mapJoeReport({ data: {} }).verdict).toBeUndefined();
    });
});

describe('mapHaState', () => {
    it('normalises HA lifecycle strings', () => {
        expect(mapHaState('IN_QUEUE')).toBe('queued');
        expect(mapHaState('IN_PROGRESS')).toBe('running');
        expect(mapHaState('SUCCESS')).toBe('completed');
        expect(mapHaState('ERROR')).toBe('failed');
        expect(mapHaState('TIMEOUT')).toBe('timeout');
    });

    it('returns undefined for unknown states', () => {
        expect(mapHaState('something-weird')).toBeUndefined();
        expect(mapHaState(undefined)).toBeUndefined();
    });
});

describe('mapHaSummary', () => {
    it('maps malicious with a threat_score', () => {
        const r = mapHaSummary({ verdict: 'malicious', threat_score: 78 });
        expect(r.status).toBe('completed');
        expect(r.verdict).toBe('malicious');
        expect(r.score).toBe(78);
    });

    it('maps suspicious', () => {
        const r = mapHaSummary({ verdict: 'suspicious', threat_score: 40 });
        expect(r.verdict).toBe('suspicious');
    });

    it('maps "no specific threat" → benign', () => {
        const r = mapHaSummary({ verdict: 'no specific threat', threat_score: 0 });
        expect(r.verdict).toBe('benign');
    });

    it('maps whitelisted → benign', () => {
        const r = mapHaSummary({ verdict: 'whitelisted' });
        expect(r.verdict).toBe('benign');
    });

    it('clamps + drops malformed scores', () => {
        expect(mapHaSummary({ verdict: 'malicious', threat_score: 250 }).score).toBe(100);
        expect(mapHaSummary({ verdict: 'malicious', threat_score: -10 }).score).toBe(0);
        expect(mapHaSummary({ verdict: 'malicious' }).score).toBeUndefined();
    });

    it('still completes when verdict is unknown', () => {
        const r = mapHaSummary({});
        expect(r.status).toBe('completed');
        expect(r.verdict).toBeUndefined();
    });
});
