/**
 * Brand-monitor tests — Phase 5 #1.
 *
 * Covers the pure pieces: permutation generator behaviour + the
 * scoring function. The DNS sweep + DB upsert path needs live network
 * + Postgres and is covered in the PR test plan.
 */
import { describe, it, expect } from 'vitest';
import {
    generatePermutations, splitApex, levenshtein, scoreAlert,
} from '@rinjani/core/domainPermutations';
import {
    MonitoredDomainCreateSchema, BrandAlertListSchema, BrandAlertUpdateSchema,
} from '../lib/schemas';

// ── splitApex ─────────────────────────────────────────────────────

describe('splitApex', () => {
    it('splits a 2-component apex', () => {
        expect(splitApex('rinjanianalytics.com')).toEqual({ label: 'rinjanianalytics', tld: 'com' });
    });

    it('handles co.uk-style 2-char trailing TLDs', () => {
        expect(splitApex('example.co.uk')).toEqual({ label: 'example', tld: 'co.uk' });
    });

    it('lowercases the input', () => {
        expect(splitApex('Example.COM')).toEqual({ label: 'example', tld: 'com' });
    });

    it('throws on a bare label with no TLD', () => {
        expect(() => splitApex('example')).toThrow();
    });
});

// ── generatePermutations ──────────────────────────────────────────

describe('generatePermutations', () => {
    it('produces multiple algorithm types for a typical apex', () => {
        const out = generatePermutations('rinjani.com');
        const algos = new Set(out.map(o => o.algorithm));
        expect(algos.has('homoglyph')).toBe(true);
        expect(algos.has('insertion')).toBe(true);
        expect(algos.has('omission')).toBe(true);
        expect(algos.has('substitution')).toBe(true);
        expect(algos.has('transposition')).toBe(true);
        expect(algos.has('vowel-swap')).toBe(true);
        expect(algos.has('hyphenation')).toBe(true);
        expect(algos.has('subdomain')).toBe(true);
    });

    it('never produces the apex itself', () => {
        const out = generatePermutations('rinjani.com');
        expect(out.some(o => o.value === 'rinjani.com')).toBe(false);
    });

    it('emits homoglyph swaps as expected (l→1, o→0)', () => {
        const out = generatePermutations('rinjani.com');
        const homoglyphs = out.filter(o => o.algorithm === 'homoglyph').map(o => o.value);
        // r→ no map; i→1; n→m; a→4,@; etc. Expect at least one
        expect(homoglyphs.length).toBeGreaterThan(0);
        // 'rinjani' has 'i' which homoglyphs to '1' and 'l', so we should see r1njani
        expect(homoglyphs).toContain('r1njani.com');
    });

    it('emits transposition pairs (swap adjacent)', () => {
        const out = generatePermutations('abcd.com');
        const transposed = out.filter(o => o.algorithm === 'transposition').map(o => o.value);
        expect(transposed).toContain('bacd.com');
        expect(transposed).toContain('acbd.com');
        expect(transposed).toContain('abdc.com');
    });

    it('emits omissions (drop one char) only for labels longer than 2', () => {
        const longOut = generatePermutations('abcd.com');
        const longOmissions = longOut.filter(o => o.algorithm === 'omission').map(o => o.value);
        expect(longOmissions).toContain('bcd.com');
        expect(longOmissions).toContain('abd.com');
        // 2-char label should produce no omissions
        const shortOut = generatePermutations('ab.com');
        expect(shortOut.filter(o => o.algorithm === 'omission')).toHaveLength(0);
    });

    it('emits subdomain prefixes', () => {
        const out = generatePermutations('rinjani.com');
        const subs = out.filter(o => o.algorithm === 'subdomain').map(o => o.value);
        expect(subs).toContain('www.rinjani.com');
        expect(subs).toContain('login.rinjani.com');
    });

    it('emits hyphenation but skips edge positions', () => {
        const out = generatePermutations('abcd.com');
        const hyphenated = out.filter(o => o.algorithm === 'hyphenation').map(o => o.value);
        expect(hyphenated).toContain('a-bcd.com');
        expect(hyphenated).toContain('abc-d.com');
        // Should not have a leading or trailing hyphen
        expect(hyphenated.every(h => !h.startsWith('-') && !h.endsWith('-'))).toBe(true);
    });

    it('dedupes — no two entries share the same value', () => {
        const out = generatePermutations('rinjani.com');
        const values = out.map(o => o.value);
        expect(new Set(values).size).toBe(values.length);
    });

    it('respects maxPerAlgorithm cap', () => {
        const out = generatePermutations('rinjanianalyticscom.com', { maxPerAlgorithm: 5 });
        for (const alg of new Set(out.map(o => o.algorithm))) {
            expect(out.filter(o => o.algorithm === alg).length).toBeLessThanOrEqual(5);
        }
    });
});

// ── Levenshtein ───────────────────────────────────────────────────

describe('levenshtein', () => {
    it('returns 0 for equal strings', () => {
        expect(levenshtein('abc', 'abc')).toBe(0);
    });

    it('returns the length for an empty other side', () => {
        expect(levenshtein('abc', '')).toBe(3);
        expect(levenshtein('', 'abc')).toBe(3);
    });

    it('counts single-character edits', () => {
        expect(levenshtein('cat', 'bat')).toBe(1);   // substitution
        expect(levenshtein('cat', 'cats')).toBe(1);  // insertion
        expect(levenshtein('cats', 'cat')).toBe(1);  // deletion
    });

    it('reports the classic kitten/sitting distance of 3', () => {
        expect(levenshtein('kitten', 'sitting')).toBe(3);
    });
});

// ── scoreAlert ────────────────────────────────────────────────────

describe('scoreAlert', () => {
    const now = new Date('2026-06-09T12:00:00Z');

    it('scores a typical hot alert at 100 (active + fresh + same-TLD + edit-distance 1)', () => {
        const score = scoreAlert({
            apex: 'rinjani.com',
            permutation: 'rinjamï.com', // close but not exactly distance 1; use clear case below
            dnsState: 'active',
            firstSeenAt: now,
            now,
        });
        // Above example may not satisfy distance ≤ 2 if Unicode breaks it.
        // Use a cleaner one:
        const score2 = scoreAlert({
            apex: 'rinjani.com',
            permutation: 'rinjami.com', // distance 1, same TLD
            dnsState: 'active',
            firstSeenAt: now,
            now,
        });
        expect(score2).toBe(100);
        // Score must be in [0, 100]
        expect(score).toBeGreaterThanOrEqual(0);
        expect(score).toBeLessThanOrEqual(100);
    });

    it('skips the active bonus when dnsState is nx', () => {
        const score = scoreAlert({
            apex: 'rinjani.com',
            permutation: 'rinjami.com',
            dnsState: 'nx',
            firstSeenAt: now,
            now,
        });
        // No 40 for active, but 20 fresh + 20 same TLD + 20 distance = 60
        expect(score).toBe(60);
    });

    it('counts mx_only as a hit (same +40 as active)', () => {
        const active = scoreAlert({
            apex: 'rinjani.com', permutation: 'rinjami.com',
            dnsState: 'active', firstSeenAt: now, now,
        });
        const mxOnly = scoreAlert({
            apex: 'rinjani.com', permutation: 'rinjami.com',
            dnsState: 'mx_only', firstSeenAt: now, now,
        });
        expect(mxOnly).toBe(active);
    });

    it('drops the fresh bonus after 7 days', () => {
        const old = new Date(now.getTime() - 10 * 24 * 3600 * 1000);
        const score = scoreAlert({
            apex: 'rinjani.com', permutation: 'rinjami.com',
            dnsState: 'active', firstSeenAt: old, now,
        });
        // 40 active + 20 same TLD + 20 distance = 80 (no freshness)
        expect(score).toBe(80);
    });

    it('skips the same-TLD bonus when TLDs differ', () => {
        const score = scoreAlert({
            apex: 'rinjani.com', permutation: 'rinjani.io', // distance 1, different TLD
            dnsState: 'active', firstSeenAt: now, now,
        });
        // 40 active + 20 fresh + 0 TLD + 20 distance = 80
        expect(score).toBe(80);
    });

    it('caps at 100 even when all bonuses apply', () => {
        const score = scoreAlert({
            apex: 'abcd.com', permutation: 'abce.com', // distance 1, same tld
            dnsState: 'active', firstSeenAt: now, now,
        });
        expect(score).toBeLessThanOrEqual(100);
    });
});

// ── Zod schemas ───────────────────────────────────────────────────

describe('MonitoredDomainCreateSchema', () => {
    it('accepts a valid apex and lowercases it', () => {
        const r = MonitoredDomainCreateSchema.parse({ apexDomain: 'Rinjani.COM' });
        expect(r.apexDomain).toBe('rinjani.com');
        expect(r.enabled).toBe(true);
    });

    it('rejects malformed apexes', () => {
        expect(() => MonitoredDomainCreateSchema.parse({ apexDomain: 'no-tld' })).toThrow();
        expect(() => MonitoredDomainCreateSchema.parse({ apexDomain: '.com' })).toThrow();
        expect(() => MonitoredDomainCreateSchema.parse({ apexDomain: 'a@b.com' })).toThrow();
    });
});

describe('BrandAlertListSchema + BrandAlertUpdateSchema', () => {
    it('list coerces numeric query strings', () => {
        const r = BrandAlertListSchema.parse({ page: '2', pageSize: '20', minScore: '60' });
        expect(r.page).toBe(2);
        expect(r.pageSize).toBe(20);
        expect(r.minScore).toBe(60);
    });

    it('list rejects unknown status', () => {
        expect(() => BrandAlertListSchema.parse({ status: 'archived' })).toThrow();
    });

    it('update accepts a status flip', () => {
        const r = BrandAlertUpdateSchema.parse({ status: 'escalated' });
        expect(r.status).toBe('escalated');
    });
});
