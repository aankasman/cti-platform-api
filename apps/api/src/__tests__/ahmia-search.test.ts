/**
 * Ahmia search tests — Phase 5 #4.
 *
 * Live fetch + DB upsert path lives in the PR test plan. Here we pin
 * down the deterministic part — the HTML parser — and the Zod
 * schemas the routes rely on.
 */
import { describe, it, expect } from 'vitest';
import { parseAhmiaResults } from '../services/ahmiaSearch';
import {
    DarkWebWatchtermCreateSchema, DarkWebMentionListSchema, DarkWebMentionUpdateSchema,
} from '../lib/schemas';

// Synthesised Ahmia HTML — matches the documented result shape close
// enough that real-world responses parse correctly. Two genuine result
// rows + one bogus row (cite missing, non-onion URL) we expect dropped.
const SAMPLE_HTML = `
<html><body>
    <ol id="ahmiaResultsPage">
        <li class="result">
            <h4><a href="/search/redirect?redirect_url=http://example1234567890abcd.onion/leak">APT99 leak archive</a></h4>
            <cite>http://example1234567890abcd.onion/leak</cite>
            <p>Folder dump described as Rinjani internal docs Q2 2026.</p>
        </li>
        <li class="result">
            <h4><a href="/search/redirect?redirect_url=http://otherxyz1234567890ab.onion/">Forum thread</a></h4>
            <cite>http://otherxyz1234567890ab.onion/</cite>
            <p>Discussion mentions credentials leaked from rinjanianalytics.com.</p>
        </li>
        <li class="result">
            <h4><a href="https://ahmia.fi/donate">Donate to Ahmia</a></h4>
            <p>Support the index — clearnet ad, no onion URL.</p>
        </li>
    </ol>
</body></html>
`.trim();

describe('parseAhmiaResults', () => {
    it('extracts title, onion URL, and snippet for genuine result rows', () => {
        const r = parseAhmiaResults(SAMPLE_HTML);
        expect(r).toHaveLength(2);
        expect(r[0].title).toBe('APT99 leak archive');
        expect(r[0].onionUrl).toBe('http://example1234567890abcd.onion/leak');
        expect(r[0].snippet).toMatch(/Rinjani internal docs/);
        expect(r[1].onionUrl).toBe('http://otherxyz1234567890ab.onion/');
    });

    it('drops result rows where the URL is not a .onion', () => {
        const r = parseAhmiaResults(SAMPLE_HTML);
        const hits = r.map(x => x.onionUrl);
        expect(hits.some(u => u.includes('ahmia.fi'))).toBe(false);
    });

    it('falls back to the redirect URL when <cite> is missing', () => {
        const html = `<li class="result">
            <h4><a href="/search/redirect?redirect_url=http://noccc1234567890abcd.onion/">no cite</a></h4>
            <p>snippet</p>
        </li>`;
        const r = parseAhmiaResults(html);
        expect(r).toHaveLength(1);
        expect(r[0].onionUrl).toBe('http://noccc1234567890abcd.onion/');
    });

    it('drops rows missing both title and URL', () => {
        const html = `<li class="result"><p>empty</p></li>`;
        const r = parseAhmiaResults(html);
        expect(r).toHaveLength(0);
    });

    it('returns empty array when no .result elements are present', () => {
        expect(parseAhmiaResults('<html><body>nothing here</body></html>')).toEqual([]);
    });

    it('caps the snippet length', () => {
        const long = 'x'.repeat(3000);
        const html = `<li class="result">
            <h4>t</h4><cite>http://abcdefgh12345678.onion/</cite><p>${long}</p>
        </li>`;
        const r = parseAhmiaResults(html);
        expect(r[0].snippet?.length).toBeLessThanOrEqual(2000);
    });
});

// ── Zod schemas ───────────────────────────────────────────────────

describe('DarkWebWatchtermCreateSchema', () => {
    it('accepts a minimal payload', () => {
        const r = DarkWebWatchtermCreateSchema.parse({ term: 'rinjanianalytics' });
        expect(r.term).toBe('rinjanianalytics');
        expect(r.enabled).toBe(true);
    });

    it('rejects an empty term', () => {
        expect(() => DarkWebWatchtermCreateSchema.parse({ term: '' })).toThrow();
    });

    it('caps term length at 255 chars', () => {
        expect(() => DarkWebWatchtermCreateSchema.parse({ term: 'x'.repeat(256) })).toThrow();
    });
});

describe('DarkWebMentionListSchema + DarkWebMentionUpdateSchema', () => {
    it('list coerces numeric query strings', () => {
        const r = DarkWebMentionListSchema.parse({ page: '2', pageSize: '20', minScore: '60' });
        expect(r.page).toBe(2);
        expect(r.pageSize).toBe(20);
        expect(r.minScore).toBe(60);
    });

    it('list rejects unknown status', () => {
        expect(() => DarkWebMentionListSchema.parse({ status: 'archived' })).toThrow();
    });

    it('update accepts a status flip', () => {
        const r = DarkWebMentionUpdateSchema.parse({ status: 'escalated' });
        expect(r.status).toBe('escalated');
    });
});
