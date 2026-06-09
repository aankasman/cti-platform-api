/**
 * Paste-site monitor (GitHub Gist firehose) tests — Phase 5 #5.
 *
 * The over-the-wire fetch + DB upsert path needs live network + Postgres
 * (covered in PR test plan). Here we pin down the pure pieces: the
 * GitHub API → internal shape normaliser and the watchterm matcher.
 */
import { describe, it, expect } from 'vitest';
import { normaliseGist, findMatches, type NormalisedGist } from '../services/gistMonitor';
import {
    PasteWatchtermCreateSchema, PasteMentionListSchema, PasteMentionUpdateSchema,
} from '../lib/schemas';

const SAMPLE_GIST_API_ROW = {
    id: 'abc123',
    html_url: 'https://gist.github.com/someone/abc123',
    description: 'Rinjani analytics API key dump for testing',
    created_at: '2026-06-09T12:00:00Z',
    updated_at: '2026-06-09T12:00:00Z',
    owner: { login: 'rogue-actor-99' },
    files: {
        'secrets.env': { filename: 'secrets.env', type: 'text/plain', language: 'Text' },
        'extra.txt': { filename: 'extra.txt' },
    },
};

describe('normaliseGist', () => {
    it('extracts owner login + description + filenames + lower-cased searchable text', () => {
        const n = normaliseGist(SAMPLE_GIST_API_ROW);
        expect(n.id).toBe('abc123');
        expect(n.htmlUrl).toBe('https://gist.github.com/someone/abc123');
        expect(n.owner).toBe('rogue-actor-99');
        expect(n.description).toContain('Rinjani analytics');
        expect(n.filenames).toEqual(['secrets.env', 'extra.txt']);
        // searchable is lower-cased and includes both description + filenames
        expect(n.searchable).toContain('rinjani analytics api key dump');
        expect(n.searchable).toContain('secrets.env');
    });

    it('defaults missing fields safely', () => {
        const n = normaliseGist({
            id: 'x', html_url: 'u', description: null,
            created_at: '', updated_at: '',
        });
        expect(n.owner).toBeNull();
        expect(n.description).toBe('');
        expect(n.filenames).toEqual([]);
    });

    it('falls back to the file key when a file entry has no filename', () => {
        const n = normaliseGist({
            id: 'x', html_url: 'u', description: null,
            created_at: '', updated_at: '',
            files: { 'fallback.txt': { /* no filename field */ } },
        });
        expect(n.filenames).toEqual(['fallback.txt']);
    });
});

const wt = (id: string, term: string) => ({ id, term });
const g = (id: string, description: string, filenames: string[]): NormalisedGist => ({
    id,
    htmlUrl: `https://gist.github.com/x/${id}`,
    owner: 'x',
    description,
    filenames,
    searchable: `${description} ${filenames.join(' ')}`.toLowerCase(),
});

describe('findMatches', () => {
    it('returns one match per (watchterm, gist) pair where the term is found', () => {
        const matches = findMatches(
            [wt('w1', 'Rinjani')],
            [g('g1', 'Rinjani secrets dump', ['db.env'])],
        );
        expect(matches).toHaveLength(1);
        expect(matches[0].watchtermId).toBe('w1');
        expect(matches[0].gist.id).toBe('g1');
    });

    it('is case-insensitive on both sides', () => {
        const matches = findMatches(
            [wt('w1', 'RINJANI')],
            [g('g1', 'rinjani api keys', ['x.txt'])],
        );
        expect(matches).toHaveLength(1);
    });

    it('matches when the term appears in a filename but not the description', () => {
        const matches = findMatches(
            [wt('w1', 'rinjani')],
            [g('g1', 'random dump', ['rinjani-secrets.env'])],
        );
        expect(matches).toHaveLength(1);
        expect(matches[0].matchedFilename).toBe('rinjani-secrets.env');
    });

    it('returns the matched filename when description+filename both contain the term', () => {
        const matches = findMatches(
            [wt('w1', 'rinjani')],
            [g('g1', 'rinjani description', ['rinjani.env', 'other.txt'])],
        );
        expect(matches[0].matchedFilename).toBe('rinjani.env');
    });

    it('returns null for matchedFilename when the term is only in description', () => {
        const matches = findMatches(
            [wt('w1', 'rinjani')],
            [g('g1', 'rinjani secrets', ['unrelated.txt'])],
        );
        expect(matches[0].matchedFilename).toBeNull();
    });

    it('emits multiple rows when one gist hits multiple watchterms', () => {
        const matches = findMatches(
            [wt('w1', 'rinjani'), wt('w2', 'apikey')],
            [g('g1', 'rinjani apikey dump', ['secrets.env'])],
        );
        expect(matches).toHaveLength(2);
        expect(new Set(matches.map(m => m.watchtermId))).toEqual(new Set(['w1', 'w2']));
    });

    it('skips watchterms with empty strings', () => {
        const matches = findMatches(
            [wt('w1', ''), wt('w2', 'rinjani')],
            [g('g1', 'rinjani dump', ['x.env'])],
        );
        expect(matches).toHaveLength(1);
        expect(matches[0].watchtermId).toBe('w2');
    });

    it('returns empty when no watchterm matches any gist', () => {
        const matches = findMatches(
            [wt('w1', 'rinjani')],
            [g('g1', 'unrelated dump', ['x.env'])],
        );
        expect(matches).toEqual([]);
    });
});

describe('PasteWatchtermCreateSchema', () => {
    it('accepts a minimal payload + defaults enabled true', () => {
        const r = PasteWatchtermCreateSchema.parse({ term: 'rinjanianalytics' });
        expect(r.term).toBe('rinjanianalytics');
        expect(r.enabled).toBe(true);
    });

    it('rejects empty terms', () => {
        expect(() => PasteWatchtermCreateSchema.parse({ term: '' })).toThrow();
    });
});

describe('PasteMentionListSchema + PasteMentionUpdateSchema', () => {
    it('list coerces numeric query strings', () => {
        const r = PasteMentionListSchema.parse({ page: '3', pageSize: '25', minScore: '50' });
        expect(r.page).toBe(3);
        expect(r.pageSize).toBe(25);
        expect(r.minScore).toBe(50);
    });

    it('list rejects unknown status', () => {
        expect(() => PasteMentionListSchema.parse({ status: 'archived' })).toThrow();
    });

    it('update accepts a status flip', () => {
        const r = PasteMentionUpdateSchema.parse({ status: 'benign' });
        expect(r.status).toBe('benign');
    });
});
