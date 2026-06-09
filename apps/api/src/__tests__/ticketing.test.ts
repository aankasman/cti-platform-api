/**
 * Ticketing scaffold tests — Phase 4 #6.
 *
 * Network-side create/get/comment integration needs a real GitHub PAT,
 * verified via the PR test plan. These unit tests cover the
 * deterministic core:
 *   - the GitHub Issue mapper (state + labels + title normalisation)
 *   - the Zod schemas (vendor enum, size caps, repo shape, body required)
 */
import { describe, it, expect } from 'vitest';
import { mapGhIssue } from '../services/ticketing/github';
import {
    TicketCreateSchema, TicketCommentSchema, TicketListFiltersSchema,
} from '../lib/schemas';

describe('mapGhIssue', () => {
    it('maps an open issue with label objects', () => {
        const r = mapGhIssue({
            state: 'open',
            title: 'IOC observed: evil.test',
            labels: [{ name: 'incident' }, { name: 'severity/high' }],
        });
        expect(r.status).toBe('open');
        expect(r.title).toBe('IOC observed: evil.test');
        expect(r.labels).toEqual(['incident', 'severity/high']);
    });

    it('maps a closed issue', () => {
        const r = mapGhIssue({ state: 'closed', title: 'resolved', labels: [] });
        expect(r.status).toBe('closed');
    });

    it('accepts label arrays of strings (some integrations use that shape)', () => {
        const r = mapGhIssue({ state: 'open', title: 'x', labels: ['a', 'b'] });
        expect(r.labels).toEqual(['a', 'b']);
    });

    it('drops label entries that have no name', () => {
        const r = mapGhIssue({
            state: 'open',
            title: 'x',
            labels: [{ name: 'good' }, { color: 'red' /* no name */ }, null, undefined],
        });
        expect(r.labels).toEqual(['good']);
    });

    it('uppercases the unknown bucket for non-standard state', () => {
        const r = mapGhIssue({ state: 'merged', title: 'x', labels: [] });
        expect(r.status).toBe('unknown');
    });

    it('falls back gracefully on missing fields', () => {
        const r = mapGhIssue({});
        expect(r.status).toBe('unknown');
        expect(r.title).toBe('');
        expect(r.labels).toEqual([]);
    });
});

describe('TicketCreateSchema', () => {
    const valid = { vendor: 'github' as const, repo: 'rinjanianalytics/cti-platform-api' };

    it('accepts minimal payload', () => {
        const r = TicketCreateSchema.parse(valid);
        expect(r.vendor).toBe('github');
    });

    it('accepts an overridden title + body + labels', () => {
        const r = TicketCreateSchema.parse({
            ...valid,
            title: 'Critical APT28 IOC observed on /admin',
            body: 'See case xyz for details.',
            labels: ['incident', 'severity/critical'],
        });
        expect(r.title).toBe('Critical APT28 IOC observed on /admin');
        expect(r.labels).toEqual(['incident', 'severity/critical']);
    });

    it('rejects unknown vendor', () => {
        expect(() => TicketCreateSchema.parse({ ...valid, vendor: 'gitlab' })).toThrow();
    });

    it('rejects an oversized title', () => {
        expect(() => TicketCreateSchema.parse({ ...valid, title: 'x'.repeat(300) })).toThrow();
    });

    it('rejects a missing repo', () => {
        expect(() => TicketCreateSchema.parse({ vendor: 'github' })).toThrow();
    });
});

describe('TicketCommentSchema', () => {
    it('rejects an empty body', () => {
        expect(() => TicketCommentSchema.parse({ body: '' })).toThrow();
    });
    it('accepts non-empty body', () => {
        expect(TicketCommentSchema.parse({ body: 'New IOC added to case' }).body)
            .toBe('New IOC added to case');
    });
    it('rejects > 64 KiB body', () => {
        expect(() => TicketCommentSchema.parse({ body: 'x'.repeat(65537) })).toThrow();
    });
});

describe('TicketListFiltersSchema', () => {
    it('defaults page/pageSize', () => {
        const r = TicketListFiltersSchema.parse({});
        expect(r.page).toBe(1);
        expect(r.pageSize).toBe(50);
    });

    it('coerces numeric query strings', () => {
        const r = TicketListFiltersSchema.parse({ page: '3', pageSize: '25', vendor: 'github' });
        expect(r.page).toBe(3);
        expect(r.pageSize).toBe(25);
        expect(r.vendor).toBe('github');
    });

    it('caps pageSize at 200', () => {
        expect(() => TicketListFiltersSchema.parse({ pageSize: '500' })).toThrow();
    });
});
