/**
 * JIRA client tests — Phase 4 #6a.
 *
 * Like the GitHub tests, the over-the-wire create/get/comment paths need
 * a real JIRA Cloud tenant and live in the PR test plan. These unit
 * tests cover the deterministic mapper, which is the part most likely
 * to drift if Atlassian's payload shape changes.
 */
import { describe, it, expect } from 'vitest';
import { mapJiraIssue } from '../services/ticketing/jira';

describe('mapJiraIssue', () => {
    it('maps statusCategory.key="done" to closed', () => {
        const r = mapJiraIssue({
            fields: {
                summary: 'IOC investigated',
                status: { name: 'Done', statusCategory: { key: 'done' } },
                labels: ['incident'],
            },
        });
        expect(r.status).toBe('closed');
        expect(r.title).toBe('IOC investigated');
        expect(r.labels).toEqual(['incident']);
    });

    it('maps statusCategory.key="new" to open', () => {
        const r = mapJiraIssue({
            fields: { summary: 'just filed', status: { statusCategory: { key: 'new' } }, labels: [] },
        });
        expect(r.status).toBe('open');
    });

    it('maps statusCategory.key="indeterminate" to open (in-progress workflows)', () => {
        const r = mapJiraIssue({
            fields: { summary: 'mid-flight', status: { statusCategory: { key: 'indeterminate' } }, labels: [] },
        });
        expect(r.status).toBe('open');
    });

    it('is resilient to custom workflow names — only category matters', () => {
        // Real-world: many tenants rename "Done" to "Triaged & Closed". statusCategory.key stays "done".
        const r = mapJiraIssue({
            fields: {
                summary: 'custom workflow',
                status: { name: 'Triaged & Closed', statusCategory: { key: 'done' } },
                labels: [],
            },
        });
        expect(r.status).toBe('closed');
    });

    it('falls back to unknown when statusCategory missing', () => {
        const r = mapJiraIssue({ fields: { summary: 'x', labels: [] } });
        expect(r.status).toBe('unknown');
    });

    it('drops non-string labels (defensive against malformed payload)', () => {
        const r = mapJiraIssue({
            fields: {
                summary: 'x',
                status: { statusCategory: { key: 'new' } },
                labels: ['good', 42, null, undefined, { name: 'object' }],
            },
        });
        expect(r.labels).toEqual(['good']);
    });

    it('handles missing fields object entirely', () => {
        const r = mapJiraIssue({});
        expect(r.status).toBe('unknown');
        expect(r.title).toBe('');
        expect(r.labels).toEqual([]);
    });

    it('handles non-array labels', () => {
        const r = mapJiraIssue({
            fields: { summary: 'x', status: { statusCategory: { key: 'new' } }, labels: 'not-an-array' },
        });
        expect(r.labels).toEqual([]);
    });

    it('treats statusCategory.key case-insensitively', () => {
        const r = mapJiraIssue({
            fields: { summary: 'x', status: { statusCategory: { key: 'DONE' } }, labels: [] },
        });
        expect(r.status).toBe('closed');
    });
});
