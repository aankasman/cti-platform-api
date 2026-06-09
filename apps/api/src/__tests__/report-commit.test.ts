/**
 * Tests for the IocKind → ioc.type mapping + Zod schemas — Phase 3 #1 follow-on.
 *
 * The DB-touching `commitReport` is covered by the live test plan in
 * the PR (it needs a live `iocs` table). Here we cover the pure piece:
 * the public schemas the route layer relies on.
 */
import { describe, it, expect } from 'vitest';
import { ReportCommitSchema, ReportListSchema } from '../lib/schemas';

describe('ReportCommitSchema', () => {
    it('accepts an empty approval set (operator commits nothing)', () => {
        const r = ReportCommitSchema.parse({});
        expect(r.approvedIocs).toEqual([]);
    });

    it('accepts a typical approval list', () => {
        const r = ReportCommitSchema.parse({
            approvedIocs: [
                { kind: 'ipv4', value: '1.2.3.4' },
                { kind: 'domain', value: 'evil.test' },
                { kind: 'hash-sha256', value: 'a'.repeat(64) },
            ],
            iocSource: 'mandiant-2026-q2',
        });
        expect(r.approvedIocs).toHaveLength(3);
        expect(r.iocSource).toBe('mandiant-2026-q2');
    });

    it('rejects unknown ioc kinds', () => {
        expect(() => ReportCommitSchema.parse({
            approvedIocs: [{ kind: 'mac-address', value: '00:11:22:33:44:55' }],
        })).toThrow();
    });

    it('rejects empty IOC values', () => {
        expect(() => ReportCommitSchema.parse({
            approvedIocs: [{ kind: 'ipv4', value: '' }],
        })).toThrow();
    });

    it('caps approval list at 10k entries', () => {
        const huge = Array.from({ length: 10_001 }, (_, i) => ({ kind: 'ipv4' as const, value: `1.2.3.${i % 255}` }));
        expect(() => ReportCommitSchema.parse({ approvedIocs: huge })).toThrow();
    });

    it('allows all nine IOC kinds the extractor emits', () => {
        const kinds = ['ipv4', 'ipv6', 'domain', 'url', 'hash-md5', 'hash-sha1', 'hash-sha256', 'email', 'cve'] as const;
        const r = ReportCommitSchema.parse({
            approvedIocs: kinds.map(k => ({ kind: k, value: 'x' })),
        });
        expect(r.approvedIocs).toHaveLength(9);
    });
});

describe('ReportListSchema', () => {
    it('defaults page + pageSize and leaves status undefined', () => {
        const r = ReportListSchema.parse({});
        expect(r.page).toBe(1);
        expect(r.pageSize).toBe(50);
        expect(r.status).toBeUndefined();
    });

    it('coerces numeric query strings', () => {
        const r = ReportListSchema.parse({ page: '3', pageSize: '25', status: 'draft' });
        expect(r.page).toBe(3);
        expect(r.pageSize).toBe(25);
        expect(r.status).toBe('draft');
    });

    it('caps pageSize at 200', () => {
        expect(() => ReportListSchema.parse({ pageSize: '500' })).toThrow();
    });

    it('rejects an unknown status', () => {
        expect(() => ReportListSchema.parse({ status: 'archived' })).toThrow();
    });
});
