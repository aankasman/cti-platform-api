/**
 * TTP changelog differ tests — Phase 5 #2.
 *
 * Only the pure diff function. The live snapshot + DB upsert path
 * needs Postgres + a populated relationships table; covered in PR
 * test plan.
 */
import { describe, it, expect } from 'vitest';
import { computeTtpDiff } from '../services/actorTtpDiffer';
import { TtpChangeListSchema } from '../lib/schemas';

const mkSet = (...techs: string[]) => new Set(techs);

describe('computeTtpDiff', () => {
    it('returns empty diff when nothing changed', () => {
        const prev = new Map([['G0016', mkSet('T1059', 'T1071')]]);
        const current = [{ actorId: 'G0016', techniqueIds: mkSet('T1059', 'T1071') }];
        expect(computeTtpDiff(prev, current)).toEqual([]);
    });

    it('emits an added entry for a new technique on an existing actor', () => {
        const prev = new Map([['G0016', mkSet('T1059')]]);
        const current = [{ actorId: 'G0016', techniqueIds: mkSet('T1059', 'T1071') }];
        const diff = computeTtpDiff(prev, current);
        expect(diff).toEqual([{ actorId: 'G0016', techniqueId: 'T1071', changeType: 'added' }]);
    });

    it('emits a removed entry when a previously-known technique vanishes', () => {
        const prev = new Map([['G0016', mkSet('T1059', 'T1071')]]);
        const current = [{ actorId: 'G0016', techniqueIds: mkSet('T1059') }];
        const diff = computeTtpDiff(prev, current);
        expect(diff).toEqual([{ actorId: 'G0016', techniqueId: 'T1071', changeType: 'removed' }]);
    });

    it('handles brand-new actors (all techniques emit as added)', () => {
        const prev = new Map<string, Set<string>>();
        const current = [{ actorId: 'G9999', techniqueIds: mkSet('T1001', 'T1002') }];
        const diff = computeTtpDiff(prev, current);
        expect(diff.length).toBe(2);
        expect(diff.every(d => d.changeType === 'added')).toBe(true);
        expect(new Set(diff.map(d => d.techniqueId))).toEqual(new Set(['T1001', 'T1002']));
    });

    it('handles deprecated actors (all techniques emit as removed)', () => {
        const prev = new Map([['G0099', mkSet('T1001', 'T1002')]]);
        const current: { actorId: string; techniqueIds: Set<string> }[] = [];
        const diff = computeTtpDiff(prev, current);
        expect(diff.length).toBe(2);
        expect(diff.every(d => d.changeType === 'removed')).toBe(true);
    });

    it('handles mixed add+remove on the same actor', () => {
        const prev = new Map([['G0016', mkSet('T1001', 'T1002')]]);
        const current = [{ actorId: 'G0016', techniqueIds: mkSet('T1002', 'T1003') }];
        const diff = computeTtpDiff(prev, current);
        // T1001 removed, T1003 added; T1002 unchanged (no entry)
        expect(diff).toHaveLength(2);
        expect(diff).toContainEqual({ actorId: 'G0016', techniqueId: 'T1001', changeType: 'removed' });
        expect(diff).toContainEqual({ actorId: 'G0016', techniqueId: 'T1003', changeType: 'added' });
    });

    it('keeps adds and removes for different actors independent', () => {
        const prev = new Map([
            ['G0001', mkSet('T1001')],
            ['G0002', mkSet('T2002')],
        ]);
        const current = [
            { actorId: 'G0001', techniqueIds: mkSet('T1001', 'T1099') }, // add T1099
            { actorId: 'G0002', techniqueIds: mkSet() },                  // remove T2002
        ];
        const diff = computeTtpDiff(prev, current);
        expect(diff).toContainEqual({ actorId: 'G0001', techniqueId: 'T1099', changeType: 'added' });
        expect(diff).toContainEqual({ actorId: 'G0002', techniqueId: 'T2002', changeType: 'removed' });
        expect(diff).toHaveLength(2);
    });

    it('handles empty input on both sides', () => {
        const diff = computeTtpDiff(new Map(), []);
        expect(diff).toEqual([]);
    });
});

describe('TtpChangeListSchema', () => {
    it('defaults page + pageSize, leaves filters undefined', () => {
        const r = TtpChangeListSchema.parse({});
        expect(r.page).toBe(1);
        expect(r.pageSize).toBe(100);
        expect(r.actorId).toBeUndefined();
    });

    it('coerces numeric query strings', () => {
        const r = TtpChangeListSchema.parse({ page: '3', pageSize: '50', actorId: 'G0016' });
        expect(r.page).toBe(3);
        expect(r.pageSize).toBe(50);
        expect(r.actorId).toBe('G0016');
    });

    it('caps pageSize at 500', () => {
        expect(() => TtpChangeListSchema.parse({ pageSize: '1000' })).toThrow();
    });

    it('rejects unknown change type', () => {
        expect(() => TtpChangeListSchema.parse({ changeType: 'updated' })).toThrow();
    });

    it('accepts ISO-8601 since cutoff', () => {
        const r = TtpChangeListSchema.parse({ since: '2026-05-01T00:00:00Z' });
        expect(r.since).toBe('2026-05-01T00:00:00Z');
    });

    it('rejects malformed since', () => {
        expect(() => TtpChangeListSchema.parse({ since: 'last week' })).toThrow();
    });
});
