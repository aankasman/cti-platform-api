/**
 * HIBP sync tests — Phase 5 #3.
 *
 * The over-the-wire fetch + DB upsert needs live network + Postgres
 * (covered in PR test plan). Here we cover the pure mapper and the
 * Zod filter schema — the parts most likely to drift if HIBP changes
 * its response shape.
 */
import { describe, it, expect } from 'vitest';
import { mapHibpBreach } from '../services/feedSync/hibpSync';
import { DataBreachListSchema } from '../lib/schemas';

const FULL_BREACH = {
    Name: 'Adobe',
    Title: 'Adobe',
    Domain: 'adobe.com',
    BreachDate: '2013-10-04',
    AddedDate: '2013-12-04T00:00:00Z',
    ModifiedDate: '2022-05-15T23:52:49Z',
    PwnCount: 152445165,
    Description: 'In October 2013, 153 million Adobe accounts were breached.',
    DataClasses: ['Email addresses', 'Password hints', 'Passwords', 'Usernames'],
    IsVerified: true,
    IsFabricated: false,
    IsSensitive: false,
    IsRetired: false,
    IsSpamList: false,
    LogoPath: 'https://haveibeenpwned.com/Content/Images/PwnedLogos/Adobe.png',
    LastModified: '2025-01-15T00:00:00Z', // extra field, captured in rawData
};

describe('mapHibpBreach', () => {
    it('maps a typical fully-populated entry', () => {
        const m = mapHibpBreach(FULL_BREACH);
        expect(m.name).toBe('Adobe');
        expect(m.domain).toBe('adobe.com');
        expect(m.pwnCount).toBe(152445165);
        expect(m.dataClasses).toEqual(['Email addresses', 'Password hints', 'Passwords', 'Usernames']);
        expect(m.isVerified).toBe(true);
        expect(m.breachDate?.toISOString().slice(0, 10)).toBe('2013-10-04');
        expect(m.addedDate?.toISOString()).toBe('2013-12-04T00:00:00.000Z');
    });

    it('preserves unknown fields in rawData for forensic recovery', () => {
        const m = mapHibpBreach(FULL_BREACH);
        expect((m.rawData as { LastModified?: string }).LastModified).toBe('2025-01-15T00:00:00Z');
    });

    it('defaults Title to Name when Title is missing', () => {
        const m = mapHibpBreach({ Name: 'NoTitle' });
        expect(m.title).toBe('NoTitle');
    });

    it('returns null for empty Domain (not the empty string)', () => {
        const m = mapHibpBreach({ Name: 'NoDomain', Title: 'No', Domain: '' });
        expect(m.domain).toBeNull();
    });

    it('returns null for unparseable dates (and does not throw)', () => {
        const m = mapHibpBreach({ Name: 'X', Title: 'x', BreachDate: 'not a date' });
        expect(m.breachDate).toBeNull();
    });

    it('clamps pwnCount to 0 when PwnCount is missing', () => {
        const m = mapHibpBreach({ Name: 'X', Title: 'x' });
        expect(m.pwnCount).toBe(0);
    });

    it('drops non-string entries from DataClasses', () => {
        const m = mapHibpBreach({
            Name: 'X', Title: 'x',
            DataClasses: ['Email addresses', 42, null, 'Passwords'] as unknown as string[],
        });
        expect(m.dataClasses).toEqual(['Email addresses', 'Passwords']);
    });

    it('returns empty dataClasses on non-array input', () => {
        const m = mapHibpBreach({ Name: 'X', Title: 'x', DataClasses: 'not an array' as unknown as string[] });
        expect(m.dataClasses).toEqual([]);
    });

    it('defaults all boolean flags to false when absent', () => {
        const m = mapHibpBreach({ Name: 'X', Title: 'x' });
        expect(m.isVerified).toBe(false);
        expect(m.isFabricated).toBe(false);
        expect(m.isSensitive).toBe(false);
        expect(m.isRetired).toBe(false);
        expect(m.isSpamList).toBe(false);
    });
});

describe('DataBreachListSchema', () => {
    it('defaults filters to hide retired + spam + fabricated', () => {
        const r = DataBreachListSchema.parse({});
        expect(r.includeRetired).toBe(false);
        expect(r.includeSpamList).toBe(false);
        expect(r.includeFabricated).toBe(false);
        expect(r.page).toBe(1);
        expect(r.pageSize).toBe(100);
    });

    it('coerces query-string booleans', () => {
        const r = DataBreachListSchema.parse({ includeRetired: 'true', includeSpamList: 'true' });
        expect(r.includeRetired).toBe(true);
        expect(r.includeSpamList).toBe(true);
    });

    it('accepts ISO addedSince + breachSince', () => {
        const r = DataBreachListSchema.parse({
            addedSince: '2026-05-01T00:00:00Z',
            breachSince: '2024-01-01T00:00:00Z',
        });
        expect(r.addedSince).toBe('2026-05-01T00:00:00Z');
    });

    it('rejects malformed since', () => {
        expect(() => DataBreachListSchema.parse({ addedSince: 'last week' })).toThrow();
    });

    it('caps pageSize at 500', () => {
        expect(() => DataBreachListSchema.parse({ pageSize: '1000' })).toThrow();
    });
});
