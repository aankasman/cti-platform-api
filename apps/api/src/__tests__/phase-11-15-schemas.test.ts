/**
 * Schema Validation Tests — Wave 3 (Phases 11–14)
 */

import { describe, it, expect } from 'vitest';
import {
    CreateWatchlistSchema, UpdateWatchlistSchema, WatchlistEntrySchema, WatchlistCheckSchema,
    CreateReportScheduleSchema, UpdateReportScheduleSchema,
    CreateRelationshipSchema, BulkRelationshipSchema, RelationshipFilterSchema,
    LandscapeQuerySchema,
} from '../lib/schemas';

// Phase 11: Watchlists
describe('CreateWatchlistSchema', () => {
    it('requires name', () => { expect(() => CreateWatchlistSchema.parse({})).toThrow(); });
    it('accepts minimal', () => {
        const r = CreateWatchlistSchema.parse({ name: 'Critical IPs' });
        expect(r.visibility).toBe('personal');
        expect(r.notifyOnHit).toBe(false);
    });
    it('accepts full config', () => {
        const r = CreateWatchlistSchema.parse({ name: 'APT IPs', visibility: 'team', notifyOnHit: true, tags: ['apt'] });
        expect(r.visibility).toBe('team');
    });
});

describe('UpdateWatchlistSchema', () => {
    it('rejects empty', () => { expect(() => UpdateWatchlistSchema.parse({})).toThrow(); });
    it('accepts partial', () => { expect(UpdateWatchlistSchema.parse({ notifyOnHit: true }).notifyOnHit).toBe(true); });
});

describe('WatchlistEntrySchema', () => {
    it('requires value and type', () => { expect(() => WatchlistEntrySchema.parse({})).toThrow(); });
    it('accepts IP entry', () => {
        const r = WatchlistEntrySchema.parse({ value: '8.8.8.8', type: 'ip', notes: 'Google DNS' });
        expect(r.type).toBe('ip');
    });
    it('accepts CIDR type', () => {
        const r = WatchlistEntrySchema.parse({ value: '10.0.0.0/8', type: 'cidr' });
        expect(r.type).toBe('cidr');
    });
});

describe('WatchlistCheckSchema', () => {
    it('requires value', () => { expect(() => WatchlistCheckSchema.parse({})).toThrow(); });
    it('accepts value', () => { expect(WatchlistCheckSchema.parse({ value: '8.8.8.8' }).value).toBe('8.8.8.8'); });
});

// Phase 12: Scheduled Reports
describe('CreateReportScheduleSchema', () => {
    it('requires name', () => { expect(() => CreateReportScheduleSchema.parse({})).toThrow(); });
    it('accepts minimal with defaults', () => {
        const r = CreateReportScheduleSchema.parse({ name: 'Weekly Summary' });
        expect(r.schedule).toBe('weekly');
        expect(r.format).toBe('markdown');
        expect(r.scope).toBe('summary');
        expect(r.enabled).toBe(true);
    });
    it('accepts full config', () => {
        const r = CreateReportScheduleSchema.parse({
            name: 'Daily Critical', schedule: 'daily', format: 'html', scope: 'full',
            filters: { severity: 'critical', dateRange: '24h' },
            delivery: { email: 'team@corp.com', slack: true, inApp: true },
        });
        expect(r.schedule).toBe('daily');
        expect(r.delivery.email).toBe('team@corp.com');
    });
});

describe('UpdateReportScheduleSchema', () => {
    it('rejects empty', () => { expect(() => UpdateReportScheduleSchema.parse({})).toThrow(); });
    it('accepts enable toggle', () => { expect(UpdateReportScheduleSchema.parse({ enabled: false }).enabled).toBe(false); });
});

// Phase 13: Relationships
describe('CreateRelationshipSchema', () => {
    it('requires all fields', () => { expect(() => CreateRelationshipSchema.parse({})).toThrow(); });
    it('accepts valid relationship', () => {
        const r = CreateRelationshipSchema.parse({
            sourceType: 'ioc', sourceId: 'abc', targetType: 'threat-actor', targetId: 'xyz',
            relationshipType: 'attributed-to',
        });
        expect(r.confidence).toBe(70);
    });
    it('rejects invalid type', () => {
        expect(() => CreateRelationshipSchema.parse({
            sourceType: 'ioc', sourceId: 'a', targetType: 'ioc', targetId: 'b', relationshipType: 'invalid',
        })).toThrow();
    });
    it('accepts every STIX 2.1 SRO common relationship type', () => {
        // Vocab moved to @rinjani/core/stixVocab (Phase 2 #2). Kept this
        // test honest by walking a representative subset; the
        // stix-vocab.test.ts file locks the full list.
        const types = ['related-to', 'derived-from', 'communicates-with',
            'drops', 'uses', 'targets', 'indicates', 'mitigates', 'attributed-to',
            'exploits', 'controls', 'beacons-to'];
        for (const t of types) {
            expect(CreateRelationshipSchema.parse({
                sourceType: 'ioc', sourceId: 'a', targetType: 'ioc', targetId: 'b', relationshipType: t,
            }).relationshipType).toBe(t);
        }
    });
});

describe('BulkRelationshipSchema', () => {
    it('requires at least 1', () => { expect(() => BulkRelationshipSchema.parse({ relationships: [] })).toThrow(); });
    it('accepts list', () => {
        const r = BulkRelationshipSchema.parse({
            relationships: [
                { sourceType: 'ioc', sourceId: 'a', targetType: 'ioc', targetId: 'b', relationshipType: 'related-to' },
            ],
        });
        expect(r.relationships).toHaveLength(1);
    });
});

describe('RelationshipFilterSchema', () => {
    it('has defaults', () => {
        const r = RelationshipFilterSchema.parse({});
        expect(r.page).toBe(1);
        expect(r.pageSize).toBe(20);
    });
    it('accepts entityId filter', () => {
        expect(RelationshipFilterSchema.parse({ entityId: 'abc' }).entityId).toBe('abc');
    });
});

// Phase 14: Landscape
describe('LandscapeQuerySchema', () => {
    it('defaults to 7d/20', () => {
        const r = LandscapeQuerySchema.parse({});
        expect(r.period).toBe('7d');
        expect(r.limit).toBe(20);
    });
    it('accepts 90d period', () => {
        expect(LandscapeQuerySchema.parse({ period: '90d' }).period).toBe('90d');
    });
    it('rejects invalid period', () => {
        expect(() => LandscapeQuerySchema.parse({ period: '1y' })).toThrow();
    });
});
