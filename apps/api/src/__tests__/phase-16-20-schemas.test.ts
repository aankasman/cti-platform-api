/**
 * Schema Validation Tests — Wave 4 (Phases 16–19)
 */

import { describe, it, expect } from 'vitest';
import {
    CreateCampaignSchema, UpdateCampaignSchema, CampaignLinkSchema, CampaignFilterSchema,
    CreateCommentSchema, UpdateCommentSchema,
    CreateRetentionPolicySchema, UpdateRetentionPolicySchema,
    UpdateEnrichmentProviderSchema,
} from '../lib/schemas';

// Phase 16: Campaign Tracking
describe('CreateCampaignSchema', () => {
    it('requires name', () => { expect(() => CreateCampaignSchema.parse({})).toThrow(); });
    it('accepts minimal', () => {
        const r = CreateCampaignSchema.parse({ name: 'Operation Aurora' });
        expect(r.status).toBe('active');
        expect(r.threatLevel).toBe('unknown');
        expect(r.tlp).toBe('green');
    });
    it('accepts full profile', () => {
        const r = CreateCampaignSchema.parse({
            name: 'APT29 SolarWinds', status: 'concluded', threatLevel: 'critical',
            attribution: 'APT29', tags: ['apt29', 'supply-chain'], tlp: 'amber',
            firstSeen: '2020-01-01T00:00:00Z', lastSeen: '2021-06-01T00:00:00Z',
        });
        expect(r.attribution).toBe('APT29');
    });
    it('rejects invalid status', () => { expect(() => CreateCampaignSchema.parse({ name: 'x', status: 'invalid' })).toThrow(); });
});

describe('UpdateCampaignSchema', () => {
    it('rejects empty', () => { expect(() => UpdateCampaignSchema.parse({})).toThrow(); });
    it('accepts status change', () => { expect(UpdateCampaignSchema.parse({ status: 'dormant' }).status).toBe('dormant'); });
});

describe('CampaignLinkSchema', () => {
    it('requires entityType and entityId', () => { expect(() => CampaignLinkSchema.parse({})).toThrow(); });
    it('accepts IOC link', () => {
        const r = CampaignLinkSchema.parse({ entityType: 'ioc', entityId: 'abc', role: 'primary' });
        expect(r.role).toBe('primary');
    });
    it('defaults role to observed', () => {
        const r = CampaignLinkSchema.parse({ entityType: 'threat-actor', entityId: 'xyz' });
        expect(r.role).toBe('observed');
    });
});

describe('CampaignFilterSchema', () => {
    it('has defaults', () => {
        const r = CampaignFilterSchema.parse({});
        expect(r.page).toBe(1);
        expect(r.pageSize).toBe(20);
    });
});

// Phase 17: Comments
describe('CreateCommentSchema', () => {
    it('requires entityType, entityId, content', () => { expect(() => CreateCommentSchema.parse({})).toThrow(); });
    it('accepts full comment', () => {
        const r = CreateCommentSchema.parse({
            entityType: 'ioc', entityId: 'abc', content: 'Looks suspicious',
            visibility: 'team', pinned: true,
        });
        expect(r.visibility).toBe('team');
        expect(r.pinned).toBe(true);
    });
    it('defaults visibility to public', () => {
        const r = CreateCommentSchema.parse({ entityType: 'campaign', entityId: 'x', content: 'Note' });
        expect(r.visibility).toBe('public');
    });
    it('supports case entity type', () => {
        const r = CreateCommentSchema.parse({ entityType: 'case', entityId: 'x', content: 'Test' });
        expect(r.entityType).toBe('case');
    });
});

describe('UpdateCommentSchema', () => {
    it('rejects empty', () => { expect(() => UpdateCommentSchema.parse({})).toThrow(); });
    it('accepts pin toggle', () => { expect(UpdateCommentSchema.parse({ pinned: true }).pinned).toBe(true); });
});

// Phase 18: Retention
describe('CreateRetentionPolicySchema', () => {
    it('requires name, entityType, retentionDays', () => { expect(() => CreateRetentionPolicySchema.parse({})).toThrow(); });
    it('accepts minimal', () => {
        const r = CreateRetentionPolicySchema.parse({ name: 'Old IOCs', entityType: 'ioc', retentionDays: 90 });
        expect(r.action).toBe('delete');
        expect(r.enabled).toBe(true);
    });
    it('accepts archive action with filters', () => {
        const r = CreateRetentionPolicySchema.parse({
            name: 'Stale alerts', entityType: 'alert', retentionDays: 30,
            action: 'archive', filters: { severity: 'low', maxRiskScore: 20 },
        });
        expect(r.action).toBe('archive');
    });
    it('rejects invalid entity type', () => {
        expect(() => CreateRetentionPolicySchema.parse({ name: 'x', entityType: 'user', retentionDays: 30 })).toThrow();
    });
    it('enforces max 3650 days', () => {
        expect(() => CreateRetentionPolicySchema.parse({ name: 'x', entityType: 'ioc', retentionDays: 5000 })).toThrow();
    });
});

describe('UpdateRetentionPolicySchema', () => {
    it('rejects empty', () => { expect(() => UpdateRetentionPolicySchema.parse({})).toThrow(); });
    it('accepts days change', () => { expect(UpdateRetentionPolicySchema.parse({ retentionDays: 180 }).retentionDays).toBe(180); });
});

// Phase 19: Enrichment Providers
describe('UpdateEnrichmentProviderSchema', () => {
    it('rejects empty', () => { expect(() => UpdateEnrichmentProviderSchema.parse({})).toThrow(); });
    it('accepts enable toggle', () => { expect(UpdateEnrichmentProviderSchema.parse({ enabled: false }).enabled).toBe(false); });
    it('accepts priority', () => { expect(UpdateEnrichmentProviderSchema.parse({ priority: 10 }).priority).toBe(10); });
    it('accepts rate limit and timeout', () => {
        const r = UpdateEnrichmentProviderSchema.parse({ rateLimit: 100, timeout: 5000 });
        expect(r.rateLimit).toBe(100);
        expect(r.timeout).toBe(5000);
    });
    it('rejects timeout below 1000ms', () => {
        expect(() => UpdateEnrichmentProviderSchema.parse({ timeout: 500 })).toThrow();
    });
});
