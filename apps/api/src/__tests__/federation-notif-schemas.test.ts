/**
 * Federation, Notification & Playbook Schema Tests
 *
 * Phase Q — validates all new Zod schemas added for
 * federation admin, notification, and playbook routes.
 */

import { describe, it, expect } from 'vitest';
import {
    CreateTenantSchema, AddPeerSchema, RollbackSchema, RescoreSchema,
    NotificationSettingsSchema, TestSlackSchema, TestEmailSchema, ManualAlertSchema,
    CreatePlaybookSchema, UpdatePlaybookSchema,
} from '../lib/schemas';

// ============================================================================
// Federation Admin Schemas
// ============================================================================

describe('CreateTenantSchema', () => {
    it('accepts valid tenant', () => {
        const result = CreateTenantSchema.parse({ name: 'Acme Corp', slug: 'acme-corp' });
        expect(result.name).toBe('Acme Corp');
        expect(result.slug).toBe('acme-corp');
        expect(result.tier).toBe('free'); // default
    });

    it('accepts all tier values', () => {
        for (const tier of ['free', 'pro', 'enterprise'] as const) {
            const result = CreateTenantSchema.parse({ name: 'T', slug: 't', tier });
            expect(result.tier).toBe(tier);
        }
    });

    it('rejects missing name', () => {
        expect(() => CreateTenantSchema.parse({ slug: 'test' })).toThrow();
    });

    it('rejects missing slug', () => {
        expect(() => CreateTenantSchema.parse({ name: 'Test' })).toThrow();
    });

    it('rejects invalid slug format', () => {
        expect(() => CreateTenantSchema.parse({ name: 'X', slug: 'UPPER_CASE' })).toThrow();
        expect(() => CreateTenantSchema.parse({ name: 'X', slug: 'has spaces' })).toThrow();
    });

    it('rejects invalid tier', () => {
        expect(() => CreateTenantSchema.parse({ name: 'X', slug: 'x', tier: 'ultra' })).toThrow();
    });

    it('accepts optional config', () => {
        const result = CreateTenantSchema.parse({ name: 'X', slug: 'x', config: { maxUsers: 10 } });
        expect(result.config).toEqual({ maxUsers: 10 });
    });
});

describe('AddPeerSchema', () => {
    it('accepts valid peer', () => {
        const result = AddPeerSchema.parse({
            name: 'Partner', url: 'https://partner.io', apiKey: 'key123',
        });
        expect(result.name).toBe('Partner');
        expect(result.trustLevel).toBe('read-only'); // default
    });

    it('accepts all trust levels', () => {
        for (const tl of ['full', 'limited', 'read-only'] as const) {
            const r = AddPeerSchema.parse({
                name: 'P', url: 'https://x.io', apiKey: 'k', trustLevel: tl,
            });
            expect(r.trustLevel).toBe(tl);
        }
    });

    it('rejects missing apiKey', () => {
        expect(() => AddPeerSchema.parse({ name: 'P', url: 'https://x.io' })).toThrow();
    });

    it('rejects invalid url', () => {
        expect(() => AddPeerSchema.parse({ name: 'P', url: 'not-a-url', apiKey: 'k' })).toThrow();
    });
});

describe('RollbackSchema', () => {
    it('defaults count to 1', () => {
        expect(RollbackSchema.parse({}).count).toBe(1);
    });

    it('clamps count to max 5', () => {
        expect(() => RollbackSchema.parse({ count: 10 })).toThrow();
    });

    it('rejects count 0', () => {
        expect(() => RollbackSchema.parse({ count: 0 })).toThrow();
    });
});

describe('RescoreSchema', () => {
    it('defaults batchSize to 100', () => {
        expect(RescoreSchema.parse({}).batchSize).toBe(100);
    });

    it('clamps to max 500', () => {
        expect(() => RescoreSchema.parse({ batchSize: 1000 })).toThrow();
    });

    it('accepts valid batchSize', () => {
        expect(RescoreSchema.parse({ batchSize: 250 }).batchSize).toBe(250);
    });
});

// ============================================================================
// Notification Schemas
// ============================================================================

describe('NotificationSettingsSchema', () => {
    it('accepts empty object (all optional)', () => {
        const result = NotificationSettingsSchema.parse({});
        expect(result).toEqual({});
    });

    it('accepts full settings', () => {
        const result = NotificationSettingsSchema.parse({
            emailEnabled: true,
            emailAddress: 'user@example.com',
            slackEnabled: false,
            slackWebhookUrl: null,
            severityThreshold: 'high',
            notifyOnNewIOC: true,
            notifyOnNewVuln: false,
            notifyOnThreatActor: true,
        });
        expect(result.emailEnabled).toBe(true);
        expect(result.severityThreshold).toBe('high');
    });

    it('rejects invalid emailAddress', () => {
        expect(() => NotificationSettingsSchema.parse({ emailAddress: 'not-email' })).toThrow();
    });

    it('rejects invalid severity threshold', () => {
        expect(() => NotificationSettingsSchema.parse({ severityThreshold: 'info' })).toThrow();
    });
});

describe('TestSlackSchema', () => {
    it('accepts valid webhook URL', () => {
        const result = TestSlackSchema.parse({ webhookUrl: 'https://hooks.slack.com/services/xxx' });
        expect(result.webhookUrl).toContain('hooks.slack.com');
    });

    it('rejects missing webhookUrl', () => {
        expect(() => TestSlackSchema.parse({})).toThrow();
    });

    it('rejects invalid URL', () => {
        expect(() => TestSlackSchema.parse({ webhookUrl: 'not-a-url' })).toThrow();
    });
});

describe('TestEmailSchema', () => {
    it('accepts valid email', () => {
        const result = TestEmailSchema.parse({ emailAddress: 'test@example.com' });
        expect(result.emailAddress).toBe('test@example.com');
    });

    it('rejects missing email', () => {
        expect(() => TestEmailSchema.parse({})).toThrow();
    });

    it('rejects invalid email format', () => {
        expect(() => TestEmailSchema.parse({ emailAddress: 'not-an-email' })).toThrow();
    });
});

describe('ManualAlertSchema', () => {
    it('accepts valid alert', () => {
        const result = ManualAlertSchema.parse({
            type: 'alert', severity: 'critical',
            title: 'Test Alert', message: 'Something happened',
        });
        expect(result.type).toBe('alert');
        expect(result.severity).toBe('critical');
    });

    it('accepts all type values', () => {
        for (const type of ['ioc', 'vulnerability', 'threat_actor', 'alert'] as const) {
            const r = ManualAlertSchema.parse({
                type, severity: 'low', title: 'T', message: 'M',
            });
            expect(r.type).toBe(type);
        }
    });

    it('rejects invalid type', () => {
        expect(() => ManualAlertSchema.parse({
            type: 'unknown', severity: 'low', title: 'T', message: 'M',
        })).toThrow();
    });

    it('rejects missing required fields', () => {
        expect(() => ManualAlertSchema.parse({ type: 'alert' })).toThrow();
    });

    it('accepts optional data', () => {
        const result = ManualAlertSchema.parse({
            type: 'alert', severity: 'high', title: 'T', message: 'M',
            data: { iocId: '123' },
        });
        expect(result.data).toEqual({ iocId: '123' });
    });
});

// ============================================================================
// Playbook Schemas
// ============================================================================

describe('CreatePlaybookSchema', () => {
    const validPlaybook = {
        name: 'Auto-enrich malware',
        triggerEvent: 'ioc.created',
        actions: [{ type: 'enrich' as const, config: { provider: 'virustotal' } }],
    };

    it('accepts valid playbook', () => {
        const result = CreatePlaybookSchema.parse(validPlaybook);
        expect(result.name).toBe('Auto-enrich malware');
        expect(result.actions).toHaveLength(1);
    });

    it('rejects missing name', () => {
        expect(() => CreatePlaybookSchema.parse({ ...validPlaybook, name: '' })).toThrow();
    });

    it('rejects missing triggerEvent', () => {
        expect(() => CreatePlaybookSchema.parse({ ...validPlaybook, triggerEvent: '' })).toThrow();
    });

    it('rejects empty actions array', () => {
        expect(() => CreatePlaybookSchema.parse({ ...validPlaybook, actions: [] })).toThrow();
    });

    it('rejects invalid action type', () => {
        expect(() => CreatePlaybookSchema.parse({
            ...validPlaybook,
            actions: [{ type: 'invalid', config: {} }],
        })).toThrow();
    });

    it('accepts all valid action types', () => {
        for (const type of ['enrich', 'notify', 'alert', 'tag', 'warninglist_check'] as const) {
            const result = CreatePlaybookSchema.parse({
                ...validPlaybook,
                actions: [{ type, config: {} }],
            });
            expect(result.actions[0].type).toBe(type);
        }
    });

    it('accepts optional description and conditions', () => {
        const result = CreatePlaybookSchema.parse({
            ...validPlaybook,
            description: 'Auto enrichment',
            conditions: { source: 'otx' },
        });
        expect(result.description).toBe('Auto enrichment');
        expect(result.conditions).toEqual({ source: 'otx' });
    });
});

describe('UpdatePlaybookSchema', () => {
    it('accepts empty object (all optional)', () => {
        const result = UpdatePlaybookSchema.parse({});
        expect(result).toEqual({});
    });

    it('accepts partial update', () => {
        const result = UpdatePlaybookSchema.parse({ name: 'Renamed', enabled: false });
        expect(result.name).toBe('Renamed');
        expect(result.enabled).toBe(false);
    });

    it('rejects invalid action type in update', () => {
        expect(() => UpdatePlaybookSchema.parse({
            actions: [{ type: 'invalid', config: {} }],
        })).toThrow();
    });

    it('rejects empty actions array in update', () => {
        expect(() => UpdatePlaybookSchema.parse({ actions: [] })).toThrow();
    });
});
