/**
 * Phase W — Admin Schemas Unit Tests
 *
 * Validates all Zod schemas added in Phase W:
 *   - CreateApiKeySchema, CreateWebhookSchema
 *   - AdminCreateUserSchema, AdminUpdateUserSchema
 *   - AdminCreateRoleSchema, AdminUpdateRoleSchema
 *   - AdminCreatePermModuleSchema, AdminUpdatePermModuleSchema
 *   - FeedSyncJobSchema, EnrichmentJobSchema, AiAnalysisJobSchema
 *   - NotificationJobQueueSchema, Neo4jSyncJobSchema
 *   - SandboxTestFeedSchema, SandboxTestEndpointSchema
 */

import { describe, test, expect } from 'vitest';
import {
    CreateApiKeySchema,
    CreateWebhookSchema,
    AdminCreateUserSchema,
    AdminUpdateUserSchema,
    AdminCreateRoleSchema,
    AdminUpdateRoleSchema,
    AdminCreatePermModuleSchema,
    AdminUpdatePermModuleSchema,
    FeedSyncJobSchema,
    EnrichmentJobSchema,
    AiAnalysisJobSchema,
    NotificationJobQueueSchema,
    Neo4jSyncJobSchema,
    SandboxTestFeedSchema,
    SandboxTestEndpointSchema,
} from '../lib/schemas';

// ============================================================================
// CreateApiKeySchema
// ============================================================================

describe('CreateApiKeySchema', () => {
    test('accepts empty object (defaults name)', () => {
        const result = CreateApiKeySchema.parse({});
        expect(result.name).toBe('API Key');
    });

    test('accepts custom name', () => {
        const result = CreateApiKeySchema.parse({ name: 'Production Key' });
        expect(result.name).toBe('Production Key');
    });

    test('rejects empty string name', () => {
        expect(() => CreateApiKeySchema.parse({ name: '' })).toThrow();
    });
});

// ============================================================================
// CreateWebhookSchema
// ============================================================================

describe('CreateWebhookSchema', () => {
    test('accepts valid webhook', () => {
        const result = CreateWebhookSchema.parse({
            name: 'My Webhook',
            url: 'https://example.com/hook',
        });
        expect(result.name).toBe('My Webhook');
        expect(result.url).toBe('https://example.com/hook');
        expect(result.events).toEqual(['*']);
        expect(result.headers).toEqual({});
    });

    test('rejects missing name', () => {
        expect(() => CreateWebhookSchema.parse({ url: 'https://x.com' })).toThrow();
    });

    test('rejects missing url', () => {
        expect(() => CreateWebhookSchema.parse({ name: 'test' })).toThrow();
    });

    test('rejects invalid url', () => {
        expect(() => CreateWebhookSchema.parse({
            name: 'test',
            url: 'not-a-url',
        })).toThrow();
    });

    test('accepts optional fields', () => {
        const result = CreateWebhookSchema.parse({
            name: 'Full',
            url: 'https://example.com/hook',
            secret: 's3cret',
            events: ['ioc.new', 'vuln.new'],
            filters: { severity: ['critical'] },
            headers: { 'X-Custom': 'value' },
        });
        expect(result.secret).toBe('s3cret');
        expect(result.events).toEqual(['ioc.new', 'vuln.new']);
        expect(result.filters.severity).toEqual(['critical']);
        expect(result.headers['X-Custom']).toBe('value');
    });
});

// ============================================================================
// AdminCreateUserSchema / AdminUpdateUserSchema
// ============================================================================

describe('AdminCreateUserSchema', () => {
    test('accepts valid user', () => {
        const result = AdminCreateUserSchema.parse({
            email: 'admin@rinjani.io',
            name: 'Admin',
            role: 'admin',
        });
        expect(result.email).toBe('admin@rinjani.io');
    });

    test('rejects invalid email', () => {
        expect(() => AdminCreateUserSchema.parse({
            email: 'not-email',
            name: 'X',
            role: 'admin',
        })).toThrow();
    });

    test('rejects missing required fields', () => {
        expect(() => AdminCreateUserSchema.parse({ email: 'a@b.com' })).toThrow();
        expect(() => AdminCreateUserSchema.parse({ name: 'x' })).toThrow();
    });
});

describe('AdminUpdateUserSchema', () => {
    test('accepts partial update', () => {
        const result = AdminUpdateUserSchema.parse({ name: 'New Name' });
        expect(result.name).toBe('New Name');
        expect(result.email).toBeUndefined();
    });

    test('accepts empty object', () => {
        const result = AdminUpdateUserSchema.parse({});
        expect(result).toBeDefined();
    });
});

// ============================================================================
// AdminCreateRoleSchema / AdminUpdateRoleSchema
// ============================================================================

describe('AdminCreateRoleSchema', () => {
    test('accepts valid role', () => {
        const result = AdminCreateRoleSchema.parse({
            id: 'analyst',
            name: 'Analyst',
        });
        expect(result.description).toBe('');
        expect(result.defaultPermissions).toEqual([]);
    });

    test('rejects missing id', () => {
        expect(() => AdminCreateRoleSchema.parse({ name: 'Test' })).toThrow();
    });
});

describe('AdminUpdateRoleSchema', () => {
    test('accepts partial update', () => {
        const result = AdminUpdateRoleSchema.parse({ name: 'Updated' });
        expect(result.name).toBe('Updated');
    });
});

// ============================================================================
// AdminCreatePermModuleSchema / AdminUpdatePermModuleSchema
// ============================================================================

describe('AdminCreatePermModuleSchema', () => {
    test('accepts valid module', () => {
        const result = AdminCreatePermModuleSchema.parse({
            id: 'dashboard',
            name: 'Dashboard',
        });
        expect(result.icon).toBe('settings');
        expect(result.permissions).toEqual([]);
    });

    test('accepts with permissions array', () => {
        const result = AdminCreatePermModuleSchema.parse({
            id: 'alerts',
            name: 'Alerts',
            permissions: [{ id: 'view', name: 'View Alerts', description: 'Can view alerts' }],
        });
        expect(result.permissions).toHaveLength(1);
    });

    test('rejects invalid permission objects', () => {
        expect(() => AdminCreatePermModuleSchema.parse({
            id: 'x',
            name: 'X',
            permissions: [{ id: '' }], // missing name, description
        })).toThrow();
    });
});

describe('AdminUpdatePermModuleSchema', () => {
    test('accepts partial update', () => {
        const result = AdminUpdatePermModuleSchema.parse({ icon: 'shield' });
        expect(result.icon).toBe('shield');
    });
});

// ============================================================================
// Job Schemas
// ============================================================================

describe('FeedSyncJobSchema', () => {
    test('defaults source to all', () => {
        const result = FeedSyncJobSchema.parse({});
        expect(result.source).toBe('all');
    });

    test('accepts custom source', () => {
        const result = FeedSyncJobSchema.parse({ source: 'alienvault' });
        expect(result.source).toBe('alienvault');
    });
});

describe('EnrichmentJobSchema', () => {
    test('accepts valid enrichment job', () => {
        const result = EnrichmentJobSchema.parse({
            iocId: 'uuid-123',
            iocValue: '192.168.1.1',
            iocType: 'ip',
        });
        expect(result.iocId).toBe('uuid-123');
    });

    test('rejects missing required fields', () => {
        expect(() => EnrichmentJobSchema.parse({ iocId: 'x' })).toThrow();
    });
});

describe('AiAnalysisJobSchema', () => {
    test('defaults analysisType', () => {
        const result = AiAnalysisJobSchema.parse({
            iocId: 'x',
            iocValue: '1.2.3.4',
        });
        expect(result.analysisType).toBe('threat-assessment');
    });
});

describe('NotificationJobQueueSchema', () => {
    test('accepts valid notification job', () => {
        const result = NotificationJobQueueSchema.parse({
            channel: 'slack',
            target: '#alerts',
            payload: { message: 'test' },
        });
        expect(result.channel).toBe('slack');
    });

    test('rejects missing payload', () => {
        expect(() => NotificationJobQueueSchema.parse({
            channel: 'slack',
            target: '#alerts',
        })).toThrow();
    });
});

describe('Neo4jSyncJobSchema', () => {
    test('defaults syncType', () => {
        const result = Neo4jSyncJobSchema.parse({});
        expect(result.syncType).toBe('all-iocs');
    });
});

// ============================================================================
// Sandbox Schemas
// ============================================================================

describe('SandboxTestFeedSchema', () => {
    test('accepts valid feed test', () => {
        const result = SandboxTestFeedSchema.parse({
            url: 'https://api.example.com/feed',
        });
        expect(result.method).toBe('GET');
    });

    test('rejects invalid URL', () => {
        expect(() => SandboxTestFeedSchema.parse({ url: 'not-url' })).toThrow();
    });

    test('rejects invalid method', () => {
        expect(() => SandboxTestFeedSchema.parse({
            url: 'https://x.com',
            method: 'DELETE',
        })).toThrow();
    });
});

describe('SandboxTestEndpointSchema', () => {
    test('accepts valid endpoint test', () => {
        const result = SandboxTestEndpointSchema.parse({
            url: 'https://api.example.com/test',
        });
        expect(result.method).toBe('GET');
        expect(result.timeoutMs).toBe(10000);
    });

    test('accepts all valid methods', () => {
        for (const m of ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD']) {
            const result = SandboxTestEndpointSchema.parse({
                url: 'https://x.com',
                method: m,
            });
            expect(result.method).toBeDefined();
        }
    });

    test('clamps timeout to max 30000', () => {
        expect(() => SandboxTestEndpointSchema.parse({
            url: 'https://x.com',
            timeoutMs: 60000,
        })).toThrow();
    });

    test('rejects invalid URL', () => {
        expect(() => SandboxTestEndpointSchema.parse({ url: 'bad' })).toThrow();
    });
});
