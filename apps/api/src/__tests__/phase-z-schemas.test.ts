/**
 * Phase Z — Final Validation Sweep Schema Tests
 *
 * Validates all Zod schemas added in Phase Z:
 *   - AdminAuditListSchema, AdminAuditStatsSchema
 *   - AdminUserListSchema
 *   - AdminQueueCleanSchema, AdminQueueJobsSchema
 *   - AdminDLQListSchema
 *   - AdminStreamClaimSchema
 *   - UserListQuerySchema
 *   - BulkExportQuerySchema
 *   - MetricsGrowthQuerySchema
 *   - AIAnalyzeSchema        (Phase AA)
 *   - SSEPublishSchema       (Phase AB)
 */

import { describe, test, expect } from 'vitest';
import {
    AdminAuditListSchema,
    AdminAuditStatsSchema,
    AdminUserListSchema,
    AdminQueueCleanSchema,
    AdminQueueJobsSchema,
    AdminDLQListSchema,
    AdminStreamClaimSchema,
    UserListQuerySchema,
    BulkExportQuerySchema,
    MetricsGrowthQuerySchema,
    AIAnalyzeSchema,
    SSEPublishSchema,
} from '../lib/schemas';

// ============================================================================
// AdminAuditListSchema
// ============================================================================

describe('AdminAuditListSchema', () => {
    test('accepts all filter params', () => {
        const result = AdminAuditListSchema.parse({
            entityType: 'ioc',
            action: 'create',
            from: '2024-01-01',
            to: '2024-12-31',
            page: '3',
            limit: '25',
        });
        expect(result.entityType).toBe('ioc');
        expect(result.action).toBe('create');
        expect(result.from).toBe('2024-01-01');
        expect(result.to).toBe('2024-12-31');
        expect(result.page).toBe(3);
        expect(result.limit).toBe(25);
    });

    test('uses defaults', () => {
        const result = AdminAuditListSchema.parse({});
        expect(result.page).toBe(1);
        expect(result.limit).toBe(50);
        expect(result.entityType).toBeUndefined();
    });

    test('rejects limit above 100', () => {
        expect(() => AdminAuditListSchema.parse({ limit: '200' })).toThrow();
    });

    test('accepts any string action for filtering', () => {
        const result = AdminAuditListSchema.parse({ action: 'incident' });
        expect(result.action).toBe('incident');
    });

    test('rejects invalid entityType enum', () => {
        expect(() => AdminAuditListSchema.parse({ entityType: 'user' })).toThrow();
    });
});

// ============================================================================
// AdminAuditStatsSchema
// ============================================================================

describe('AdminAuditStatsSchema', () => {
    test('accepts valid days', () => {
        expect(AdminAuditStatsSchema.parse({ days: '90' }).days).toBe(90);
    });

    test('defaults to 30 days', () => {
        expect(AdminAuditStatsSchema.parse({}).days).toBe(30);
    });

    test('rejects above 365', () => {
        expect(() => AdminAuditStatsSchema.parse({ days: '400' })).toThrow();
    });
});

// ============================================================================
// AdminUserListSchema
// ============================================================================

describe('AdminUserListSchema', () => {
    test('accepts all params', () => {
        const result = AdminUserListSchema.parse({
            role: 'admin',
            status: 'active',
            search: 'test',
            page: '2',
            limit: '10',
        });
        expect(result.role).toBe('admin');
        expect(result.status).toBe('active');
        expect(result.search).toBe('test');
        expect(result.page).toBe(2);
        expect(result.limit).toBe(10);
    });

    test('rejects invalid status', () => {
        expect(() => AdminUserListSchema.parse({ status: 'banned' })).toThrow();
    });

    test('all params are optional', () => {
        const result = AdminUserListSchema.parse({});
        expect(result.role).toBeUndefined();
        expect(result.status).toBeUndefined();
    });
});

// ============================================================================
// AdminQueueCleanSchema
// ============================================================================

describe('AdminQueueCleanSchema', () => {
    test('accepts grace and limit', () => {
        const result = AdminQueueCleanSchema.parse({ grace: '5000', limit: '500' });
        expect(result.grace).toBe(5000);
        expect(result.limit).toBe(500);
    });

    test('uses defaults', () => {
        const result = AdminQueueCleanSchema.parse({});
        expect(result.grace).toBe(0);
        expect(result.limit).toBe(1000);
    });

    test('rejects limit above 10000', () => {
        expect(() => AdminQueueCleanSchema.parse({ limit: '20000' })).toThrow();
    });
});

// ============================================================================
// AdminQueueJobsSchema
// ============================================================================

describe('AdminQueueJobsSchema', () => {
    test('accepts all params', () => {
        const result = AdminQueueJobsSchema.parse({ state: 'waiting', start: '10', limit: '50' });
        expect(result.state).toBe('waiting');
        expect(result.start).toBe(10);
        expect(result.limit).toBe(50);
    });

    test('defaults to failed state', () => {
        expect(AdminQueueJobsSchema.parse({}).state).toBe('failed');
    });

    test('rejects invalid state', () => {
        expect(() => AdminQueueJobsSchema.parse({ state: 'invalid' })).toThrow();
    });

    test('accepts all valid states', () => {
        for (const state of ['waiting', 'active', 'completed', 'failed', 'delayed']) {
            expect(AdminQueueJobsSchema.parse({ state }).state).toBe(state);
        }
    });
});

// ============================================================================
// AdminDLQListSchema
// ============================================================================

describe('AdminDLQListSchema', () => {
    test('accepts page and limit', () => {
        const result = AdminDLQListSchema.parse({ page: '2', limit: '25' });
        expect(result.page).toBe(2);
        expect(result.limit).toBe(25);
    });

    test('uses defaults', () => {
        const result = AdminDLQListSchema.parse({});
        expect(result.page).toBe(1);
        expect(result.limit).toBe(50);
    });
});

// ============================================================================
// AdminStreamClaimSchema
// ============================================================================

describe('AdminStreamClaimSchema', () => {
    test('accepts all params', () => {
        const result = AdminStreamClaimSchema.parse({
            group: 'my-group',
            consumer: 'worker-1',
            minIdleMs: '30000',
        });
        expect(result.group).toBe('my-group');
        expect(result.consumer).toBe('worker-1');
        expect(result.minIdleMs).toBe(30000);
    });

    test('uses defaults', () => {
        const result = AdminStreamClaimSchema.parse({});
        expect(result.group).toBe('enrichment-group');
        expect(result.consumer).toBe('claimer');
        expect(result.minIdleMs).toBe(60000);
    });
});

// ============================================================================
// UserListQuerySchema
// ============================================================================

describe('UserListQuerySchema', () => {
    test('accepts status and role', () => {
        const result = UserListQuerySchema.parse({ status: 'active', role: 'admin' });
        expect(result.status).toBe('active');
        expect(result.role).toBe('admin');
    });

    test('all params are optional', () => {
        const result = UserListQuerySchema.parse({});
        expect(result.status).toBeUndefined();
        expect(result.role).toBeUndefined();
    });
});

// ============================================================================
// BulkExportQuerySchema
// ============================================================================

describe('BulkExportQuerySchema', () => {
    test('accepts valid formats', () => {
        for (const fmt of ['json', 'csv', 'stix']) {
            expect(BulkExportQuerySchema.parse({ format: fmt }).format).toBe(fmt);
        }
    });

    test('defaults to json', () => {
        expect(BulkExportQuerySchema.parse({}).format).toBe('json');
    });

    test('rejects invalid format', () => {
        expect(() => BulkExportQuerySchema.parse({ format: 'xml' })).toThrow();
    });
});

// ============================================================================
// MetricsGrowthQuerySchema
// ============================================================================

describe('MetricsGrowthQuerySchema', () => {
    test('accepts day and hour', () => {
        expect(MetricsGrowthQuerySchema.parse({ granularity: 'day' }).granularity).toBe('day');
        expect(MetricsGrowthQuerySchema.parse({ granularity: 'hour' }).granularity).toBe('hour');
    });

    test('defaults to day', () => {
        expect(MetricsGrowthQuerySchema.parse({}).granularity).toBe('day');
    });

    test('rejects invalid granularity', () => {
        expect(() => MetricsGrowthQuerySchema.parse({ granularity: 'week' })).toThrow();
    });
});

// ============================================================================
// AIAnalyzeSchema (Phase AA)
// ============================================================================

describe('AIAnalyzeSchema', () => {
    test('accepts valid input', () => {
        const result = AIAnalyzeSchema.parse({
            entityType: 'ioc',
            entityId: 'abc-123',
            entityData: { value: '1.2.3.4', type: 'ip' },
            forceRefresh: true,
        });
        expect(result.entityType).toBe('ioc');
        expect(result.entityId).toBe('abc-123');
        expect(result.forceRefresh).toBe(true);
    });

    test('rejects invalid entityType', () => {
        expect(() => AIAnalyzeSchema.parse({
            entityType: 'malware',
            entityId: 'abc',
            entityData: {},
        })).toThrow();
    });

    test('rejects empty entityId', () => {
        expect(() => AIAnalyzeSchema.parse({
            entityType: 'cve',
            entityId: '',
            entityData: {},
        })).toThrow();
    });

    test('defaults forceRefresh to false', () => {
        const result = AIAnalyzeSchema.parse({
            entityType: 'actor',
            entityId: 'actor-1',
            entityData: { name: 'APT29' },
        });
        expect(result.forceRefresh).toBe(false);
    });

    test('rejects missing entityData', () => {
        expect(() => AIAnalyzeSchema.parse({
            entityType: 'ioc',
            entityId: 'abc',
        })).toThrow();
    });
});

// ============================================================================
// SSEPublishSchema (Phase AB)
// ============================================================================

describe('SSEPublishSchema', () => {
    test('accepts valid input with all fields', () => {
        const result = SSEPublishSchema.parse({
            channel: 'alert',
            type: 'new_ioc',
            data: { id: '123', severity: 'high' },
            source: 'enrichment-worker',
        });
        expect(result.channel).toBe('alert');
        expect(result.source).toBe('enrichment-worker');
    });

    test('source is optional', () => {
        const result = SSEPublishSchema.parse({
            channel: 'system',
            type: 'heartbeat',
            data: {},
        });
        expect(result.source).toBeUndefined();
    });

    test('rejects invalid channel', () => {
        expect(() => SSEPublishSchema.parse({
            channel: 'invalid',
            type: 'test',
            data: {},
        })).toThrow();
    });

    test('rejects empty type', () => {
        expect(() => SSEPublishSchema.parse({
            channel: 'ioc',
            type: '',
            data: {},
        })).toThrow();
    });

    test('accepts all valid channels', () => {
        for (const ch of ['ioc', 'alert', 'feed', 'enrichment', 'system']) {
            const result = SSEPublishSchema.parse({ channel: ch, type: 'test', data: {} });
            expect(result.channel).toBe(ch);
        }
    });
});
