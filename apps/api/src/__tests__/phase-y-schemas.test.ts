/**
 * Phase Y — Remaining Validation Schemas Unit Tests
 *
 * Validates all Zod schemas added in Phase Y:
 *   - BatchCorrelationSchema
 *   - SightingListSchema, SightingFeedSchema
 *   - AlertListFilterSchema
 *   - AuditFilterSchema
 *   - StixBundleQuerySchema
 *   - TaxiiEnvelopeQuerySchema
 *   - IntelligenceIOCQuerySchema
 */

import { describe, test, expect } from 'vitest';
import {
    BatchCorrelationSchema,
    SightingListSchema,
    SightingFeedSchema,
    AlertListFilterSchema,
    AuditFilterSchema,
    StixBundleQuerySchema,
    TaxiiEnvelopeQuerySchema,
    IntelligenceIOCQuerySchema,
} from '../lib/schemas';

// ============================================================================
// BatchCorrelationSchema
// ============================================================================

describe('BatchCorrelationSchema', () => {
    test('accepts valid limit', () => {
        const result = BatchCorrelationSchema.parse({ limit: '200' });
        expect(result.limit).toBe(200);
    });

    test('uses default limit of 500', () => {
        const result = BatchCorrelationSchema.parse({});
        expect(result.limit).toBe(500);
    });

    test('rejects limit below 1', () => {
        expect(() => BatchCorrelationSchema.parse({ limit: '0' })).toThrow();
    });

    test('rejects limit above 5000', () => {
        expect(() => BatchCorrelationSchema.parse({ limit: '6000' })).toThrow();
    });

    test('coerces string to number', () => {
        const result = BatchCorrelationSchema.parse({ limit: '1000' });
        expect(result.limit).toBe(1000);
    });
});

// ============================================================================
// SightingListSchema
// ============================================================================

describe('SightingListSchema', () => {
    test('accepts valid limit and offset', () => {
        const result = SightingListSchema.parse({ limit: '25', offset: '10' });
        expect(result.limit).toBe(25);
        expect(result.offset).toBe(10);
    });

    test('uses defaults', () => {
        const result = SightingListSchema.parse({});
        expect(result.limit).toBe(50);
        expect(result.offset).toBe(0);
    });

    test('rejects limit above 500', () => {
        expect(() => SightingListSchema.parse({ limit: '1000' })).toThrow();
    });

    test('rejects negative offset', () => {
        expect(() => SightingListSchema.parse({ offset: '-1' })).toThrow();
    });
});

// ============================================================================
// SightingFeedSchema
// ============================================================================

describe('SightingFeedSchema', () => {
    test('accepts limit and optional iocId', () => {
        const result = SightingFeedSchema.parse({ limit: '20', iocId: 'abc-123' });
        expect(result.limit).toBe(20);
        expect(result.iocId).toBe('abc-123');
    });

    test('iocId is optional', () => {
        const result = SightingFeedSchema.parse({});
        expect(result.limit).toBe(50);
        expect(result.iocId).toBeUndefined();
    });
});

// ============================================================================
// AlertListFilterSchema
// ============================================================================

describe('AlertListFilterSchema', () => {
    test('accepts all filter params', () => {
        const result = AlertListFilterSchema.parse({
            page: '2',
            pageSize: '20',
            severity: 'critical',
            unread: 'true',
        });
        expect(result.page).toBe(2);
        expect(result.pageSize).toBe(20);
        expect(result.severity).toBe('critical');
        expect(result.unread).toBe(true);
    });

    test('uses pagination defaults', () => {
        const result = AlertListFilterSchema.parse({});
        expect(result.page).toBe(1);
        expect(result.pageSize).toBe(25);
        expect(result.severity).toBeUndefined();
        expect(result.unread).toBeUndefined();
    });

    test('rejects invalid severity', () => {
        expect(() => AlertListFilterSchema.parse({ severity: 'extreme' })).toThrow();
    });

    test('accepts all valid severity levels', () => {
        for (const sev of ['critical', 'high', 'medium', 'low', 'info']) {
            const result = AlertListFilterSchema.parse({ severity: sev });
            expect(result.severity).toBe(sev);
        }
    });
});

// ============================================================================
// AuditFilterSchema
// ============================================================================

describe('AuditFilterSchema', () => {
    test('accepts all filters', () => {
        const result = AuditFilterSchema.parse({
            entityType: 'ioc',
            entityId: 'abc-123',
            action: 'create',
            source: 'api',
            limit: '50',
            offset: '10',
        });
        expect(result.entityType).toBe('ioc');
        expect(result.entityId).toBe('abc-123');
        expect(result.action).toBe('create');
        expect(result.source).toBe('api');
        expect(result.limit).toBe(50);
        expect(result.offset).toBe(10);
    });

    test('all string filters are optional', () => {
        const result = AuditFilterSchema.parse({});
        expect(result.entityType).toBeUndefined();
        expect(result.entityId).toBeUndefined();
        expect(result.action).toBeUndefined();
        expect(result.source).toBeUndefined();
    });
});

// ============================================================================
// StixBundleQuerySchema
// ============================================================================

describe('StixBundleQuerySchema', () => {
    test('accepts all query params', () => {
        const result = StixBundleQuerySchema.parse({
            include: 'iocs,threats',
            limit: '500',
            type: 'ip',
            source: 'alienvault',
            severity: 'high',
        });
        expect(result.include).toBe('iocs,threats');
        expect(result.limit).toBe(500);
        expect(result.type).toBe('ip');
        expect(result.source).toBe('alienvault');
        expect(result.severity).toBe('high');
    });

    test('all params are optional with limit default', () => {
        const result = StixBundleQuerySchema.parse({});
        expect(result.include).toBeUndefined();
        expect(result.limit).toBe(50); // LimitSchema default
        expect(result.type).toBeUndefined();
    });
});

// ============================================================================
// TaxiiEnvelopeQuerySchema
// ============================================================================

describe('TaxiiEnvelopeQuerySchema', () => {
    test('accepts all TAXII query params', () => {
        const result = TaxiiEnvelopeQuerySchema.parse({
            added_after: '2024-01-01T00:00:00Z',
            limit: '50',
            next: 'cursor-abc',
            'match[type]': 'indicator',
            'match[id]': 'indicator--123',
        });
        expect(result.added_after).toBe('2024-01-01T00:00:00Z');
        expect(result.limit).toBe(50);
        expect(result.next).toBe('cursor-abc');
        expect(result['match[type]']).toBe('indicator');
        expect(result['match[id]']).toBe('indicator--123');
    });

    test('uses default limit of 100', () => {
        const result = TaxiiEnvelopeQuerySchema.parse({});
        expect(result.limit).toBe(100);
    });

    test('caps limit at 1000', () => {
        expect(() => TaxiiEnvelopeQuerySchema.parse({ limit: '2000' })).toThrow();
    });
});

// ============================================================================
// IntelligenceIOCQuerySchema
// ============================================================================

describe('IntelligenceIOCQuerySchema', () => {
    test('accepts refresh and sources', () => {
        const result = IntelligenceIOCQuerySchema.parse({
            refresh: 'true',
            sources: 'virustotal,shodan',
        });
        expect(result.refresh).toBe(true);
        expect(result.sources).toBe('virustotal,shodan');
    });

    test('defaults refresh to false', () => {
        const result = IntelligenceIOCQuerySchema.parse({});
        expect(result.refresh).toBe(false);
        expect(result.sources).toBeUndefined();
    });

    test('coerces refresh boolean from string', () => {
        // z.coerce.boolean() treats any non-empty string as truthy
        expect(IntelligenceIOCQuerySchema.parse({ refresh: 'false' }).refresh).toBe(true);
        expect(IntelligenceIOCQuerySchema.parse({ refresh: '' }).refresh).toBe(false);
    });
});
