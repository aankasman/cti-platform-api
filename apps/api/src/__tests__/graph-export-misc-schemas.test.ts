/**
 * Phase T Schema Tests
 *
 * Unit tests for: Neo4jSyncSchema, CypherQuerySchema, ExportRequestSchema,
 * TaxiiInboundSchema, BulkEnrichSchema, StreamSubscribeSchema
 */

import { describe, it, expect } from 'vitest';
import {
    Neo4jSyncSchema,
    CypherQuerySchema,
    ExportRequestSchema,
    TaxiiInboundSchema,
    BulkEnrichSchema,
    StreamSubscribeSchema,
} from '../lib/schemas';

// ============================================================================
// Neo4jSyncSchema
// ============================================================================

describe('Neo4jSyncSchema', () => {
    it('accepts empty body with defaults', () => {
        const result = Neo4jSyncSchema.parse({});
        expect(result.syncType).toBe('full');
        expect(result.options).toEqual({});
    });

    it('accepts all valid syncType values', () => {
        for (const t of ['full', 'incremental', 'iocs', 'actors', 'cves']) {
            const result = Neo4jSyncSchema.parse({ syncType: t });
            expect(result.syncType).toBe(t);
        }
    });

    it('rejects invalid syncType', () => {
        expect(() => Neo4jSyncSchema.parse({ syncType: 'bogus' })).toThrow();
    });

    it('passes through options object', () => {
        const result = Neo4jSyncSchema.parse({ options: { batchSize: 500 } });
        expect(result.options).toEqual({ batchSize: 500 });
    });
});

// ============================================================================
// CypherQuerySchema
// ============================================================================

describe('CypherQuerySchema', () => {
    it('accepts valid query with defaults', () => {
        const result = CypherQuerySchema.parse({ query: 'MATCH (n) RETURN n' });
        expect(result.query).toBe('MATCH (n) RETURN n');
        expect(result.limit).toBe(100);
        expect(result.params).toBeUndefined();
    });

    it('accepts query with params and limit', () => {
        const result = CypherQuerySchema.parse({
            query: 'MATCH (n) WHERE n.name = $name RETURN n',
            params: { name: 'test' },
            limit: 50,
        });
        expect(result.params).toEqual({ name: 'test' });
        expect(result.limit).toBe(50);
    });

    it('rejects missing query', () => {
        expect(() => CypherQuerySchema.parse({})).toThrow();
    });

    it('rejects empty query', () => {
        expect(() => CypherQuerySchema.parse({ query: '' })).toThrow();
    });

    it('rejects limit below 1', () => {
        expect(() => CypherQuerySchema.parse({ query: 'MATCH (n) RETURN n', limit: 0 })).toThrow();
    });

    it('rejects limit above 1000', () => {
        expect(() => CypherQuerySchema.parse({ query: 'MATCH (n) RETURN n', limit: 1001 })).toThrow();
    });

    it('accepts max limit of 1000', () => {
        const result = CypherQuerySchema.parse({ query: 'MATCH (n) RETURN n', limit: 1000 });
        expect(result.limit).toBe(1000);
    });
});

// ============================================================================
// ExportRequestSchema
// ============================================================================

describe('ExportRequestSchema', () => {
    it('accepts empty body with defaults', () => {
        const result = ExportRequestSchema.parse({});
        expect(result.filters).toEqual({});
        expect(result.limit).toBe(10000);
    });

    it('accepts filters and custom limit', () => {
        const result = ExportRequestSchema.parse({
            filters: { type: 'ip', severity: 'high' },
            limit: 500,
        });
        expect(result.filters).toEqual({ type: 'ip', severity: 'high' });
        expect(result.limit).toBe(500);
    });

    it('rejects limit below 1', () => {
        expect(() => ExportRequestSchema.parse({ limit: 0 })).toThrow();
    });

    it('rejects limit above 50000', () => {
        expect(() => ExportRequestSchema.parse({ limit: 50001 })).toThrow();
    });

    it('accepts max limit of 50000', () => {
        const result = ExportRequestSchema.parse({ limit: 50000 });
        expect(result.limit).toBe(50000);
    });
});

// ============================================================================
// TaxiiInboundSchema
// ============================================================================

describe('TaxiiInboundSchema', () => {
    it('accepts valid STIX bundle', () => {
        const result = TaxiiInboundSchema.parse({
            type: 'bundle',
            objects: [{ type: 'indicator', id: 'indicator--1' }],
        });
        expect(result.type).toBe('bundle');
        expect(result.objects).toHaveLength(1);
    });

    it('rejects non-bundle type', () => {
        expect(() => TaxiiInboundSchema.parse({
            type: 'collection',
            objects: [],
        })).toThrow();
    });

    it('rejects missing objects', () => {
        expect(() => TaxiiInboundSchema.parse({ type: 'bundle' })).toThrow();
    });

    it('rejects bundle exceeding 10000 objects', () => {
        const objects = Array.from({ length: 10001 }, (_, i) => ({ id: `obj-${i}` }));
        expect(() => TaxiiInboundSchema.parse({
            type: 'bundle',
            objects,
        })).toThrow(/10,000/);
    });

    it('accepts exactly 10000 objects', () => {
        const objects = Array.from({ length: 10000 }, (_, i) => ({ id: `obj-${i}` }));
        const result = TaxiiInboundSchema.parse({ type: 'bundle', objects });
        expect(result.objects).toHaveLength(10000);
    });

    it('passes through extra fields (spec_version, id)', () => {
        const result = TaxiiInboundSchema.parse({
            type: 'bundle',
            id: 'bundle--abc',
            spec_version: '2.1',
            objects: [],
        });
        expect((result as any).id).toBe('bundle--abc');
        expect((result as any).spec_version).toBe('2.1');
    });
});

// ============================================================================
// BulkEnrichSchema
// ============================================================================

describe('BulkEnrichSchema', () => {
    it('accepts valid values array', () => {
        const result = BulkEnrichSchema.parse({ values: ['1.2.3.4', 'evil.com'] });
        expect(result.values).toEqual(['1.2.3.4', 'evil.com']);
    });

    it('rejects empty values array', () => {
        expect(() => BulkEnrichSchema.parse({ values: [] })).toThrow();
    });

    it('rejects missing values', () => {
        expect(() => BulkEnrichSchema.parse({})).toThrow();
    });

    it('rejects more than 100 values', () => {
        const values = Array.from({ length: 101 }, (_, i) => `val-${i}`);
        expect(() => BulkEnrichSchema.parse({ values })).toThrow(/100/);
    });

    it('accepts exactly 100 values', () => {
        const values = Array.from({ length: 100 }, (_, i) => `val-${i}`);
        const result = BulkEnrichSchema.parse({ values });
        expect(result.values).toHaveLength(100);
    });

    it('accepts single value', () => {
        const result = BulkEnrichSchema.parse({ values: ['8.8.8.8'] });
        expect(result.values).toEqual(['8.8.8.8']);
    });
});

// ============================================================================
// StreamSubscribeSchema
// ============================================================================

describe('StreamSubscribeSchema', () => {
    it('accepts empty body with defaults', () => {
        const result = StreamSubscribeSchema.parse({});
        expect(result.channels).toEqual(['webint']);
        expect(result.keywords).toEqual([]);
    });

    it('accepts custom channels and keywords', () => {
        const result = StreamSubscribeSchema.parse({
            channels: ['intel', 'social'],
            keywords: ['ransomware', 'apt28'],
        });
        expect(result.channels).toEqual(['intel', 'social']);
        expect(result.keywords).toEqual(['ransomware', 'apt28']);
    });

    it('accepts empty channels array', () => {
        const result = StreamSubscribeSchema.parse({ channels: [] });
        expect(result.channels).toEqual([]);
    });

    it('accepts channels only', () => {
        const result = StreamSubscribeSchema.parse({ channels: ['campaign'] });
        expect(result.channels).toEqual(['campaign']);
        expect(result.keywords).toEqual([]);
    });
});
