/**
 * Phase S — STIX, Users, Sightings & Config Schema Tests
 *
 * Validates all new Zod schemas added in Phase S:
 *  - StixImportSchema, StixExportSchema
 *  - CreateUserSchema, UpdateUserSchema
 *  - AddSightingSchema
 *  - Config schemas (AddFeedSchema, AddApiKeySchema, AddServiceSchema,
 *    UpdateFeedSchema, UpdateApiKeyValueSchema, UpdateServiceSchema)
 */

import { describe, it, expect } from 'vitest';
import {
    StixImportSchema,
    StixExportSchema,
    CreateUserSchema,
    UpdateUserSchema,
    AddSightingSchema,
    AddFeedSchema,
    AddApiKeySchema,
    AddServiceSchema,
    UpdateFeedSchema,
    UpdateApiKeyValueSchema,
    UpdateServiceSchema,
} from '../lib/schemas';

// ============================================================================
// STIX Import Schema
// ============================================================================

describe('StixImportSchema', () => {
    const validBundle = {
        type: 'bundle' as const,
        id: 'bundle--abc-123',
        objects: [
            { type: 'indicator', id: 'indicator--001' },
            { type: 'vulnerability', id: 'vulnerability--002' },
        ],
    };

    it('accepts valid STIX bundle', () => {
        const result = StixImportSchema.parse(validBundle);
        expect(result.type).toBe('bundle');
        expect(result.id).toBe('bundle--abc-123');
        expect(result.objects).toHaveLength(2);
        expect(result.dryRun).toBe(false);
    });

    it('accepts dryRun = true', () => {
        const result = StixImportSchema.parse({ ...validBundle, dryRun: true });
        expect(result.dryRun).toBe(true);
    });

    it('defaults dryRun to false', () => {
        const result = StixImportSchema.parse(validBundle);
        expect(result.dryRun).toBe(false);
    });

    it('rejects non-bundle type', () => {
        expect(() =>
            StixImportSchema.parse({ ...validBundle, type: 'report' })
        ).toThrow();
    });

    it('rejects missing id', () => {
        expect(() =>
            StixImportSchema.parse({ type: 'bundle', objects: [] })
        ).toThrow();
    });

    it('rejects missing objects', () => {
        expect(() =>
            StixImportSchema.parse({ type: 'bundle', id: 'bundle--1' })
        ).toThrow();
    });

    it('rejects oversized bundle (>10000 objects)', () => {
        const bigObjects = Array.from({ length: 10001 }, (_, i) => ({
            type: 'indicator',
            id: `indicator--${i}`,
        }));
        expect(() =>
            StixImportSchema.parse({ ...validBundle, objects: bigObjects })
        ).toThrow();
    });

    it('accepts exactly 10000 objects', () => {
        const objects = Array.from({ length: 10000 }, (_, i) => ({
            type: 'indicator',
            id: `indicator--${i}`,
        }));
        const result = StixImportSchema.parse({ ...validBundle, objects });
        expect(result.objects).toHaveLength(10000);
    });

    it('passes through extra fields (STIX extension)', () => {
        const result = StixImportSchema.parse({
            ...validBundle,
            spec_version: '2.1',
        });
        expect((result as any).spec_version).toBe('2.1');
    });
});

// ============================================================================
// STIX Export Schema
// ============================================================================

describe('StixExportSchema', () => {
    it('accepts valid export request', () => {
        const result = StixExportSchema.parse({
            entityTypes: ['iocs', 'cves'],
            includeRelationships: false,
            limit: 500,
        });
        expect(result.entityTypes).toEqual(['iocs', 'cves']);
        expect(result.includeRelationships).toBe(false);
        expect(result.limit).toBe(500);
    });

    it('applies defaults', () => {
        const result = StixExportSchema.parse({});
        expect(result.entityTypes).toEqual(['iocs']);
        expect(result.includeRelationships).toBe(true);
        expect(result.limit).toBe(1000);
    });

    it('rejects limit below 1', () => {
        expect(() =>
            StixExportSchema.parse({ limit: 0 })
        ).toThrow();
    });

    it('rejects limit above 5000', () => {
        expect(() =>
            StixExportSchema.parse({ limit: 5001 })
        ).toThrow();
    });

    it('accepts max limit of 5000', () => {
        const result = StixExportSchema.parse({ limit: 5000 });
        expect(result.limit).toBe(5000);
    });
});

// ============================================================================
// User Schemas
// ============================================================================

describe('CreateUserSchema', () => {
    const validUser = {
        email: 'analyst@rinjani.io',
        name: 'Test Analyst',
        role: 'analyst' as const,
    };

    it('accepts valid user creation', () => {
        const result = CreateUserSchema.parse(validUser);
        expect(result.email).toBe('analyst@rinjani.io');
        expect(result.name).toBe('Test Analyst');
        expect(result.role).toBe('analyst');
    });

    it('rejects invalid email', () => {
        expect(() =>
            CreateUserSchema.parse({ ...validUser, email: 'not-an-email' })
        ).toThrow();
    });

    it('rejects missing name', () => {
        expect(() =>
            CreateUserSchema.parse({ email: 'a@b.com', role: 'viewer' })
        ).toThrow();
    });

    it('rejects empty name', () => {
        expect(() =>
            CreateUserSchema.parse({ ...validUser, name: '' })
        ).toThrow();
    });

    it('rejects invalid role', () => {
        expect(() =>
            CreateUserSchema.parse({ ...validUser, role: 'superadmin' })
        ).toThrow();
    });

    it('accepts all valid roles', () => {
        for (const role of ['admin', 'analyst', 'viewer']) {
            const result = CreateUserSchema.parse({ ...validUser, role });
            expect(result.role).toBe(role);
        }
    });
});

describe('UpdateUserSchema', () => {
    it('accepts partial update (email only)', () => {
        const result = UpdateUserSchema.parse({ email: 'new@rinjani.io' });
        expect(result.email).toBe('new@rinjani.io');
        expect(result.name).toBeUndefined();
    });

    it('accepts partial update (status only)', () => {
        const result = UpdateUserSchema.parse({ status: 'inactive' });
        expect(result.status).toBe('inactive');
    });

    it('accepts empty object (no changes)', () => {
        const result = UpdateUserSchema.parse({});
        expect(Object.keys(result)).toHaveLength(0);
    });

    it('rejects invalid status', () => {
        expect(() =>
            UpdateUserSchema.parse({ status: 'banned' })
        ).toThrow();
    });

    it('accepts all valid statuses', () => {
        for (const status of ['active', 'inactive', 'pending']) {
            const result = UpdateUserSchema.parse({ status });
            expect(result.status).toBe(status);
        }
    });

    it('rejects invalid email format', () => {
        expect(() =>
            UpdateUserSchema.parse({ email: 'bad' })
        ).toThrow();
    });
});

// ============================================================================
// Sighting Schema
// ============================================================================

describe('AddSightingSchema', () => {
    it('accepts minimal sighting (source only)', () => {
        const result = AddSightingSchema.parse({ source: 'VirusTotal' });
        expect(result.source).toBe('VirusTotal');
        expect(result.type).toBeUndefined();
    });

    it('accepts full sighting payload', () => {
        const result = AddSightingSchema.parse({
            source: 'MISP',
            type: 'sighting',
            description: 'Observed in the wild',
            confidence: 85,
            count: 3,
            observedAt: '2025-01-15T10:00:00Z',
        });
        expect(result.source).toBe('MISP');
        expect(result.type).toBe('sighting');
        expect(result.confidence).toBe(85);
        expect(result.count).toBe(3);
    });

    it('rejects missing source', () => {
        expect(() =>
            AddSightingSchema.parse({})
        ).toThrow();
    });

    it('rejects empty source', () => {
        expect(() =>
            AddSightingSchema.parse({ source: '' })
        ).toThrow();
    });

    it('rejects invalid type', () => {
        expect(() =>
            AddSightingSchema.parse({ source: 'test', type: 'invalid' })
        ).toThrow();
    });

    it('accepts all valid types', () => {
        for (const type of ['sighting', 'false-positive', 'expiration']) {
            const result = AddSightingSchema.parse({ source: 'test', type });
            expect(result.type).toBe(type);
        }
    });

    it('rejects confidence below 0', () => {
        expect(() =>
            AddSightingSchema.parse({ source: 'test', confidence: -1 })
        ).toThrow();
    });

    it('rejects confidence above 100', () => {
        expect(() =>
            AddSightingSchema.parse({ source: 'test', confidence: 101 })
        ).toThrow();
    });

    it('rejects count below 1', () => {
        expect(() =>
            AddSightingSchema.parse({ source: 'test', count: 0 })
        ).toThrow();
    });

    it('rejects invalid observedAt datetime', () => {
        expect(() =>
            AddSightingSchema.parse({ source: 'test', observedAt: 'not-a-date' })
        ).toThrow();
    });
});

// ============================================================================
// Config Schemas (pre-existing but validated here for coverage)
// ============================================================================

describe('AddFeedSchema', () => {
    it('accepts valid feed', () => {
        const result = AddFeedSchema.parse({
            name: 'Custom OTX Feed',
            source: 'otx-custom',
        });
        expect(result.name).toBe('Custom OTX Feed');
        expect(result.enabled).toBe(true);
        expect(result.category).toBe('custom-api');
    });

    it('rejects missing name', () => {
        expect(() =>
            AddFeedSchema.parse({ source: 'x' })
        ).toThrow();
    });

    it('rejects missing source', () => {
        expect(() =>
            AddFeedSchema.parse({ name: 'Test' })
        ).toThrow();
    });

    it('accepts all valid categories', () => {
        const categories = ['high-frequency', 'ioc-feeds', 'knowledge-base', 'nexus', 'custom-api', 'rss', 'financial', 'osint'];
        for (const category of categories) {
            const r = AddFeedSchema.parse({ name: 'N', source: 'S', category });
            expect(r.category).toBe(category);
        }
    });
});

describe('AddApiKeySchema', () => {
    it('accepts valid API key slot', () => {
        const result = AddApiKeySchema.parse({
            name: 'Custom VT',
            provider: 'VirusTotal',
            envVar: 'CUSTOM_VT_KEY',
        });
        expect(result.name).toBe('Custom VT');
        expect(result.provider).toBe('VirusTotal');
    });

    it('rejects missing provider', () => {
        expect(() =>
            AddApiKeySchema.parse({ name: 'N', envVar: 'V' })
        ).toThrow();
    });
});

describe('AddServiceSchema', () => {
    it('accepts valid service with envVars', () => {
        const result = AddServiceSchema.parse({
            name: 'Custom Neo4j',
            envVars: [{ key: 'NEO4J_URI', label: 'URI' }],
        });
        expect(result.name).toBe('Custom Neo4j');
        expect(result.envVars).toHaveLength(1);
    });

    it('rejects empty envVars', () => {
        expect(() =>
            AddServiceSchema.parse({ name: 'S', envVars: [] })
        ).toThrow();
    });
});

describe('UpdateFeedSchema', () => {
    it('accepts partial update', () => {
        const result = UpdateFeedSchema.parse({ enabled: false });
        expect(result.enabled).toBe(false);
    });

    it('accepts empty object', () => {
        const result = UpdateFeedSchema.parse({});
        expect(Object.keys(result)).toHaveLength(0);
    });

    it('rejects invalid URL', () => {
        expect(() =>
            UpdateFeedSchema.parse({ url: 'not-a-url' })
        ).toThrow();
    });
});

describe('UpdateApiKeyValueSchema', () => {
    it('accepts valid key value', () => {
        const result = UpdateApiKeyValueSchema.parse({ value: 'sk-abc123' });
        expect(result.value).toBe('sk-abc123');
    });

    it('rejects empty value', () => {
        expect(() =>
            UpdateApiKeyValueSchema.parse({ value: '' })
        ).toThrow();
    });

    it('rejects missing value', () => {
        expect(() =>
            UpdateApiKeyValueSchema.parse({})
        ).toThrow();
    });
});

describe('UpdateServiceSchema', () => {
    it('accepts any object (passthrough)', () => {
        const result = UpdateServiceSchema.parse({ NEO4J_URI: 'bolt://localhost:7687' });
        expect((result as any).NEO4J_URI).toBe('bolt://localhost:7687');
    });

    it('accepts empty object', () => {
        const result = UpdateServiceSchema.parse({});
        expect(Object.keys(result)).toHaveLength(0);
    });
});
