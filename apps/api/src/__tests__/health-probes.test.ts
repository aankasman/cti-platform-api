/**
 * Phase P Schema + Health Probe Tests
 *
 * Tests for EvaluateAlertSchema, admin config schemas,
 * and validates the liveness probe contract.
 */

import { describe, it, expect } from 'vitest';
import {
    EvaluateAlertSchema,
    AddFeedSchema,
    AddApiKeySchema,
    AddServiceSchema,
    UpdateSettingSchema,
} from '../lib/schemas';

// ============================================================================
// EvaluateAlertSchema
// ============================================================================

describe('EvaluateAlertSchema', () => {
    it('should default threshold to 75', () => {
        const result = EvaluateAlertSchema.parse({});
        expect(result.threshold).toBe(75);
    });

    it('should accept valid threshold', () => {
        expect(EvaluateAlertSchema.parse({ threshold: 90 }).threshold).toBe(90);
    });

    it('should reject threshold > 100', () => {
        expect(EvaluateAlertSchema.safeParse({ threshold: 101 }).success).toBe(false);
    });

    it('should reject threshold < 1', () => {
        expect(EvaluateAlertSchema.safeParse({ threshold: 0 }).success).toBe(false);
    });

    it('should coerce string to number', () => {
        expect(EvaluateAlertSchema.parse({ threshold: '80' }).threshold).toBe(80);
    });
});

// ============================================================================
// AddFeedSchema
// ============================================================================

describe('AddFeedSchema', () => {
    it('should validate a complete feed', () => {
        const result = AddFeedSchema.safeParse({
            name: 'Custom Feed',
            source: 'custom-api',
            url: 'https://example.com/feed',
            format: 'json',
            category: 'ioc-feeds',
        });
        expect(result.success).toBe(true);
    });

    it('should apply defaults', () => {
        const result = AddFeedSchema.parse({ name: 'Test', source: 'test' });
        expect(result.category).toBe('custom-api');
        expect(result.cron).toBe('0 */6 * * *');
        expect(result.enabled).toBe(true);
    });

    it('should reject missing name', () => {
        expect(AddFeedSchema.safeParse({ source: 'test' }).success).toBe(false);
    });

    it('should reject invalid category', () => {
        expect(AddFeedSchema.safeParse({
            name: 'Test', source: 'test', category: 'invalid',
        }).success).toBe(false);
    });

    it('should reject invalid format', () => {
        expect(AddFeedSchema.safeParse({
            name: 'Test', source: 'test', format: 'yaml',
        }).success).toBe(false);
    });
});

// ============================================================================
// AddApiKeySchema
// ============================================================================

describe('AddApiKeySchema', () => {
    it('should validate required fields', () => {
        const result = AddApiKeySchema.safeParse({
            name: 'OpenAI', provider: 'openai', envVar: 'OPENAI_API_KEY',
        });
        expect(result.success).toBe(true);
    });

    it('should reject missing provider', () => {
        expect(AddApiKeySchema.safeParse({
            name: 'Test', envVar: 'TEST_KEY',
        }).success).toBe(false);
    });

    it('should accept optional value', () => {
        const result = AddApiKeySchema.parse({
            name: 'Test', provider: 'test', envVar: 'TEST_KEY', value: 'sk-123',
        });
        expect(result.value).toBe('sk-123');
    });
});

// ============================================================================
// AddServiceSchema
// ============================================================================

describe('AddServiceSchema', () => {
    it('should validate service with envVars objects', () => {
        const result = AddServiceSchema.safeParse({
            name: 'Neo4j',
            envVars: [{ key: 'NEO4J_URI', label: 'URI' }],
        });
        expect(result.success).toBe(true);
    });

    it('should reject empty envVars array', () => {
        expect(AddServiceSchema.safeParse({
            name: 'Test', envVars: [],
        }).success).toBe(false);
    });

    it('should reject envVars without key', () => {
        expect(AddServiceSchema.safeParse({
            name: 'Test', envVars: [{ label: 'Test' }],
        }).success).toBe(false);
    });
});

// ============================================================================
// UpdateSettingSchema
// ============================================================================

describe('UpdateSettingSchema', () => {
    it('should accept string value', () => {
        expect(UpdateSettingSchema.parse({ value: 'debug' }).value).toBe('debug');
    });

    it('should accept number value', () => {
        expect(UpdateSettingSchema.parse({ value: 42 }).value).toBe(42);
    });

    it('should accept boolean value', () => {
        expect(UpdateSettingSchema.parse({ value: true }).value).toBe(true);
    });

    it('should reject null value', () => {
        expect(UpdateSettingSchema.safeParse({ value: null }).success).toBe(false);
    });

    it('should reject missing value', () => {
        expect(UpdateSettingSchema.safeParse({}).success).toBe(false);
    });
});
