/**
 * Alert Schema Unit Tests
 *
 * Tests Zod validation schemas for alert mutation endpoints.
 */

import { describe, it, expect } from 'vitest';
import { CreateAlertSchema, UpdateAlertSchema, BulkAckSchema } from '../lib/schemas';

// ============================================================================
// CreateAlertSchema
// ============================================================================

describe('CreateAlertSchema', () => {
    it('should validate a complete alert', () => {
        const result = CreateAlertSchema.safeParse({
            severity: 'high',
            type: 'ioc_detected',
            title: 'Malicious IP detected',
            message: 'Found suspicious activity from 1.2.3.4',
            source: 'manual',
            metadata: { ip: '1.2.3.4' },
        });
        expect(result.success).toBe(true);
    });

    it('should apply defaults for severity and type', () => {
        const result = CreateAlertSchema.parse({
            title: 'Test alert',
            message: 'Test message',
        });
        expect(result.severity).toBe('medium');
        expect(result.type).toBe('system_alert');
    });

    it('should reject missing title', () => {
        const result = CreateAlertSchema.safeParse({
            message: 'Some message',
        });
        expect(result.success).toBe(false);
    });

    it('should reject missing message', () => {
        const result = CreateAlertSchema.safeParse({
            title: 'Some title',
        });
        expect(result.success).toBe(false);
    });

    it('should reject empty title', () => {
        const result = CreateAlertSchema.safeParse({
            title: '',
            message: 'Valid message',
        });
        expect(result.success).toBe(false);
    });

    it('should reject invalid severity', () => {
        const result = CreateAlertSchema.safeParse({
            severity: 'extreme',
            title: 'Test',
            message: 'Message',
        });
        expect(result.success).toBe(false);
    });

    it('should accept all valid severity levels', () => {
        for (const severity of ['critical', 'high', 'medium', 'low', 'info']) {
            const result = CreateAlertSchema.safeParse({
                severity,
                title: 'Test',
                message: 'Message',
            });
            expect(result.success).toBe(true);
        }
    });

    it('should reject title exceeding max length', () => {
        const result = CreateAlertSchema.safeParse({
            title: 'x'.repeat(501),
            message: 'Valid message',
        });
        expect(result.success).toBe(false);
    });
});

// ============================================================================
// UpdateAlertSchema
// ============================================================================

describe('UpdateAlertSchema', () => {
    it('should accept empty object (no-op update)', () => {
        const result = UpdateAlertSchema.safeParse({});
        expect(result.success).toBe(true);
    });

    it('should validate partial updates', () => {
        const result = UpdateAlertSchema.parse({
            severity: 'critical',
            read: true,
        });
        expect(result.severity).toBe('critical');
        expect(result.read).toBe(true);
        expect(result.title).toBeUndefined();
    });

    it('should reject invalid severity in update', () => {
        const result = UpdateAlertSchema.safeParse({
            severity: 'banana',
        });
        expect(result.success).toBe(false);
    });

    it('should accept boolean read field', () => {
        expect(UpdateAlertSchema.safeParse({ read: false }).success).toBe(true);
        expect(UpdateAlertSchema.safeParse({ read: true }).success).toBe(true);
    });
});

// ============================================================================
// BulkAckSchema
// ============================================================================

describe('BulkAckSchema', () => {
    it('should validate array of UUIDs', () => {
        const result = BulkAckSchema.safeParse({
            ids: ['550e8400-e29b-41d4-a716-446655440000'],
        });
        expect(result.success).toBe(true);
    });

    it('should reject empty array', () => {
        const result = BulkAckSchema.safeParse({
            ids: [],
        });
        expect(result.success).toBe(false);
    });

    it('should reject non-UUID strings', () => {
        const result = BulkAckSchema.safeParse({
            ids: ['not-a-uuid'],
        });
        expect(result.success).toBe(false);
    });

    it('should reject missing ids field', () => {
        const result = BulkAckSchema.safeParse({});
        expect(result.success).toBe(false);
    });

    it('should accept multiple valid UUIDs', () => {
        const result = BulkAckSchema.safeParse({
            ids: [
                '550e8400-e29b-41d4-a716-446655440000',
                '6ba7b810-9dad-11d1-80b4-00c04fd430c8',
                'f47ac10b-58cc-4372-a567-0e02b2c3d479',
            ],
        });
        expect(result.success).toBe(true);
    });
});
