/**
 * Core Services Unit Tests
 */

import { describe, it, expect } from 'vitest';

describe('Audit Service', () => {
    describe('calculateDiff', () => {
        // Dynamic import to avoid path issues
        it('should detect changes between objects', async () => {
            const { calculateDiff } = await import('@rinjani/core/audit');

            const before = { name: 'test', status: 'active' };
            const after = { name: 'test', status: 'inactive' };

            const diff = calculateDiff(before, after);

            expect(diff).toContainEqual({
                field: 'status',
                old: 'active',
                new: 'inactive',
            });
        });

        it('should return empty array for identical objects', async () => {
            const { calculateDiff } = await import('@rinjani/core/audit');

            const before = { name: 'test', status: 'active' };
            const after = { name: 'test', status: 'active' };

            const diff = calculateDiff(before, after);

            expect(diff).toHaveLength(0);
        });
    });

    describe('generateDataHash', () => {
        it('should generate consistent hash for same data', async () => {
            const { generateDataHash } = await import('@rinjani/core/audit');

            const data = { name: 'test', value: 123 };

            const hash1 = generateDataHash(data);
            const hash2 = generateDataHash(data);

            expect(hash1).toBe(hash2);
        });
    });
});

describe('Deduplication Service', () => {
    describe('generateCanonicalId', () => {
        it('should generate consistent ID for same IOC', async () => {
            const { generateCanonicalId } = await import('@rinjani/core/deduplication');

            const id1 = generateCanonicalId('ip', '8.8.8.8');
            const id2 = generateCanonicalId('ip', '8.8.8.8');

            expect(id1).toBe(id2);
        });

        it('should normalize values before generating ID', async () => {
            const { generateCanonicalId } = await import('@rinjani/core/deduplication');

            const id1 = generateCanonicalId('domain', 'EXAMPLE.COM');
            const id2 = generateCanonicalId('domain', 'example.com');

            expect(id1).toBe(id2);
        });
    });

    describe('normalizeIOCValue', () => {
        it('should lowercase domain values', async () => {
            const { normalizeIOCValue } = await import('@rinjani/core/deduplication');

            const normalized = normalizeIOCValue('domain', 'EXAMPLE.COM');
            expect(normalized).toBe('example.com');
        });

        it('should trim whitespace', async () => {
            const { normalizeIOCValue } = await import('@rinjani/core/deduplication');

            const normalized = normalizeIOCValue('ip', '  8.8.8.8  ');
            expect(normalized).toBe('8.8.8.8');
        });
    });
});

describe('Enrichment Service', () => {
    describe('detectIOCType', () => {
        it('should detect IPv4 addresses', async () => {
            const { detectIOCType } = await import('@rinjani/core/enrichment');

            expect(detectIOCType('8.8.8.8')).toBe('ip');
            expect(detectIOCType('192.168.1.1')).toBe('ip');
        });

        it('should detect domains', async () => {
            const { detectIOCType } = await import('@rinjani/core/enrichment');

            expect(detectIOCType('example.com')).toBe('domain');
        });

        it('should detect URLs', async () => {
            const { detectIOCType } = await import('@rinjani/core/enrichment');

            expect(detectIOCType('https://example.com/path')).toBe('url');
        });

        it('should detect hashes', async () => {
            const { detectIOCType } = await import('@rinjani/core/enrichment');

            expect(detectIOCType('d41d8cd98f00b204e9800998ecf8427e')).toBe('hash');
        });

        it('should detect email addresses', async () => {
            const { detectIOCType } = await import('@rinjani/core/enrichment');

            expect(detectIOCType('user@example.com')).toBe('email');
        });

        it('should return null for unrecognized values', async () => {
            const { detectIOCType } = await import('@rinjani/core/enrichment');

            expect(detectIOCType('random text')).toBeNull();
        });
    });
});
