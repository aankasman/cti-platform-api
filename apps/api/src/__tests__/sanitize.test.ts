/**
 * SQL Sanitization Helper Tests
 */

import { describe, it, expect } from 'vitest';
import { escSql, escInt } from '../lib/sanitize';

describe('escSql', () => {
    it('should double single quotes', () => {
        expect(escSql("O'Brien")).toBe("O''Brien");
    });

    it('should handle multiple single quotes', () => {
        expect(escSql("it's a 'test'")).toBe("it''s a ''test''");
    });

    it('should strip null bytes', () => {
        expect(escSql("abc\x00def")).toBe("abcdef");
    });

    it('should return empty string for non-string input', () => {
        expect(escSql(undefined as any)).toBe('');
        expect(escSql(null as any)).toBe('');
        expect(escSql(42 as any)).toBe('');
    });

    it('should pass through safe strings unchanged', () => {
        expect(escSql('hello world')).toBe('hello world');
        expect(escSql('192.168.1.1')).toBe('192.168.1.1');
        expect(escSql('')).toBe('');
    });

    it('should handle SQL injection attempts', () => {
        expect(escSql("'; DROP TABLE iocs; --")).toBe("''; DROP TABLE iocs; --");
    });
});

describe('escInt', () => {
    it('should parse valid integers', () => {
        expect(escInt(42)).toBe(42);
        expect(escInt('100')).toBe(100);
    });

    it('should return fallback for NaN', () => {
        expect(escInt('abc')).toBe(0);
        expect(escInt('abc', 25)).toBe(25);
    });

    it('should return fallback for negative numbers', () => {
        expect(escInt(-5)).toBe(0);
        expect(escInt(-1, 10)).toBe(10);
    });

    it('should clamp to max', () => {
        expect(escInt(999999)).toBe(100000);
        expect(escInt(50, 0, 20)).toBe(20);
    });

    it('should floor floating point numbers', () => {
        expect(escInt(3.7)).toBe(3);
        expect(escInt('3.9')).toBe(3);
    });

    it('should handle null and undefined', () => {
        expect(escInt(null)).toBe(0);
        expect(escInt(undefined)).toBe(0);
    });
});
