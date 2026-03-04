/**
 * Scoring Engine Factor Calculator Tests
 *
 * Tests the pure mathematical functions used in composite risk scoring.
 * No DB or Neo4j calls — these only test the side-effect-free factor calculators.
 */

import { describe, it, expect } from 'vitest';
import { calcSourceConfidence, calcVtDetections, calcTemporalFreshness } from '../services/scoringEngine';

// ============================================================================
// calcSourceConfidence
// ============================================================================

describe('calcSourceConfidence', () => {
    it('should return confidence directly when provided', () => {
        expect(calcSourceConfidence(80)).toBe(80);
        expect(calcSourceConfidence(0)).toBe(0);
        expect(calcSourceConfidence(100)).toBe(100);
    });

    it('should default to 50 when null', () => {
        expect(calcSourceConfidence(null)).toBe(50);
    });

    it('should clamp to 0–100 range', () => {
        expect(calcSourceConfidence(-10)).toBe(0);
        expect(calcSourceConfidence(150)).toBe(100);
    });
});

// ============================================================================
// calcVtDetections
// ============================================================================

describe('calcVtDetections', () => {
    it('should return 0 for null/undefined rawData', () => {
        expect(calcVtDetections(null)).toBe(0);
        expect(calcVtDetections(undefined)).toBe(0);
    });

    it('should return 0 when no VT data is present', () => {
        expect(calcVtDetections({})).toBe(0);
        expect(calcVtDetections({ otherField: true })).toBe(0);
    });

    it('should calculate ratio from virustotal key', () => {
        const rawData = { virustotal: { malicious: 30, total: 60 } };
        expect(calcVtDetections(rawData)).toBe(50);
    });

    it('should handle vt shorthand key', () => {
        const rawData = { vt: { malicious: 10, total: 100 } };
        expect(calcVtDetections(rawData)).toBe(10);
    });

    it('should handle nested enrichment.virustotal key', () => {
        const rawData = { enrichment: { virustotal: { malicious: 70, total: 70 } } };
        expect(calcVtDetections(rawData)).toBe(100);
    });

    it('should handle positives/total_engines fallback fields', () => {
        const rawData = { virustotal: { positives: 5, total_engines: 50 } };
        expect(calcVtDetections(rawData)).toBe(10);
    });

    it('should return 0 when total is 0', () => {
        const rawData = { virustotal: { malicious: 10, total: 0 } };
        expect(calcVtDetections(rawData)).toBe(0);
    });
});

// ============================================================================
// calcTemporalFreshness
// ============================================================================

describe('calcTemporalFreshness', () => {
    it('should return 0 for null lastSeen', () => {
        expect(calcTemporalFreshness(null)).toBe(0);
    });

    it('should return ~100 for very recent timestamps', () => {
        const justNow = new Date().toISOString();
        expect(calcTemporalFreshness(justNow)).toBeGreaterThanOrEqual(99);
    });

    it('should return ~50 after one half-life (7 days)', () => {
        const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
        const score = calcTemporalFreshness(sevenDaysAgo);
        expect(score).toBeGreaterThanOrEqual(45);
        expect(score).toBeLessThanOrEqual(55);
    });

    it('should return ~25 after two half-lives (14 days)', () => {
        const fourteenDaysAgo = new Date(Date.now() - 14 * 24 * 60 * 60 * 1000).toISOString();
        const score = calcTemporalFreshness(fourteenDaysAgo);
        expect(score).toBeGreaterThanOrEqual(20);
        expect(score).toBeLessThanOrEqual(30);
    });

    it('should approach 0 for very old timestamps', () => {
        const yearAgo = new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString();
        expect(calcTemporalFreshness(yearAgo)).toBe(0);
    });

    it('should return 100 for future timestamps', () => {
        const future = new Date(Date.now() + 86400000).toISOString();
        expect(calcTemporalFreshness(future)).toBe(100);
    });
});
