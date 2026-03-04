/**
 * Redis Cache Service
 *
 * Provides distributed caching on the existing ioredis connection.
 * Replaces volatile in-memory Map with persistent Redis SET/GET + TTL.
 *
 * Key namespace: rjn:cache:*   (avoids collision with BullMQ keys)
 */

import { cacheConnection as connection } from './redis';
import { createLogger } from '../lib/logger';

const log = createLogger('RedisCache');

// ============================================================================
// Configuration
// ============================================================================

const KEY_PREFIX = 'rjn:cache:';

// Cache TTL by endpoint pattern (in seconds)
const CACHE_TTL: Record<string, number> = {
    '/v1/stats/distribution': 120,     // 2 minutes (aggregation query)
    '/v1/stats/severity-trend': 120,   // 2 minutes (date histogram)
    '/v1/stats/source-breakdown': 120, // 2 minutes (aggregation query)
    '/v1/stats/threat-heatmap': 120,   // 2 minutes (nested aggregation)
    '/v1/stats': 60,                   // 1 minute
    '/v1/monitoring/health': 30,       // 30 seconds
    '/v1/monitoring/feeds': 60,        // 1 minute
    '/v1/monitoring/metrics': 60,      // 1 minute
    '/v1/ops/system': 30,              // 30 seconds (health checks)
    '/v1/ops/ingestion': 60,           // 1 minute (ingestion metrics)
    '/v1/ops/enrichment': 30,          // 30 seconds (queue stats)
    '/v1/ops/workers': 15,             // 15 seconds (worker activity)
    '/v1/graph/layout': 300,           // 5 minutes (expensive computation)
    '/health': 10,                     // 10 seconds
};

const DEFAULT_TTL = 30; // 30 seconds default

// ============================================================================
// ETag Generation (FNV-1a — fast, non-cryptographic hash)
// ============================================================================

function fnv1aHash(str: string): string {
    let hash = 0x811c9dc5; // FNV offset basis (32-bit)
    for (let i = 0; i < str.length; i++) {
        hash ^= str.charCodeAt(i);
        hash = (hash * 0x01000193) >>> 0; // FNV prime, unsigned
    }
    return `"${hash.toString(16)}"`;
}

// ============================================================================
// Cache Operations
// ============================================================================

export interface CacheEntry {
    data: unknown;
    etag: string;
    createdAt: number;
}

/**
 * Get TTL for a given path
 */
export function getTTL(path: string): number {
    for (const [pattern, ttl] of Object.entries(CACHE_TTL)) {
        if (path.startsWith(pattern)) {
            return ttl;
        }
    }
    return DEFAULT_TTL;
}

/**
 * Retrieve a cached entry from Redis.
 * Returns null on miss or error (fail-open).
 */
export async function getCache(key: string): Promise<CacheEntry | null> {
    try {
        const raw = await connection.get(`${KEY_PREFIX}${key}`);
        if (!raw) return null;
        return JSON.parse(raw) as CacheEntry;
    } catch (err) {
        log.warn('Redis cache GET failed (fail-open)', { key, error: (err as Error).message });
        return null;
    }
}

/**
 * Store a value in Redis with TTL.
 * Returns the generated ETag.
 */
export async function setCache(key: string, data: unknown, ttlSeconds: number): Promise<CacheEntry> {
    const serialized = JSON.stringify(data);
    const entry: CacheEntry = {
        data,
        etag: fnv1aHash(serialized),
        createdAt: Date.now(),
    };

    try {
        await connection.setex(
            `${KEY_PREFIX}${key}`,
            ttlSeconds,
            JSON.stringify(entry),
        );
    } catch (err) {
        log.warn('Redis cache SET failed (fail-open)', { key, error: (err as Error).message });
    }

    return entry;
}

/**
 * Invalidate cache entries matching a pattern.
 * Uses SCAN to avoid blocking Redis.
 * Returns the number of deleted keys.
 */
export async function invalidateCache(pattern?: string): Promise<number> {
    try {
        const scanPattern = pattern
            ? `${KEY_PREFIX}*${pattern}*`
            : `${KEY_PREFIX}*`;

        let cursor = '0';
        let count = 0;

        do {
            const [nextCursor, keys] = await connection.scan(
                cursor, 'MATCH', scanPattern, 'COUNT', 100,
            );
            cursor = nextCursor;

            if (keys.length > 0) {
                await connection.del(...keys);
                count += keys.length;
            }
        } while (cursor !== '0');

        return count;
    } catch (err) {
        log.warn('Redis cache invalidation failed', { pattern, error: (err as Error).message });
        return 0;
    }
}

/**
 * Get cache statistics from Redis.
 */
export async function getCacheStats(): Promise<{
    keyCount: number;
    memoryUsedBytes: number | null;
    keys: string[];
}> {
    try {
        // Count cache keys via SCAN
        const keys: string[] = [];
        let cursor = '0';

        do {
            const [nextCursor, batch] = await connection.scan(
                cursor, 'MATCH', `${KEY_PREFIX}*`, 'COUNT', 200,
            );
            cursor = nextCursor;
            keys.push(...batch.map(k => k.replace(KEY_PREFIX, '')));
        } while (cursor !== '0');

        // Memory usage from Redis INFO
        let memoryUsedBytes: number | null = null;
        try {
            const info = await connection.info('memory');
            const match = info.match(/used_memory:(\d+)/);
            if (match) memoryUsedBytes = parseInt(match[1], 10);
        } catch { /* non-critical */ }

        return { keyCount: keys.length, memoryUsedBytes, keys };
    } catch (err) {
        log.warn('Redis cache stats failed', { error: (err as Error).message });
        return { keyCount: 0, memoryUsedBytes: null, keys: [] };
    }
}
