/**
 * Cache Middleware (Redis-backed)
 *
 * Provides distributed caching with TTL support via Redis.
 * Features: ETag / If-None-Match (304), Cache-Control headers, fail-open.
 */

import type { Context, Next } from 'hono';
import * as redisCache from '../../services/redisCache';

// ============================================================================
// Middleware
// ============================================================================

/**
 * Cache middleware with conditional request support
 *
 * Features:
 * - Redis-backed caching with TTL (auto-expiry)
 * - ETag support for conditional requests
 * - Cache-Control headers
 * - If-None-Match support (304 responses)
 * - Fail-open: if Redis is down, requests pass through to handler
 */
export function cacheMiddleware(customTTL?: number) {
    return async (c: Context, next: Next) => {
        const method = c.req.method;

        // Only cache GET requests
        if (method !== 'GET') {
            await next();
            return;
        }

        const path = c.req.path;
        const queryString = new URL(c.req.url).search;
        const cacheKey = `${path}${queryString}`;
        const ttl = customTTL || redisCache.getTTL(path);

        // Check for cached response in Redis
        const cached = await redisCache.getCache(cacheKey);

        if (cached) {
            // Check If-None-Match header (conditional request)
            const clientETag = c.req.header('If-None-Match');
            if (clientETag === cached.etag) {
                // Return 304 Not Modified
                c.header('ETag', cached.etag);
                c.header('Cache-Control', `public, max-age=${ttl}`);
                c.header('X-Cache', 'HIT');
                return c.body(null, 304);
            }

            // Return cached response
            c.header('ETag', cached.etag);
            c.header('Cache-Control', `public, max-age=${ttl}`);
            c.header('X-Cache', 'HIT');
            c.header('X-Cache-Age', String(Math.floor((Date.now() - cached.createdAt) / 1000)));
            return c.json(cached.data);
        }

        // Execute handler and cache response
        await next();

        // Only cache successful responses
        const status = c.res.status;
        if (status >= 200 && status < 300) {
            try {
                // Clone response to read body
                const cloned = c.res.clone();
                const data = await cloned.json();

                const entry = await redisCache.setCache(cacheKey, data, ttl);

                // Set cache headers on original response
                c.header('ETag', entry.etag);
                c.header('Cache-Control', `public, max-age=${ttl}`);
                c.header('X-Cache', 'MISS');
            } catch {
                // If we can't parse JSON, skip caching
            }
        }
    };
}

/**
 * Stats-specific cache (1 minute TTL)
 */
export const statsCacheMiddleware = cacheMiddleware(60);

/**
 * Monitoring cache (30 seconds TTL for near-real-time data)
 */
export const monitoringCacheMiddleware = cacheMiddleware(30);

// ============================================================================
// Cache Management API
// ============================================================================

import { Hono } from 'hono';

export const cacheRouter = new Hono();

// Get cache stats
cacheRouter.get('/stats', async (c) => {
    const stats = await redisCache.getCacheStats();
    return c.json({
        success: true,
        data: {
            size: stats.keyCount,
            entries: stats.keys,
            memoryUsage: stats.memoryUsedBytes,
            backend: 'redis',
        },
    });
});

// Invalidate cache
cacheRouter.delete('/', async (c) => {
    const pattern = c.req.query('pattern');
    const count = await redisCache.invalidateCache(pattern || undefined);
    return c.json({
        success: true,
        message: `Invalidated ${count} cache entries`,
        pattern: pattern || 'all',
    });
});
