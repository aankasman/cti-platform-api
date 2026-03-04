/**
 * Rate Limiting Middleware (Redis-backed)
 *
 * Distributed sliding-window rate limiting via Redis INCR + EXPIRE.
 * Supports role-based limits, endpoint-specific overrides,
 * abuse detection with penalty keys, and policy transparency headers.
 */

import type { Context, Next } from 'hono';
import { cacheConnection as connection } from '../../services/redis';
import { createLogger } from '../lib/logger';

const log = createLogger('RateLimiter');

// ============================================================================
// Configuration
// ============================================================================

const KEY_PREFIX = 'rjn:rl:';
const ABUSE_PREFIX = 'rjn:abuse:';
const METRICS_EXCEEDED_KEY = 'rjn:rl:exceeded:total';
const METRICS_ABUSE_KEY = 'rjn:rl:abuse:total';

/** Abuse threshold = 3× the normal limit in a single window */
const ABUSE_MULTIPLIER = 3;
/** Penalty TTL = 5 minutes */
const ABUSE_PENALTY_SECONDS = 300;

interface RateLimitConfig {
    maxRequests: number;
    windowSeconds: number;
}

// Role-based default limits
const ROLE_LIMITS: Record<string, RateLimitConfig> = {
    admin: { maxRequests: 1000, windowSeconds: 60 },
    analyst: { maxRequests: 300, windowSeconds: 60 },
    viewer: { maxRequests: 100, windowSeconds: 60 },
    anonymous: { maxRequests: 30, windowSeconds: 60 },
};

// Endpoint-specific overrides (stricter limits for expensive operations)
const ENDPOINT_LIMITS: Record<string, RateLimitConfig> = {
    '/v2/ai': { maxRequests: 10, windowSeconds: 60 },
    '/v2/bulk': { maxRequests: 5, windowSeconds: 60 },
    '/v1/graph/layout': { maxRequests: 60, windowSeconds: 60 },
    '/v2/search': { maxRequests: 50, windowSeconds: 60 },
    '/v1/export': { maxRequests: 20, windowSeconds: 60 },
    '/auth/login': { maxRequests: 10, windowSeconds: 300 },
};

// ============================================================================
// Middleware
// ============================================================================

/**
 * Rate limiting middleware using Redis sliding window counter.
 *
 * Uses Redis INCR + EXPIRE for atomic, distributed rate limiting.
 * Fail-open: if Redis is down, requests pass through.
 */
export function rateLimiter() {
    return async (c: Context, next: Next) => {
        const path = c.req.path;

        // Skip rate limiting for health endpoint
        if (path === '/health') {
            await next();
            return;
        }

        // Identify client
        const user = c.get('user') as { id?: string; role?: string; apiKey?: string } | undefined;
        const role = user?.role || 'anonymous';
        const clientId = user?.apiKey || user?.id || c.req.header('x-forwarded-for') || 'unknown';

        // Select rate limit config (endpoint-specific takes precedence)
        let config = ROLE_LIMITS[role] || ROLE_LIMITS.anonymous;
        let policyName = role;
        for (const [pattern, endpointConfig] of Object.entries(ENDPOINT_LIMITS)) {
            if (path.startsWith(pattern)) {
                config = endpointConfig;
                policyName = `endpoint:${pattern}`;
                break;
            }
        }

        try {
            // ================================================================
            // 1. Check abuse penalty (immediate rejection)
            // ================================================================
            const penaltyKey = `${ABUSE_PREFIX}${clientId}`;
            const penaltyTTL = await connection.ttl(penaltyKey);

            if (penaltyTTL > 0) {
                c.header('X-RateLimit-Policy', policyName);
                c.header('X-RateLimit-Limit', String(config.maxRequests));
                c.header('X-RateLimit-Remaining', '0');
                c.header('Retry-After', String(penaltyTTL));

                log.warn('Abuse penalty active — rejecting request', {
                    clientId,
                    penaltyTTL,
                    path,
                });

                return c.json({
                    success: false,
                    error: {
                        code: 'RATE_LIMIT_ABUSE',
                        message: `Sustained abuse detected. Try again in ${penaltyTTL}s.`,
                        retryAfter: penaltyTTL,
                    },
                }, 429);
            }

            // ================================================================
            // 2. Sliding window rate limit
            // ================================================================
            const windowKey = Math.floor(Date.now() / (config.windowSeconds * 1000));
            const redisKey = `${KEY_PREFIX}${clientId}:${windowKey}`;

            // Atomic increment + set expiry
            const currentCount = await connection.incr(redisKey);

            // Set expiry only on first request in window
            if (currentCount === 1) {
                await connection.expire(redisKey, config.windowSeconds + 1);
            }

            const remaining = Math.max(0, config.maxRequests - currentCount);
            const resetAt = (windowKey + 1) * config.windowSeconds;

            // Set rate limit headers
            c.header('X-RateLimit-Policy', policyName);
            c.header('X-RateLimit-Limit', String(config.maxRequests));
            c.header('X-RateLimit-Remaining', String(remaining));
            c.header('X-RateLimit-Reset', String(resetAt));

            if (currentCount > config.maxRequests) {
                // Increment global exceeded counter for Prometheus
                await connection.incr(METRICS_EXCEEDED_KEY).catch(() => { });

                c.header('Retry-After', String(config.windowSeconds));

                log.warn('Rate limit exceeded', {
                    clientId,
                    role,
                    path,
                    limit: config.maxRequests,
                    window: config.windowSeconds,
                    count: currentCount,
                });

                // ============================================================
                // 3. Abuse detection: if count > 3× limit, apply penalty
                // ============================================================
                if (currentCount > config.maxRequests * ABUSE_MULTIPLIER) {
                    await connection.setex(penaltyKey, ABUSE_PENALTY_SECONDS, '1');
                    await connection.incr(METRICS_ABUSE_KEY).catch(() => { });

                    log.error('Abuse detected — applying penalty', {
                        clientId,
                        role,
                        path,
                        count: currentCount,
                        limit: config.maxRequests,
                        penaltySeconds: ABUSE_PENALTY_SECONDS,
                    });
                }

                return c.json({
                    success: false,
                    error: {
                        code: 'RATE_LIMIT_EXCEEDED',
                        message: `Rate limit exceeded. ${config.maxRequests} requests per ${config.windowSeconds}s allowed.`,
                        retryAfter: config.windowSeconds,
                    },
                }, 429);
            }
        } catch (err) {
            // Fail-open: if Redis is down, allow the request
            log.warn('Rate limiting failed (fail-open)', { error: (err as Error).message });
        }

        await next();
    };
}
