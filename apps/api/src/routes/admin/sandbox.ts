/**
 * API Sandbox Routes
 *
 * Provides endpoints for testing connectivity to external feeds and arbitrary endpoints.
 * Rate-limited to prevent abuse.
 *
 * Mounts at: /admin/sandbox/*
 */

import { Hono } from 'hono';
import { requireAuth, requireRole } from '../../middleware/auth';
import { SandboxTestFeedSchema, SandboxTestEndpointSchema } from '../../lib/schemas';
import { AppError } from '../../lib/errors';

const router = new Hono();

// Simple in-memory rate limiter: 5 calls/minute per user
const rateLimitMap = new Map<string, number[]>();
const RATE_LIMIT = 5;
const RATE_WINDOW_MS = 60_000;

function checkRateLimit(userId: string): boolean {
    const now = Date.now();
    const timestamps = (rateLimitMap.get(userId) || []).filter(t => now - t < RATE_WINDOW_MS);
    if (timestamps.length >= RATE_LIMIT) return false;
    timestamps.push(now);
    rateLimitMap.set(userId, timestamps);
    return true;
}

// ============================================================================
// Test Feed Connectivity
// ============================================================================

router.post('/sandbox/test-feed', requireAuth, requireRole('admin'), async (c) => {
    const user = c.get('user');
    if (!checkRateLimit(user.id)) {
        throw new AppError('Rate limit exceeded (5 requests/minute)', { statusCode: 429, code: 'RATE_LIMIT_EXCEEDED' });
    }

    const body = SandboxTestFeedSchema.parse(await c.req.json());

    const method = body.method.toUpperCase();

    const targetUrl = new URL(body.url);

    // Support query-parameter auth (e.g. Shodan ?key=VALUE)
    if (body.authType === 'query' && body.authParam && body.authValue) {
        targetUrl.searchParams.set(body.authParam, body.authValue);
    }

    const headers: Record<string, string> = {
        'User-Agent': 'RinjaniAnalytics/3.0 Sandbox',
        'Accept': 'application/json, text/plain, */*',
    };

    if (body.authType !== 'query' && body.authHeader && body.authValue) {
        headers[body.authHeader] = body.authValue;
    }

    const start = performance.now();

    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 10_000);

        const response = await fetch(targetUrl.toString(), {
            method,
            headers,
            signal: controller.signal,
        });

        clearTimeout(timeout);

        const latencyMs = Math.round(performance.now() - start);
        let responseSnippet = '';

        let fullSize = 0;
        let truncated = false;

        try {
            const text = await response.text();
            fullSize = text.length;
            // Try to pretty-print JSON for the frontend viewer
            try {
                const parsed = JSON.parse(text);
                const pretty = JSON.stringify(parsed, null, 2);
                truncated = pretty.length > 100_000;
                responseSnippet = truncated ? pretty.substring(0, 100_000) : pretty;
            } catch {
                truncated = text.length > 100_000;
                responseSnippet = truncated ? text.substring(0, 100_000) : text;
            }
        } catch {
            responseSnippet = '(unable to read response body)';
        }

        return c.json({
            success: true,
            data: {
                success: response.ok,
                status: response.status,
                statusText: response.statusText,
                latencyMs,
                message: response.ok ? 'Connection successful' : `HTTP ${response.status} ${response.statusText}`,
                responseSnippet,
                truncated,
                fullSize,
                headers: {
                    'content-type': response.headers.get('content-type'),
                    'x-ratelimit-remaining': response.headers.get('x-ratelimit-remaining'),
                },
            },
        });
    } catch (err) {
        const latencyMs = Math.round(performance.now() - start);
        const message = (err as Error).name === 'AbortError'
            ? 'Request timed out (10s)'
            : (err as Error).message || 'Unknown error';

        return c.json({
            success: true,
            data: {
                success: false,
                status: 0,
                latencyMs,
                message,
                responseSnippet: '',
            },
        });
    }
});

// ============================================================================
// Test Arbitrary Endpoint
// ============================================================================

router.post('/sandbox/test-endpoint', requireAuth, requireRole('admin'), async (c) => {
    const user = c.get('user');
    if (!checkRateLimit(user.id)) {
        throw new AppError('Rate limit exceeded (5 requests/minute)', { statusCode: 429, code: 'RATE_LIMIT_EXCEEDED' });
    }

    const body = SandboxTestEndpointSchema.parse(await c.req.json());

    const method = body.method.toUpperCase();

    const timeoutMs = body.timeoutMs;

    const reqHeaders: Record<string, string> = {
        'User-Agent': 'RinjaniAnalytics/3.0 Sandbox',
        ...(body.headers || {}),
    };

    const fetchOptions: RequestInit = {
        method,
        headers: reqHeaders,
    };

    if (body.body && !['GET', 'HEAD'].includes(method)) {
        fetchOptions.body = JSON.stringify(body.body);
        if (!reqHeaders['Content-Type'] && !reqHeaders['content-type']) {
            reqHeaders['Content-Type'] = 'application/json';
        }
    }

    const start = performance.now();

    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), timeoutMs);
        fetchOptions.signal = controller.signal;

        const response = await fetch(body.url, fetchOptions);
        clearTimeout(timeout);

        const latencyMs = Math.round(performance.now() - start);
        let responseSnippet = '';

        let fullSize = 0;
        let truncated = false;

        try {
            const text = await response.text();
            fullSize = text.length;
            // Try to pretty-print JSON for the frontend viewer
            try {
                const parsed = JSON.parse(text);
                const pretty = JSON.stringify(parsed, null, 2);
                truncated = pretty.length > 100_000;
                responseSnippet = truncated ? pretty.substring(0, 100_000) : pretty;
            } catch {
                truncated = text.length > 100_000;
                responseSnippet = truncated ? text.substring(0, 100_000) : text;
            }
        } catch {
            responseSnippet = '(unable to read response body)';
        }

        return c.json({
            success: true,
            data: {
                success: response.ok,
                status: response.status,
                statusText: response.statusText,
                latencyMs,
                message: response.ok
                    ? `${method} ${response.status} OK`
                    : `${method} ${response.status} ${response.statusText}`,
                responseSnippet,
                truncated,
                fullSize,
                headers: {
                    'content-type': response.headers.get('content-type'),
                    'x-ratelimit-remaining': response.headers.get('x-ratelimit-remaining'),
                    'x-ratelimit-limit': response.headers.get('x-ratelimit-limit'),
                },
            },
        });
    } catch (err) {
        const latencyMs = Math.round(performance.now() - start);
        const message = (err as Error).name === 'AbortError'
            ? `Request timed out (${timeoutMs / 1000}s)`
            : (err as Error).message || 'Unknown error';

        return c.json({
            success: true,
            data: {
                success: false,
                status: 0,
                latencyMs,
                message,
                responseSnippet: '',
            },
        });
    }
});

export default router;
