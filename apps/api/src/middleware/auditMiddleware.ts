/**
 * Audit Middleware
 *
 * Hono middleware that automatically logs audit entries for all
 * mutating API requests (POST, PUT, PATCH, DELETE) that return
 * a successful response (2xx).
 *
 * Works by intercepting the response after the handler completes,
 * extracting entity information from the URL path and response body,
 * and writing an audit log entry in the background (fire-and-forget).
 */

import type { MiddlewareHandler } from 'hono';
import { logAudit, inferEntityType, inferAction, extractEntityId } from '../services/auditService';
import { createLogger } from '../lib/logger';

const log = createLogger('AuditMiddleware');

// Methods that indicate data mutation
const AUDITABLE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

// Paths to skip (health checks, reads, metrics, SSE)
const SKIP_PATTERNS = [
    /\/health/,
    /\/metrics/,
    /\/sse/,
    /\/search/,
    /\/export/,
    /\/enrich\//,       // Enrichment reads — the actual enrich action is logged by the consumer
    /\/stats/,
    /\/monitoring/,
    /\/graph\//,
    /\/audit/,          // Don't audit the audit endpoint itself
    /\/login/,
    /\/token/,
];

/**
 * Audit middleware for Hono.
 * Mount on the v1 router to auto-capture entity mutations.
 */
export function auditMiddleware(): MiddlewareHandler {
    return async (c, next) => {
        const method = c.req.method.toUpperCase();

        // Only audit mutating requests
        if (!AUDITABLE_METHODS.has(method)) {
            return next();
        }

        const path = c.req.path;

        // Skip non-entity paths
        if (SKIP_PATTERNS.some(p => p.test(path))) {
            return next();
        }

        // Run the actual handler
        await next();

        // Only audit successful responses
        const status = c.res.status;
        if (status < 200 || status >= 300) return;

        // Extract entity info (fire-and-forget — don't block the response)
        const entityType = inferEntityType(path);
        if (!entityType) return;

        const action = inferAction(method);

        // Try to read the response body for entity ID
        // Clone the response to avoid consuming it
        let responseBody: Record<string, unknown> | null = null;
        try {
            const cloned = c.res.clone();
            responseBody = await cloned.json() as Record<string, unknown>;
        } catch {
            // Response might not be JSON — that's fine
        }

        const entityId = extractEntityId(path, responseBody);
        if (!entityId) return;

        // Extract user context from the request
        const userId = (c.get('userId') as string) || null;
        const apiKeyId = (c.get('apiKeyId') as string) || null;
        const ip = c.req.header('x-forwarded-for') || c.req.header('x-real-ip') || 'unknown';
        const userAgent = c.req.header('user-agent') || 'unknown';

        // Fire-and-forget audit log
        logAudit({
            entityType,
            entityId,
            action,
            userId: userId || undefined,
            apiKeyId: apiKeyId || undefined,
            source: apiKeyId ? 'api' : userId ? 'manual' : 'system',
            changes: responseBody?.data
                ? { after: responseBody.data as Record<string, unknown> }
                : undefined,
            metadata: { ip, userAgent, requestId: c.get('requestId') as string },
        }).catch(() => {
            // Already handled inside logAudit
        });
    };
}
