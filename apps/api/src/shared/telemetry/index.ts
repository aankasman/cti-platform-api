/**
 * OpenTelemetry Configuration Stub
 * 
 * Provides telemetry interface without requiring OpenTelemetry packages.
 * Install packages to enable real telemetry:
 * 
 * pnpm add @opentelemetry/sdk-node @opentelemetry/api @opentelemetry/resources \
 *   @opentelemetry/auto-instrumentations-node @opentelemetry/exporter-trace-otlp-http \
 *   @opentelemetry/exporter-metrics-otlp-http @opentelemetry/sdk-metrics \
 *   @opentelemetry/semantic-conventions
 */

import type { Context, Next } from 'hono';
import { createLogger } from '../lib/logger';

const log = createLogger('Telemetry');

// ============================================================================
// Configuration
// ============================================================================

const OTEL_ENABLED = process.env.OTEL_ENABLED === 'true';
const OTEL_ENDPOINT = process.env.OTEL_ENDPOINT || 'http://localhost:4318';
const SERVICE_NAME = process.env.SERVICE_NAME || 'v3-api';

// ============================================================================
// Stub Implementation (when packages not installed)
// ============================================================================

export async function initTelemetry(): Promise<void> {
    if (!OTEL_ENABLED) {
        log.info('OpenTelemetry is disabled (OTEL_ENABLED=false)');
        return;
    }

    log.info('OpenTelemetry enabled but packages not installed. Install: pnpm add @opentelemetry/sdk-node @opentelemetry/api');
}

export async function shutdownTelemetry(): Promise<void> {
    log.info('Shutdown (no-op in stub mode)');
}

/**
 * Create a traced span (stub - just executes function)
 */
export async function createSpan<T>(name: string, fn: () => Promise<T>): Promise<T> {
    const startTime = Date.now();
    try {
        return await fn();
    } finally {
        const duration = Date.now() - startTime;
        if (OTEL_ENABLED) {
            console.debug(`[Telemetry] Span ${name}: ${duration}ms`);
        }
    }
}

/**
 * Record an HTTP request metric (stub)
 */
export function recordRequest(method: string, path: string, status: number, durationMs: number): void {
    if (OTEL_ENABLED) {
        console.debug(`[Telemetry] HTTP ${method} ${path} -> ${status} (${durationMs}ms)`);
    }
}

/**
 * Record a feed sync metric (stub)
 */
export function recordFeedSync(feed: string, success: boolean, durationMs: number, itemCount: number): void {
    if (OTEL_ENABLED) {
        console.debug(`[Telemetry] Feed ${feed}: ${itemCount} items, ${durationMs}ms, success=${success}`);
    }
}

/**
 * Record a database query metric (stub)
 */
export function recordDbQuery(operation: string, table: string, durationMs: number): void {
    if (OTEL_ENABLED) {
        console.debug(`[Telemetry] DB ${operation} ${table}: ${durationMs}ms`);
    }
}

/**
 * Track WebSocket connections (stub)
 */
export function trackConnection(delta: 1 | -1): void {
    if (OTEL_ENABLED) {
        console.debug(`[Telemetry] Connection ${delta > 0 ? 'added' : 'removed'}`);
    }
}

/**
 * Telemetry middleware for Hono (stub)
 */
export async function telemetryMiddleware(c: Context, next: Next): Promise<void> {
    const startTime = Date.now();
    const method = c.req.method;
    const path = new URL(c.req.url).pathname;

    await next();

    const durationMs = Date.now() - startTime;
    const status = c.res.status;

    recordRequest(method, path, status, durationMs);
}

// ============================================================================
// Export
// ============================================================================

export default {
    init: initTelemetry,
    shutdown: shutdownTelemetry,
    createSpan,
    recordRequest,
    recordFeedSync,
    recordDbQuery,
    trackConnection,
    middleware: telemetryMiddleware,
};
