/**
 * Structured Logger
 *
 * JSON-formatted logging with service prefixes, severity levels,
 * correlation IDs, and error serialization.
 */

import { randomUUID } from 'crypto';

// ============================================================================
// Types
// ============================================================================

type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'fatal';

interface LogEntry {
    timestamp: string;
    level: LogLevel;
    service: string;
    message: string;
    correlationId?: string;
    data?: Record<string, unknown>;
    error?: {
        name: string;
        message: string;
        stack?: string;
        code?: string;
    };
}

// ============================================================================
// Logger Factory
// ============================================================================

const LOG_LEVEL_PRIORITY: Record<LogLevel, number> = {
    debug: 0,
    info: 1,
    warn: 2,
    error: 3,
    fatal: 4,
};

const MIN_LEVEL = (process.env.LOG_LEVEL as LogLevel) || 'info';

function shouldLog(level: LogLevel): boolean {
    return LOG_LEVEL_PRIORITY[level] >= LOG_LEVEL_PRIORITY[MIN_LEVEL];
}

function serializeError(err: unknown): LogEntry['error'] | undefined {
    if (!err) return undefined;
    if (err instanceof Error) {
        return {
            name: err.name,
            message: err.message,
            stack: process.env.NODE_ENV === 'production' ? undefined : err.stack,
            code: (err as Error & { code?: string }).code,
        };
    }
    return { name: 'UnknownError', message: String(err) };
}

function emit(entry: LogEntry): void {
    const output = JSON.stringify(entry);
    switch (entry.level) {
        case 'error':
        case 'fatal':
            console.error(output);
            break;
        case 'warn':
            console.warn(output);
            break;
        case 'debug':
            console.debug(output);
            break;
        default:
            console.log(output);
    }
}

// ============================================================================
// Public API
// ============================================================================

export interface Logger {
    debug(message: string, data?: Record<string, unknown>): void;
    info(message: string, data?: Record<string, unknown>): void;
    warn(message: string, data?: Record<string, unknown>): void;
    error(message: string, err?: unknown, data?: Record<string, unknown>): void;
    fatal(message: string, err?: unknown, data?: Record<string, unknown>): void;
    child(service: string): Logger;
}

/**
 * Create a logger scoped to a service.
 *
 * @example
 * const log = createLogger('WebSearchWorker');
 * log.info('Processing job', { jobId: '123' });
 * log.error('Fan-out write failed', err, { target: 'neo4j' });
 */
export function createLogger(service: string, correlationId?: string): Logger {
    const cid = correlationId ?? randomUUID();

    function log(level: LogLevel, message: string, err?: unknown, data?: Record<string, unknown>) {
        if (!shouldLog(level)) return;
        emit({
            timestamp: new Date().toISOString(),
            level,
            service,
            message,
            correlationId: cid,
            data,
            error: serializeError(err),
        });
    }

    return {
        debug: (msg, data) => log('debug', msg, undefined, data),
        info: (msg, data) => log('info', msg, undefined, data),
        warn: (msg, data) => log('warn', msg, undefined, data),
        error: (msg, err, data) => log('error', msg, err, data),
        fatal: (msg, err, data) => log('fatal', msg, err, data),
        child: (childService) => createLogger(`${service}:${childService}`, cid),
    };
}
