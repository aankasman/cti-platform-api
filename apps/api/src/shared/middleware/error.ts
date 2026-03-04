/**
 * Error Handler Middleware
 *
 * Catches all uncaught errors in Hono routes and returns structured JSON.
 * Recognizes AppError subclasses for correct status codes and machine-readable codes.
 */

import type { Context } from 'hono';
import { HTTPException } from 'hono/http-exception';
import { AppError } from '../lib/errors';
import { createLogger } from '../lib/logger';

const log = createLogger('ErrorHandler');

export function errorHandler(err: Error, c: Context) {
    // ── AppError hierarchy (our standardized errors) ──────────────────
    if (err instanceof AppError) {
        // Operational errors are expected (bad input, service down, etc.)
        // Non-operational errors are bugs — log at error level
        if (err.isOperational) {
            log.warn(err.message, { code: err.code, statusCode: err.statusCode, ...err.context });
        } else {
            log.error('Non-operational error', err, err.context);
        }

        return c.json({
            success: false,
            error: err.toJSON(),
        }, err.statusCode as 400 | 401 | 403 | 404 | 409 | 422 | 429 | 500);
    }

    // ── Zod validation errors (from direct Zod usage without AppError) ─
    if (err.name === 'ZodError') {
        log.warn('Zod validation error', { details: (err as unknown as { issues: unknown[] }).issues });
        return c.json({
            success: false,
            error: {
                code: 'VALIDATION_ERROR',
                message: 'Invalid request data',
                details: (err as unknown as { issues: unknown[] }).issues,
            },
        }, 400);
    }

    // ── Hono HTTPException (from requireAuth, requireRole, etc.) ──────
    if (err instanceof HTTPException) {
        const status = err.status as 400 | 401 | 403 | 404 | 429 | 500;
        if (status === 401 || status === 403) {
            log.warn(err.message, { statusCode: status });
        }
        return c.json({
            success: false,
            error: {
                code: status === 401 ? 'UNAUTHORIZED' : status === 403 ? 'FORBIDDEN' : 'HTTP_ERROR',
                message: err.message,
            },
        }, status);
    }

    // ── Unexpected errors (bugs) ──────────────────────────────────────
    log.error('Unhandled error', err);

    return c.json({
        success: false,
        error: {
            code: 'INTERNAL_ERROR',
            message: process.env.NODE_ENV === 'production'
                ? 'An internal error occurred'
                : err.message,
            ...(process.env.NODE_ENV !== 'production' && { stack: err.stack }),
        },
    }, 500);
}

export default errorHandler;
