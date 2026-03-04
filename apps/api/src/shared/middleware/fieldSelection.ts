/**
 * Sparse Fieldsets Middleware
 *
 * REST equivalent of GraphQL field selection. Clients specify which
 * fields to return via the `fields` query parameter (comma-separated).
 *
 * Usage:
 *   GET /v1/iocs?fields=id,value,type,severity
 *   GET /v1/vulnerabilities?fields=cveId,cvssScore,severity
 *
 * Benefits:
 *   - Reduces payload size (especially for list endpoints)
 *   - Reduces DB query cost when used with column selection
 *   - Follows JSON:API sparse fieldsets convention
 */

import type { Context, Next } from 'hono';
import { createLogger } from '../lib/logger';

const log = createLogger('FieldSelection');

// ============================================================================
// Types
// ============================================================================

export interface FieldSelectionOptions {
    /** Allowed field names (whitelist). If empty, all fields are allowed. */
    allowedFields?: string[];
    /** Fields that are always included regardless of selection */
    requiredFields?: string[];
    /** Query parameter name (default: 'fields') */
    paramName?: string;
}

// ============================================================================
// Parse fields from query string
// ============================================================================

export function parseFieldSelection(
    query: Record<string, string | undefined>,
    options: FieldSelectionOptions = {},
): string[] | null {
    const paramName = options.paramName || 'fields';
    const raw = query[paramName];

    if (!raw) return null; // No field selection → return everything

    const requested = raw.split(',')
        .map(f => f.trim())
        .filter(f => f.length > 0);

    if (requested.length === 0) return null;

    // Validate against whitelist
    let fields = requested;
    if (options.allowedFields?.length) {
        fields = requested.filter(f => options.allowedFields!.includes(f));
    }

    // Always include required fields
    if (options.requiredFields?.length) {
        for (const rf of options.requiredFields) {
            if (!fields.includes(rf)) {
                fields.unshift(rf);
            }
        }
    }

    return fields.length > 0 ? fields : null;
}

// ============================================================================
// Filter object to selected fields
// ============================================================================

export function selectFields<T extends Record<string, unknown>>(
    obj: T,
    fields: string[] | null,
): Partial<T> {
    if (!fields) return obj;

    const result: Record<string, unknown> = {};
    for (const field of fields) {
        if (field in obj) {
            result[field] = obj[field];
        }
    }
    return result as Partial<T>;
}

/**
 * Filter an array of objects to selected fields
 */
export function selectFieldsArray<T extends Record<string, unknown>>(
    arr: T[],
    fields: string[] | null,
): Partial<T>[] {
    if (!fields) return arr;
    return arr.map(obj => selectFields(obj, fields));
}

// ============================================================================
// Hono Middleware
// ============================================================================

/**
 * Middleware that parses `?fields=a,b,c` and attaches selection to context.
 * Route handlers can then use `c.get('selectedFields')` for column selection.
 */
export function fieldSelection(options: FieldSelectionOptions = {}) {
    return async (c: Context, next: Next) => {
        const fields = parseFieldSelection(c.req.query() as Record<string, string>, options);

        // Store in context for route handlers
        c.set('selectedFields', fields);

        // Add header indicating which fields are returned
        if (fields) {
            c.header('X-Fields', fields.join(','));
        }

        await next();
    };
}

// ============================================================================
// Drizzle Column Selection Helper
// ============================================================================

/**
 * Build a Drizzle `columns` object from field selection.
 * Returns undefined if no field selection (= select all columns).
 *
 * Usage:
 *   const columns = buildDrizzleColumns(fields, iocs);
 *   const rows = columns
 *     ? await db.select(columns).from(iocs)
 *     : await db.select().from(iocs);
 */
export function buildDrizzleColumns(
    fields: string[] | null,
    table: Record<string, unknown>,
): Record<string, unknown> | undefined {
    if (!fields) return undefined;

    const columns: Record<string, unknown> = {};
    for (const field of fields) {
        // Convert camelCase to snake_case for Drizzle
        if (table[field]) {
            columns[field] = table[field];
        }
    }

    return Object.keys(columns).length > 0 ? columns : undefined;
}

// ============================================================================
// Standard field whitelists per entity type
// ============================================================================

export const IOC_FIELDS = [
    'id', 'type', 'value', 'source', 'threatType', 'confidence',
    'severity', 'firstSeen', 'lastSeen', 'tags', 'pulseId',
    'createdAt', 'updatedAt',
];

export const CVE_FIELDS = [
    'id', 'cveId', 'description', 'cvssScore', 'cvssVector',
    'severity', 'cweId', 'isExploited', 'exploitAddedDate', 'dueDate',
    'vendorProject', 'product', 'references', 'publishedDate',
    'lastModified', 'createdAt', 'updatedAt',
];

export const PULSE_FIELDS = [
    'id', 'otxId', 'name', 'description', 'author', 'tlp',
    'tags', 'adversary', 'targetedCountries', 'industries',
    'malwareFamilies', 'attackIds', 'indicatorCount', 'subscriberCount',
    'otxCreated', 'otxModified', 'createdAt',
];
