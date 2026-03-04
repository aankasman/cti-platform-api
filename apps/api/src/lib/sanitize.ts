/**
 * SQL Sanitization Helpers
 *
 * Shared escape utilities for raw SQL queries used with sql.raw().
 * Prevents SQL injection in string interpolation.
 */

/**
 * Escape a string for safe inclusion in a SQL query.
 * Doubles single quotes and rejects null bytes.
 */
export function escSql(s: string): string {
    if (typeof s !== 'string') return '';
    return s.replace(/\0/g, '').replace(/'/g, "''");
}

/**
 * Parse and clamp an integer for LIMIT/OFFSET use.
 * Returns a safe non-negative integer, defaulting to `fallback`.
 */
export function escInt(n: unknown, fallback = 0, max = 100000): number {
    const parsed = typeof n === 'number' ? n : parseInt(String(n), 10);
    if (isNaN(parsed) || parsed < 0) return fallback;
    return Math.min(Math.floor(parsed), max);
}
