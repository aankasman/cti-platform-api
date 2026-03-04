/**
 * Database Client
 * 
 * PostgreSQL and OpenSearch clients for the v3 backend.
 */

// Load environment variables from project root
import { config } from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '../../..');
config({ path: join(projectRoot, '.env') });

import { drizzle } from 'drizzle-orm/postgres-js';
import { sql } from 'drizzle-orm';
import postgres from 'postgres';
import { Client as OpenSearchClient } from '@opensearch-project/opensearch';
import * as schema from './schema';

// ============================================================================
// PostgreSQL Client (Drizzle)
// ============================================================================

const connectionString = process.env.DATABASE_URL || 'postgresql://localhost:6432/rinjani_v3';
console.log('[DB] Using DATABASE_URL:', connectionString.replace(/:[^:@]+@/, ':****@')); // Hide password

const queryClient = postgres(connectionString, {
    max: 25,                // Sized for PgBouncer default_pool_size=20
    idle_timeout: 20,
    connect_timeout: 10,
    prepare: false,         // REQUIRED for PgBouncer transaction pooling
});

export const db = drizzle(queryClient, { schema });

// ============================================================================
// OpenSearch Client
// ============================================================================

const opensearchUrl = process.env.OPENSEARCH_URL || 'http://localhost:9200';

export const opensearch = new OpenSearchClient({
    node: opensearchUrl,
    auth: process.env.OPENSEARCH_AUTH ? {
        username: process.env.OPENSEARCH_USERNAME || 'admin',
        password: process.env.OPENSEARCH_PASSWORD || 'admin',
    } : undefined,
});

// ============================================================================
// Connection Health Checks
// ============================================================================

export async function checkPostgresConnection(): Promise<boolean> {
    try {
        await queryClient`SELECT 1`;
        return true;
    } catch (error) {
        console.error('[DB] PostgreSQL connection failed:', error);
        return false;
    }
}

export async function checkOpenSearchConnection(): Promise<boolean> {
    try {
        const health = await opensearch.cluster.health();
        return health.body.status !== 'red';
    } catch (error) {
        console.error('[DB] OpenSearch connection failed:', error);
        return false;
    }
}

export async function closeConnections(): Promise<void> {
    await queryClient.end();
    await opensearch.close();
}

// Export types
export type Database = typeof db;
export type { schema };

/**
 * Type for raw SQL query results from db.execute(sql.raw(...)).
 * The postgres-js driver returns an array-like RowList with a `.rows` property at runtime.
 */
export interface RawQueryResult<T extends Record<string, unknown> = Record<string, unknown>> {
    rows: T[];
}

/**
 * Execute a parameterized SQL query and return typed results.
 * Uses Drizzle's `sql` tagged template for safe parameterized queries.
 *
 * @example
 *   // Parameterized (SAFE — preferred)
 *   const result = await rawQuery<{ id: string }>(sql`SELECT * FROM users WHERE id = ${userId}`);
 *
 *   // Static query (only for trusted, non-user-input queries)
 *   const result = await rawQuery<{ count: number }>(sql`SELECT count(*) FROM users`);
 */
export async function rawQuery<T extends Record<string, unknown> = Record<string, unknown>>(
    query: ReturnType<typeof sql> | string,
): Promise<RawQueryResult<T>> {
    // Accept both sql tagged template and legacy string (for backwards compat)
    const sqlQuery = typeof query === 'string' ? sql.raw(query) : query;
    const result = await db.execute(sqlQuery);
    // postgres-js returns an array-like, pg returns { rows: [...] }
    const rows = Array.isArray(result)
        ? result as unknown as T[]
        : ((result as unknown as { rows?: T[] }).rows ?? []);
    return { rows };
}

// Re-export commonly used drizzle-orm functions
export { sql, eq, and, or, desc, asc, count, like, ilike, gte, lte, ne, inArray, notInArray, isNotNull, isNull } from 'drizzle-orm';
export type { SQL } from 'drizzle-orm';
