/**
 * Centralized Database Client Module
 *
 * Unified singleton exports for all 4 database clients.
 * Uses globalThis caching for hot-reload safety in dev mode.
 * Provides graceful shutdown and unified health checks.
 *
 * Usage:
 *   import { getPostgres, getRedis, getNeo4j, getOpenSearch, shutdownAll } from '@/lib/db/clients';
 */

import { createLogger } from '../logger';

const log = createLogger('DBClients');

// ============================================================================
// globalThis cache key (survives tsx/nodemon hot reloads)
// ============================================================================

const GLOBAL_KEY = '__rinjani_db_clients__' as const;

interface ClientCache {
    postgres?: typeof import('@rinjani/db')['db'];
    redis?: import('ioredis').default;
    neo4jDriver?: import('neo4j-driver').Driver;
    opensearch?: import('@opensearch-project/opensearch').Client;
}

function getCache(): ClientCache {
    const g = globalThis as typeof globalThis & Record<string, unknown>;
    if (!g[GLOBAL_KEY]) g[GLOBAL_KEY] = {};
    return g[GLOBAL_KEY] as ClientCache;
}

// ============================================================================
// PostgreSQL (Drizzle ORM) — from packages/db
// ============================================================================

/**
 * Returns the Drizzle Postgres client.
 * Singleton managed by `@rinjani/db` package; cached here for hot-reload safety.
 */
export async function getPostgres() {
    const cache = getCache();
    if (!cache.postgres) {
        const { db } = await import('@rinjani/db');
        cache.postgres = db;
        log.info('PostgreSQL client initialized (via @rinjani/db)');
    }
    return cache.postgres;
}

// ============================================================================
// Redis (ioredis) — from services/redis.ts
// ============================================================================

/**
 * Returns the shared Redis connection.
 * Configured with `maxRetriesPerRequest: null` for BullMQ compatibility.
 */
export async function getRedis() {
    const cache = getCache();
    if (!cache.redis) {
        const { connection } = await import('../../services/redis.js');
        cache.redis = connection;
        log.info('Redis client initialized');
    }
    return cache.redis;
}

// ============================================================================
// Neo4j — from services/neo4j.ts
// ============================================================================

/**
 * Returns the Neo4j driver singleton.
 */
export async function getNeo4j() {
    const cache = getCache();
    if (!cache.neo4jDriver) {
        const { getNeo4jDriver } = await import('../../services/neo4j.js');
        cache.neo4jDriver = getNeo4jDriver();
        log.info('Neo4j driver initialized');
    }
    return cache.neo4jDriver;
}

// ============================================================================
// OpenSearch — from services/opensearch.ts
// ============================================================================

/**
 * Returns the OpenSearch client singleton.
 */
export async function getOpenSearch() {
    const cache = getCache();
    if (!cache.opensearch) {
        const { getOpenSearchClient } = await import('../../services/opensearch.js');
        cache.opensearch = getOpenSearchClient();
        log.info('OpenSearch client initialized');
    }
    return cache.opensearch;
}

// ============================================================================
// Graceful Shutdown
// ============================================================================

/**
 * Close all database connections gracefully.
 * Call this on SIGTERM / SIGINT.
 */
export async function shutdownAll(): Promise<void> {
    log.info('Shutting down all database connections...');

    const cache = getCache();
    const errors: Error[] = [];

    // Redis
    if (cache.redis) {
        try {
            cache.redis.disconnect();
            log.info('Redis disconnected');
        } catch (e) {
            errors.push(e as Error);
        }
    }

    // Neo4j
    if (cache.neo4jDriver) {
        try {
            await cache.neo4jDriver.close();
            log.info('Neo4j driver closed');
        } catch (e) {
            errors.push(e as Error);
        }
    }

    // OpenSearch
    if (cache.opensearch) {
        try {
            await cache.opensearch.close();
            log.info('OpenSearch client closed');
        } catch (e) {
            errors.push(e as Error);
        }
    }

    // Postgres (pool close)
    try {
        const { closeConnections } = await import('@rinjani/db');
        await closeConnections();
        log.info('PostgreSQL pool closed');
    } catch (e) {
        errors.push(e as Error);
    }

    // Clear cache
    (globalThis as typeof globalThis & Record<string, unknown>)[GLOBAL_KEY] = {};

    if (errors.length > 0) {
        log.error('Shutdown completed with errors', errors[0], { errorCount: errors.length });
    } else {
        log.info('All database connections closed cleanly');
    }
}

// ============================================================================
// Unified Health Check
// ============================================================================

export interface HealthStatus {
    postgres: boolean;
    redis: boolean;
    neo4j: boolean;
    opensearch: boolean;
    healthy: boolean;
}

/**
 * Race a promise against a timeout.
 */
function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
    return Promise.race([
        promise,
        new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error(`${label} health check timed out after ${ms}ms`)), ms),
        ),
    ]);
}

/**
 * Check connectivity to all 4 databases.
 * Each check has a 5-second timeout and logs specific errors on failure.
 */
export async function healthCheckAll(): Promise<HealthStatus> {
    const TIMEOUT = 5_000;
    const labels = ['Postgres', 'Redis', 'Neo4j', 'OpenSearch'];

    const results = await Promise.allSettled([
        // Postgres
        withTimeout((async () => {
            const { checkPostgresConnection } = await import('@rinjani/db');
            return checkPostgresConnection();
        })(), TIMEOUT, 'Postgres'),
        // Redis
        withTimeout((async () => {
            const redis = await getRedis();
            const pong = await redis.ping();
            return pong === 'PONG';
        })(), TIMEOUT, 'Redis'),
        // Neo4j
        withTimeout((async () => {
            const { checkNeo4jHealth } = await import('../../services/neo4j.js');
            const h = await checkNeo4jHealth();
            return h.connected;
        })(), TIMEOUT, 'Neo4j'),
        // OpenSearch
        withTimeout((async () => {
            const { checkHealth } = await import('../../services/opensearch.js');
            const h = await checkHealth();
            return h.status !== 'unavailable';
        })(), TIMEOUT, 'OpenSearch'),
    ]);

    // Log individual failures for diagnostics
    results.forEach((r, i) => {
        if (r.status === 'rejected') {
            log.error(`${labels[i]} health check failed`, r.reason instanceof Error ? r.reason : new Error(String(r.reason)));
        }
    });

    const [pg, redis, neo4j, os] = results.map((r) =>
        r.status === 'fulfilled' ? r.value : false,
    );

    const status: HealthStatus = {
        postgres: !!pg,
        redis: !!redis,
        neo4j: !!neo4j,
        opensearch: !!os,
        healthy: !!pg && !!redis && !!neo4j && !!os,
    };

    log.info('Health check completed', status as unknown as Record<string, unknown>);
    return status;
}
