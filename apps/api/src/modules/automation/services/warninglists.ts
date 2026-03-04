/**
 * Warninglists Service
 *
 * False-positive mitigation: check IOC values against curated lists
 * of known benign indicators (RFC1918, public DNS, CDNs, etc.).
 * Hot-path lookups are cached in Redis Sets for O(1) membership checks.
 */

import { warninglists, warninglistEntries } from '@rinjani/db/schema';
import { eq, sql } from '@rinjani/db';
import { getPostgres } from '../../../lib/db/clients';
import { connection } from '../../../services/redis';
import { createLogger } from '../../../lib/logger';

const log = createLogger('Warninglists');
const REDIS_PREFIX = 'rjn:wl:';

// ============================================================================
// CRUD Operations
// ============================================================================

export async function getWarninglists(enabledOnly = false) {
    const db = await getPostgres();

    const query = enabledOnly
        ? db.select().from(warninglists).where(eq(warninglists.enabled, true))
        : db.select().from(warninglists);

    const lists = await query.orderBy(warninglists.name);

    // Add entry counts
    const counts = await db.select({
        warninglistId: warninglistEntries.warninglistId,
        count: sql<number>`count(*)::int`,
    })
        .from(warninglistEntries)
        .groupBy(warninglistEntries.warninglistId);

    const countMap = Object.fromEntries(counts.map(c => [c.warninglistId, c.count]));

    return lists.map(wl => ({
        ...wl,
        entryCount: countMap[wl.id] || 0,
    }));
}

export async function getWarninglistById(id: string) {
    const db = await getPostgres();

    const [wl] = await db.select().from(warninglists).where(eq(warninglists.id, id));
    if (!wl) return null;

    const entries = await db.select()
        .from(warninglistEntries)
        .where(eq(warninglistEntries.warninglistId, id));

    return { ...wl, entries: entries.map(e => e.value) };
}

export async function createWarninglist(data: {
    name: string;
    description?: string;
    type: string;
    category?: string;
    source?: string;
    version?: string;
}) {
    const db = await getPostgres();

    const [wl] = await db.insert(warninglists).values({
        name: data.name,
        description: data.description,
        type: data.type,
        category: data.category || 'false_positive',
        source: data.source,
        version: data.version,
    }).returning();

    log.info('Warninglist created', { id: wl.id, name: wl.name });
    return wl;
}

export async function updateWarninglist(id: string, data: Partial<{
    name: string;
    description: string;
    type: string;
    category: string;
    enabled: boolean;
    version: string;
}>) {
    const db = await getPostgres();

    const [wl] = await db.update(warninglists)
        .set({ ...data, updatedAt: new Date() })
        .where(eq(warninglists.id, id))
        .returning();

    // Invalidate Redis cache for this list
    if (wl) await invalidateRedisCache(id);

    return wl || null;
}

export async function deleteWarninglist(id: string) {
    const db = await getPostgres();
    await db.delete(warninglists).where(eq(warninglists.id, id));
    await invalidateRedisCache(id);
    log.info('Warninglist deleted', { id });
}

// ============================================================================
// Entry Management
// ============================================================================

export async function addEntries(warninglistId: string, values: string[]) {
    if (values.length === 0) return 0;

    const db = await getPostgres();

    const rows = values.map(value => ({
        warninglistId,
        value: value.trim().toLowerCase(),
    }));

    await db.insert(warninglistEntries).values(rows).onConflictDoNothing();
    await invalidateRedisCache(warninglistId);

    return values.length;
}

export async function removeEntries(warninglistId: string, values: string[]) {
    if (values.length === 0) return 0;

    const db = await getPostgres();
    let removed = 0;

    for (const value of values) {
        const result = await db.delete(warninglistEntries)
            .where(
                sql`${warninglistEntries.warninglistId} = ${warninglistId} AND ${warninglistEntries.value} = ${value.trim().toLowerCase()}`
            );
        removed++;
    }

    await invalidateRedisCache(warninglistId);
    return removed;
}

// ============================================================================
// IOC Checking (hot path — Redis-cached)
// ============================================================================

export interface WarninglistMatch {
    warninglistId: string;
    warninglistName: string;
    matchType: string; // exact, cidr, regex
    category: string;
}

/**
 * Check a value against all enabled warninglists.
 * Uses Redis Sets for O(1) string/hostname lookups.
 * Falls back to DB for CIDR and regex matching.
 */
export async function checkAgainstWarninglists(
    value: string,
    iocType?: string
): Promise<WarninglistMatch[]> {
    const db = await getPostgres();
    const matches: WarninglistMatch[] = [];
    const normalizedValue = value.trim().toLowerCase();

    // Get all enabled warninglists
    const lists = await db.select()
        .from(warninglists)
        .where(eq(warninglists.enabled, true));

    for (const wl of lists) {
        let matched = false;
        let matchType = 'exact';

        switch (wl.type) {
            case 'string':
            case 'hostname': {
                // O(1) Redis Set lookup
                matched = await checkRedisSet(wl.id, normalizedValue);
                matchType = 'exact';
                break;
            }

            case 'cidr': {
                if (iocType === 'ip' || isIPv4(normalizedValue)) {
                    // Check if IP falls within any CIDR range in this list
                    matched = await checkCIDRMatch(wl.id, normalizedValue);
                    matchType = 'cidr';
                }
                break;
            }

            case 'regex': {
                matched = await checkRegexMatch(wl.id, normalizedValue);
                matchType = 'regex';
                break;
            }
        }

        if (matched) {
            matches.push({
                warninglistId: wl.id,
                warninglistName: wl.name,
                matchType,
                category: wl.category,
            });
        }
    }

    return matches;
}

// ============================================================================
// Redis Cache (for string/hostname lookups)
// ============================================================================

async function checkRedisSet(warninglistId: string, value: string): Promise<boolean> {
    try {
        const key = `${REDIS_PREFIX}${warninglistId}`;

        // Lazy-load the set if not cached
        const exists = await connection.exists(key);
        if (!exists) {
            await loadWarninglistToRedis(warninglistId);
        }

        return !!(await connection.sismember(key, value));
    } catch (err) {
        log.warn('Redis warninglist check failed, falling back to DB', { error: (err as Error).message });
        return await checkDBExact(warninglistId, value);
    }
}

async function loadWarninglistToRedis(warninglistId: string) {
    const db = await getPostgres();

    const entries = await db.select({ value: warninglistEntries.value })
        .from(warninglistEntries)
        .where(eq(warninglistEntries.warninglistId, warninglistId));

    if (entries.length === 0) return;

    const key = `${REDIS_PREFIX}${warninglistId}`;
    const pipeline = connection.pipeline();

    // Add entries in batches of 1000
    for (let i = 0; i < entries.length; i += 1000) {
        const batch = entries.slice(i, i + 1000).map(e => e.value);
        pipeline.sadd(key, ...batch);
    }

    pipeline.expire(key, 3600); // 1 hour TTL
    await pipeline.exec();

    log.debug('Warninglist loaded to Redis', { warninglistId, entries: entries.length });
}

async function invalidateRedisCache(warninglistId: string) {
    try {
        await connection.del(`${REDIS_PREFIX}${warninglistId}`);
    } catch (err) {
        log.warn('Failed to invalidate warninglist Redis cache', { error: (err as Error).message });
    }
}

// ============================================================================
// Matching Helpers
// ============================================================================

async function checkDBExact(warninglistId: string, value: string): Promise<boolean> {
    const db = await getPostgres();

    const [match] = await db.select({ id: warninglistEntries.id })
        .from(warninglistEntries)
        .where(
            sql`${warninglistEntries.warninglistId} = ${warninglistId} AND ${warninglistEntries.value} = ${value}`
        )
        .limit(1);

    return !!match;
}

async function checkCIDRMatch(warninglistId: string, ip: string): Promise<boolean> {
    const db = await getPostgres();

    // Use PostgreSQL's inet operators for CIDR matching
    const [match] = await db.select({ id: warninglistEntries.id })
        .from(warninglistEntries)
        .where(
            sql`${warninglistEntries.warninglistId} = ${warninglistId} AND ${ip}::inet <<= ${warninglistEntries.value}::inet`
        )
        .limit(1);

    return !!match;
}

async function checkRegexMatch(warninglistId: string, value: string): Promise<boolean> {
    const db = await getPostgres();

    const [match] = await db.select({ id: warninglistEntries.id })
        .from(warninglistEntries)
        .where(
            sql`${warninglistEntries.warninglistId} = ${warninglistId} AND ${value} ~ ${warninglistEntries.value}`
        )
        .limit(1);

    return !!match;
}

function isIPv4(value: string): boolean {
    return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value);
}

// ============================================================================
// Seed Default Warninglists
// ============================================================================

export async function seedDefaults() {
    const defaults = [
        {
            name: 'RFC1918 Private Networks',
            description: 'Private IPv4 address ranges (RFC1918)',
            type: 'cidr',
            category: 'false_positive',
            source: 'IETF RFC1918',
            entries: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
        },
        {
            name: 'RFC5735 Special-Use IPs',
            description: 'Special-use IPv4 addresses',
            type: 'cidr',
            category: 'false_positive',
            source: 'IETF RFC5735',
            entries: ['0.0.0.0/8', '127.0.0.0/8', '169.254.0.0/16', '224.0.0.0/4', '240.0.0.0/4', '255.255.255.255/32'],
        },
        {
            name: 'Public DNS Resolvers',
            description: 'Well-known public DNS resolver IPs',
            type: 'string',
            category: 'known_benign',
            source: 'community',
            entries: [
                '8.8.8.8', '8.8.4.4', // Google
                '1.1.1.1', '1.0.0.1', // Cloudflare
                '9.9.9.9', '149.112.112.112', // Quad9
                '208.67.222.222', '208.67.220.220', // OpenDNS
                '64.6.64.6', '64.6.65.6', // Verisign
            ],
        },
        {
            name: 'Common Empty/Test Values',
            description: 'Values commonly seen in test data or empty fields',
            type: 'string',
            category: 'false_positive',
            source: 'community',
            entries: [
                'n/a', 'none', 'null', 'unknown', 'test', 'example',
                'localhost', '0.0.0.0', '127.0.0.1', '::1',
                'example.com', 'example.org', 'example.net',
                'test.com', 'invalid',
            ],
        },
        {
            name: 'Major CDN/Cloud Provider Domains',
            description: 'Domains belonging to major cloud and CDN providers',
            type: 'hostname',
            category: 'known_benign',
            source: 'community',
            entries: [
                'cloudflare.com', 'cloudfront.net', 'amazonaws.com',
                'akamai.net', 'akamaiedge.net', 'fastly.net',
                'googleapis.com', 'google.com', 'gstatic.com',
                'microsoft.com', 'azure.com', 'azureedge.net',
                'apple.com', 'icloud.com',
                'github.com', 'githubusercontent.com',
            ],
        },
    ];

    let totalLists = 0;
    let totalEntries = 0;

    for (const def of defaults) {
        const existing = await getWarninglists();
        if (existing.find(wl => wl.name === def.name)) {
            log.debug('Warninglist already exists, skipping', { name: def.name });
            continue;
        }

        const wl = await createWarninglist({
            name: def.name,
            description: def.description,
            type: def.type,
            category: def.category,
            source: def.source,
            version: '1.0',
        });

        await addEntries(wl.id, def.entries);

        totalLists++;
        totalEntries += def.entries.length;
    }

    log.info('Default warninglists seeded', { lists: totalLists, entries: totalEntries });
    return { lists: totalLists, entries: totalEntries };
}
