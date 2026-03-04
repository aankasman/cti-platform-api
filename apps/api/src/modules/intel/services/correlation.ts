/**
 * Correlation Engine Service
 *
 * Discovers relationships between IOCs:
 *   - CIDR matching: IPs in the same /24 subnet
 *   - Domain clustering: Same registrable domain (TLD+1)
 *   - Campaign attribution: IOCs sharing the same pulse/campaign
 *   - Temporal proximity: IOCs first seen within 24h of each other from same source
 *
 * Results are stored as correlation edges and surfaced via the API.
 */

import { iocs } from '@rinjani/db/schema';
import { and, eq, gte, isNotNull, lte, ne, sql } from '@rinjani/db';
import { getPostgres } from '../../../lib/db/clients';
import { createLogger } from '../../../lib/logger';

const log = createLogger('Correlation');

// ============================================================================
// Types
// ============================================================================

export interface CorrelationResult {
    sourceId: string;
    targetId: string;
    targetValue: string;
    targetType: string;
    correlationType: 'cidr' | 'domain' | 'campaign' | 'temporal';
    confidence: number;
    details: string;
}

// ============================================================================
// Correlate a Single IOC
// ============================================================================

export async function correlateIOC(iocId: string): Promise<CorrelationResult[]> {
    const db = await getPostgres();

    // Get the source IOC
    const [ioc] = await db.select().from(iocs).where(eq(iocs.id, iocId));
    if (!ioc) {
        throw new Error(`IOC ${iocId} not found`);
    }

    const results: CorrelationResult[] = [];

    // Run all correlation strategies in parallel
    const strategies = await Promise.allSettled([
        ioc.type === 'ip' ? findCIDRCorrelations(ioc) : Promise.resolve([]),
        ['domain', 'hostname', 'url'].includes(ioc.type) ? findDomainCorrelations(ioc) : Promise.resolve([]),
        ioc.pulseId ? findCampaignCorrelations(ioc) : Promise.resolve([]),
        findTemporalCorrelations(ioc),
    ]);

    for (const result of strategies) {
        if (result.status === 'fulfilled') {
            results.push(...result.value);
        } else {
            log.warn('Correlation strategy failed', { error: result.reason?.message });
        }
    }

    // Deduplicate by target ID
    const seen = new Set<string>();
    const deduplicated = results.filter(r => {
        if (seen.has(r.targetId)) return false;
        seen.add(r.targetId);
        return true;
    });

    log.info('IOC correlated', {
        iocId,
        value: ioc.value,
        correlations: deduplicated.length,
    });

    return deduplicated;
}

// ============================================================================
// CIDR Correlation: IPs in the same /24 subnet
// ============================================================================

async function findCIDRCorrelations(ioc: typeof iocs.$inferSelect): Promise<CorrelationResult[]> {
    const db = await getPostgres();

    // Find other IPs in the same /24
    const related = await db.select()
        .from(iocs)
        .where(
            and(
                ne(iocs.id, ioc.id),
                eq(iocs.type, 'ip'),
                sql`${iocs.value}::inet <<= network(${ioc.value}::inet/24)`
            )
        )
        .limit(100);

    return related.map(r => ({
        sourceId: ioc.id,
        targetId: r.id,
        targetValue: r.value,
        targetType: r.type,
        correlationType: 'cidr' as const,
        confidence: 60,
        details: `Same /24 subnet as ${ioc.value}`,
    }));
}

// ============================================================================
// Domain Clustering: Same registrable domain (TLD+1)
// ============================================================================

async function findDomainCorrelations(ioc: typeof iocs.$inferSelect): Promise<CorrelationResult[]> {
    const db = await getPostgres();

    // Extract the registrable domain (last two parts)
    const domainValue = ioc.type === 'url' ? extractDomainFromURL(ioc.value) : ioc.value;
    if (!domainValue) return [];

    const baseDomain = getBaseDomain(domainValue);
    if (!baseDomain) return [];

    // Find IOCs with the same base domain
    const related = await db.select()
        .from(iocs)
        .where(
            and(
                ne(iocs.id, ioc.id),
                sql`${iocs.type} IN ('domain', 'hostname', 'url')`,
                sql`${iocs.value} LIKE ${'%' + baseDomain}`
            )
        )
        .limit(100);

    return related.map(r => ({
        sourceId: ioc.id,
        targetId: r.id,
        targetValue: r.value,
        targetType: r.type,
        correlationType: 'domain' as const,
        confidence: 70,
        details: `Shares base domain: ${baseDomain}`,
    }));
}

// ============================================================================
// Campaign Attribution: IOCs from the same pulse/campaign
// ============================================================================

async function findCampaignCorrelations(ioc: typeof iocs.$inferSelect): Promise<CorrelationResult[]> {
    const db = await getPostgres();

    if (!ioc.pulseId) return [];

    const related = await db.select()
        .from(iocs)
        .where(
            and(
                ne(iocs.id, ioc.id),
                eq(iocs.pulseId, ioc.pulseId),
            )
        )
        .limit(200);

    return related.map(r => ({
        sourceId: ioc.id,
        targetId: r.id,
        targetValue: r.value,
        targetType: r.type,
        correlationType: 'campaign' as const,
        confidence: 80,
        details: `Same campaign/pulse: ${ioc.pulseId}`,
    }));
}

// ============================================================================
// Temporal Proximity: IOCs first seen within 24h from the same source
// ============================================================================

async function findTemporalCorrelations(ioc: typeof iocs.$inferSelect): Promise<CorrelationResult[]> {
    const db = await getPostgres();

    if (!ioc.firstSeen) return [];

    const windowStart = new Date(ioc.firstSeen.getTime() - 24 * 60 * 60 * 1000);
    const windowEnd = new Date(ioc.firstSeen.getTime() + 24 * 60 * 60 * 1000);

    const related = await db.select()
        .from(iocs)
        .where(
            and(
                ne(iocs.id, ioc.id),
                eq(iocs.source, ioc.source),
                isNotNull(iocs.firstSeen),
                gte(iocs.firstSeen, windowStart),
                lte(iocs.firstSeen, windowEnd),
            )
        )
        .limit(100);

    return related.map(r => ({
        sourceId: ioc.id,
        targetId: r.id,
        targetValue: r.value,
        targetType: r.type,
        correlationType: 'temporal' as const,
        confidence: 50,
        details: `Seen within 24h from same source (${ioc.source})`,
    }));
}

// ============================================================================
// Batch Correlation (for background processing)
// ============================================================================

export async function runBatchCorrelation(limit = 500): Promise<{
    processed: number;
    correlationsFound: number;
}> {
    const db = await getPostgres();

    // Get recent IOCs that haven't been correlated yet
    const recentIOCs = await db.select()
        .from(iocs)
        .orderBy(sql`${iocs.createdAt} DESC`)
        .limit(limit);

    let totalCorrelations = 0;

    for (const ioc of recentIOCs) {
        try {
            const correlations = await correlateIOC(ioc.id);
            totalCorrelations += correlations.length;
        } catch (err) {
            log.warn('Batch correlation failed for IOC', {
                iocId: ioc.id,
                error: (err as Error).message,
            });
        }
    }

    log.info('Batch correlation completed', {
        processed: recentIOCs.length,
        correlationsFound: totalCorrelations,
    });

    return {
        processed: recentIOCs.length,
        correlationsFound: totalCorrelations,
    };
}

// ============================================================================
// Helpers
// ============================================================================

function extractDomainFromURL(url: string): string | null {
    try {
        return new URL(url).hostname;
    } catch {
        return null;
    }
}

function getBaseDomain(domain: string): string | null {
    const parts = domain.split('.');
    if (parts.length < 2) return null;
    return parts.slice(-2).join('.');
}
