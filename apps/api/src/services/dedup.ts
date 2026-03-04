/**
 * Cross-Source Deduplication Scoring
 *
 * When multiple intelligence feeds report the same IOC, this module
 * determines which record to keep and builds a provenance chain
 * linking all sources that corroborated the indicator.
 *
 * Scoring factors:
 *   1. Source reliability weight (VT > MISP > OTX > AbuseCH > generic)
 *   2. Recency (newer observations win)
 *   3. Enrichment completeness (more fields = higher score)
 *   4. Confidence level from source
 *
 * The winner becomes the canonical record; losers are linked as
 * corroborating sources in the provenance chain.
 *
 * Uses raw SQL via db.execute() to avoid Drizzle ORM version conflicts
 * in the monorepo (dual drizzle-orm installs with/without OTel).
 */

import { db, sql, rawQuery } from '@rinjani/db';
import type { RawQueryResult } from '@rinjani/db';
import type { IOC } from '@rinjani/db/schema';
import { createLogger } from '../lib/logger';
import { escSql } from '../lib/sanitize';

const log = createLogger('Dedup');

// ============================================================================
// Types
// ============================================================================

export interface DedupResult {
    canonical: IOC;
    duplicates: IOC[];
    mergedProvenance: ProvenanceEntry[];
    action: 'merged' | 'kept_existing' | 'replaced' | 'new';
}

export interface ProvenanceEntry {
    source: string;
    firstSeen: string | null;
    lastSeen: string | null;
    confidence: number | null;
    pulseId: string | null;
    observedAt: string;
}

// ============================================================================
// Source Reliability Weights
// ============================================================================

const SOURCE_WEIGHTS: Record<string, number> = {
    virustotal: 95,
    misp: 90,
    threatfox: 85,
    abuseipdb: 80,
    alienvault: 75,
    abusessl: 70,
    urlhaus: 70,
    ciscoumbrella: 65,
    emergingthreats: 65,
    feodotracker: 60,
    phishtank: 55,
    generic: 40,
};

function getSourceWeight(source: string): number {
    return SOURCE_WEIGHTS[source.toLowerCase()] || SOURCE_WEIGHTS.generic;
}

// ============================================================================
// Dedup Score Calculator
// ============================================================================

function calculateDedupScore(ioc: IOC): number {
    let score = 0;

    // Factor 1: Source reliability (0-95)
    score += getSourceWeight(ioc.source) * 0.35;

    // Factor 2: Recency — newer lastSeen = higher score (0-25)
    if (ioc.lastSeen) {
        const ageHours = (Date.now() - new Date(ioc.lastSeen).getTime()) / (1000 * 60 * 60);
        score += Math.max(0, 25 - (ageHours / 24)); // Decays 1 point per day
    }

    // Factor 3: Enrichment completeness (0-20)
    const fieldCount = [
        ioc.threatType,
        ioc.confidence,
        ioc.severity,
        ioc.firstSeen,
        ioc.lastSeen,
        ioc.tags?.length,
        ioc.rawData,
    ].filter(Boolean).length;
    score += (fieldCount / 7) * 20;

    // Factor 4: Source confidence (0-20)
    score += ((ioc.confidence || 0) / 100) * 20;

    return Math.round(score * 100) / 100;
}

// ============================================================================
// Merge Fields
// ============================================================================

function mergeIOCFields(canonical: IOC, duplicate: IOC): Partial<IOC> {
    const merged: Partial<IOC> = {};

    // Keep the better value for each field
    if (!canonical.threatType && duplicate.threatType) merged.threatType = duplicate.threatType;
    if (!canonical.severity && duplicate.severity) merged.severity = duplicate.severity;

    // Confidence: take the higher one
    if ((duplicate.confidence || 0) > (canonical.confidence || 0)) {
        merged.confidence = duplicate.confidence;
    }

    // First seen: take the earliest
    if (duplicate.firstSeen && (!canonical.firstSeen || duplicate.firstSeen < canonical.firstSeen)) {
        merged.firstSeen = duplicate.firstSeen;
    }

    // Last seen: take the latest
    if (duplicate.lastSeen && (!canonical.lastSeen || duplicate.lastSeen > canonical.lastSeen)) {
        merged.lastSeen = duplicate.lastSeen;
    }

    // Tags: union
    const allTags = new Set([...(canonical.tags || []), ...(duplicate.tags || [])]);
    if (allTags.size > (canonical.tags?.length || 0)) {
        merged.tags = Array.from(allTags);
    }

    return merged;
}

// ============================================================================
// Main Dedup Function
// ============================================================================

/**
 * Deduplicate an incoming IOC against existing records.
 *
 * 1. Find existing IOCs with the same (type, value)
 * 2. Score all candidates (existing + incoming)
 * 3. Highest score becomes canonical
 * 4. Merge fields from duplicates into canonical
 * 5. Build provenance chain
 */
export async function deduplicateIOC(incoming: IOC): Promise<DedupResult> {
    // Find existing records with the same value+type
    const escapedValue = escSql(incoming.value);
    const existingResult = await rawQuery(
        `SELECT * FROM iocs WHERE type = '${escSql(incoming.type)}' AND value = '${escapedValue}'`
    );
    const existing: IOC[] = existingResult.rows as unknown as IOC[];

    // No duplicates — this is a new IOC
    if (existing.length === 0) {
        return {
            canonical: incoming,
            duplicates: [],
            mergedProvenance: [buildProvenance(incoming)],
            action: 'new',
        };
    }

    // Score all candidates
    const candidates = [...existing, incoming].map(ioc => ({
        ioc,
        score: calculateDedupScore(ioc),
    }));

    candidates.sort((a, b) => b.score - a.score);

    const winner = candidates[0].ioc;
    const losers = candidates.slice(1).map(c => c.ioc);

    // Build provenance chain from all sources
    const provenance: ProvenanceEntry[] = candidates.map(c => buildProvenance(c.ioc));

    // Determine action
    const isNewWinner = winner === incoming;
    const action = isNewWinner ? 'replaced' : 'merged';

    // Merge fields from losers into winner
    let mergedFields: Partial<IOC> = {};
    for (const loser of losers) {
        const fields = mergeIOCFields(winner, loser);
        mergedFields = { ...mergedFields, ...fields };
    }

    // Apply merged fields if any
    if (Object.keys(mergedFields).length > 0 && winner.id) {
        const updates: string[] = [];
        if (mergedFields.threatType) updates.push(`threat_type = '${mergedFields.threatType}'`);
        if (mergedFields.severity) updates.push(`severity = '${mergedFields.severity}'`);
        if (mergedFields.confidence !== undefined) updates.push(`confidence = ${mergedFields.confidence}`);
        if (mergedFields.firstSeen) updates.push(`first_seen = '${new Date(mergedFields.firstSeen).toISOString()}'`);
        if (mergedFields.lastSeen) updates.push(`last_seen = '${new Date(mergedFields.lastSeen).toISOString()}'`);
        if (mergedFields.tags) updates.push(`tags = ARRAY[${mergedFields.tags.map(t => `'${escSql(t)}'`).join(',')}]`);

        const rawData = JSON.stringify({
            ...((winner.rawData as object) || {}),
            _provenance: provenance,
            _dedupScore: candidates[0].score,
            _sourceCount: candidates.length,
        }).replace(/'/g, "''");

        updates.push(`raw_data = '${rawData}'::jsonb`);
        updates.push(`updated_at = NOW()`);

        if (updates.length > 0) {
            await db.execute(sql.raw(`UPDATE iocs SET ${updates.join(', ')} WHERE id = '${escSql(winner.id)}'`));
        }
    }

    log.info('IOC deduplicated', {
        value: incoming.value,
        action,
        sourceCount: candidates.length,
        winnerSource: winner.source,
        winnerScore: candidates[0].score,
    });

    return {
        canonical: winner,
        duplicates: losers,
        mergedProvenance: provenance,
        action,
    };
}

// ============================================================================
// Helpers
// ============================================================================

function buildProvenance(ioc: IOC): ProvenanceEntry {
    return {
        source: ioc.source,
        firstSeen: ioc.firstSeen ? new Date(ioc.firstSeen).toISOString() : null,
        lastSeen: ioc.lastSeen ? new Date(ioc.lastSeen).toISOString() : null,
        confidence: ioc.confidence,
        pulseId: ioc.pulseId,
        observedAt: ioc.createdAt ? new Date(ioc.createdAt).toISOString() : new Date().toISOString(),
    };
}

/**
 * Get dedup stats for monitoring
 */
export async function getDedupStats(): Promise<{
    totalIOCs: number;
    uniqueValues: number;
    duplicateRate: number;
    topDuplicatedValues: Array<{ value: string; count: number }>;
}> {
    const [totalResult, uniqueResult, topDups] = await Promise.all([
        db.execute(sql.raw('SELECT count(*)::int as count FROM iocs')),
        db.execute(sql.raw('SELECT count(DISTINCT value)::int as count FROM iocs')),
        db.execute(sql.raw(`
            SELECT value, count(*)::int as count
            FROM iocs
            GROUP BY value
            HAVING count(*) > 1
            ORDER BY count DESC
            LIMIT 20
        `)),
    ]) as unknown as RawQueryResult[];

    const totalCount = Number(totalResult.rows?.[0]?.count ?? 0);
    const uniqueCount = Number(uniqueResult.rows?.[0]?.count ?? 0);

    return {
        totalIOCs: totalCount,
        uniqueValues: uniqueCount,
        duplicateRate: totalCount > 0 ? Math.round((1 - uniqueCount / totalCount) * 100) : 0,
        topDuplicatedValues: (topDups.rows || []) as Array<{ value: string; count: number }>,
    };
}
