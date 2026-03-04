/**
 * Sightings Service
 *
 * Manages IOC sighting lifecycle: create, list, aggregate.
 * Auto-recalculates IOC confidence on new sightings.
 */

import { sightings, iocs } from '@rinjani/db/schema';
import { and, desc, eq, sql } from '@rinjani/db';
import { getPostgres } from '../../../lib/db/clients';
import { createLogger } from '../../../lib/logger';

const log = createLogger('Sightings');

// ============================================================================
// Create Sighting
// ============================================================================

export interface CreateSightingInput {
    iocId: string;
    type?: 'sighting' | 'false-positive' | 'expiration';
    source: string;
    description?: string;
    confidence?: number;
    count?: number;
    observedAt?: string;
    createdBy?: string;
}

export async function addSighting(input: CreateSightingInput) {
    const db = await getPostgres();

    const [sighting] = await db.insert(sightings).values({
        iocId: input.iocId,
        type: input.type || 'sighting',
        source: input.source,
        description: input.description,
        confidence: input.confidence ?? 50,
        count: input.count ?? 1,
        observedAt: input.observedAt ? new Date(input.observedAt) : new Date(),
        createdBy: input.createdBy,
    }).returning();

    // Recalculate IOC confidence based on all sightings
    await recalculateConfidence(input.iocId);

    log.info('Sighting added', { sightingId: sighting.id, iocId: input.iocId, type: sighting.type });

    return sighting;
}

// ============================================================================
// Read Sightings
// ============================================================================

export async function getSightingsForIOC(iocId: string, limit = 50, offset = 0) {
    const db = await getPostgres();

    const items = await db.select()
        .from(sightings)
        .where(eq(sightings.iocId, iocId))
        .orderBy(desc(sightings.observedAt))
        .limit(limit)
        .offset(offset);

    const [{ count }] = await db.select({ count: sql<number>`count(*)::int` })
        .from(sightings)
        .where(eq(sightings.iocId, iocId));

    return { items, total: count };
}

export async function getRecentSightings(limit = 50) {
    const db = await getPostgres();

    const items = await db.select({
        sighting: sightings,
        iocValue: iocs.value,
        iocType: iocs.type,
    })
        .from(sightings)
        .leftJoin(iocs, eq(sightings.iocId, iocs.id))
        .orderBy(desc(sightings.observedAt))
        .limit(limit);

    return items.map(row => ({
        ...row.sighting,
        iocValue: row.iocValue,
        iocType: row.iocType,
    }));
}

// ============================================================================
// Sighting Stats
// ============================================================================

export async function getSightingStats(iocId?: string) {
    const db = await getPostgres();

    const condition = iocId ? eq(sightings.iocId, iocId) : undefined;

    const stats = await db.select({
        type: sightings.type,
        count: sql<number>`count(*)::int`,
        totalObservations: sql<number>`sum(${sightings.count})::int`,
        avgConfidence: sql<number>`round(avg(${sightings.confidence}))::int`,
        latestSighting: sql<string>`max(${sightings.observedAt})`,
    })
        .from(sightings)
        .where(condition)
        .groupBy(sightings.type);

    const [total] = await db.select({ count: sql<number>`count(*)::int` })
        .from(sightings)
        .where(condition);

    return {
        total: total?.count || 0,
        byType: Object.fromEntries(stats.map(s => [s.type, {
            count: s.count,
            totalObservations: s.totalObservations || 0,
            avgConfidence: s.avgConfidence || 0,
            latestSighting: s.latestSighting,
        }])),
    };
}

// ============================================================================
// Confidence Recalculation
// ============================================================================

async function recalculateConfidence(iocId: string) {
    const db = await getPostgres();

    // Weighted average: true sightings increase confidence, false-positives decrease it
    const [result] = await db.select({
        avgConfidence: sql<number>`
            round(
                sum(
                    CASE
                        WHEN ${sightings.type} = 'false-positive' THEN -${sightings.confidence}
                        WHEN ${sightings.type} = 'sighting' THEN ${sightings.confidence}
                        ELSE 0
                    END * ${sightings.count}
                ) / NULLIF(sum(${sightings.count}), 0)
            )::int
        `,
    })
        .from(sightings)
        .where(eq(sightings.iocId, iocId));

    const newConfidence = Math.max(0, Math.min(100, result?.avgConfidence ?? 50));

    await db.update(iocs)
        .set({ confidence: newConfidence })
        .where(eq(iocs.id, iocId));

    log.debug('IOC confidence recalculated', { iocId, newConfidence });
}
