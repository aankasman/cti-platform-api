/**
 * GraphQL DataLoaders
 *
 * Batch-loading functions that prevent N+1 queries in relationship resolvers.
 * Each request gets fresh loader instances to avoid cross-request caching.
 */

import DataLoader from 'dataloader';
import { db, inArray, sql } from '@rinjani/db';
import { threatActors, iocs, vulnerabilities } from '@rinjani/db/schema';
import type { ThreatActor, IOC, Vulnerability, Technique } from './schema';

// ============================================================================
// Loader Factory — call once per request
// ============================================================================

export interface Loaders {
    actorLoader: DataLoader<string, ThreatActor | null>;
    iocLoader: DataLoader<string, IOC | null>;
    vulnerabilityLoader: DataLoader<string, Vulnerability | null>;
    techniqueLoader: DataLoader<string, Technique | null>;
}

export function createLoaders(): Loaders {
    // ── Threat Actors by UUID ──
    const actorLoader = new DataLoader<string, ThreatActor | null>(async (ids) => {
        const rows = await db.select().from(threatActors).where(inArray(threatActors.id, [...ids]));
        const map = new Map(rows.map(r => [r.id, {
            id: r.id,
            stixId: r.stixId,
            name: r.name,
            aliases: r.aliases ?? [],
            description: r.description,
            primaryMotivation: r.primaryMotivation,
            sophistication: r.sophistication,
            country: r.country ?? null,
            firstSeen: r.firstSeen ?? null,
            lastSeen: r.lastSeen ?? null,
        }]));
        return ids.map(id => map.get(id) ?? null);
    });

    // ── IOCs by UUID ──
    const iocLoader = new DataLoader<string, IOC | null>(async (ids) => {
        const rows = await db.select().from(iocs).where(inArray(iocs.id, [...ids]));
        const map = new Map(rows.map(r => [r.id, {
            id: r.id,
            type: r.type,
            value: r.value,
            source: r.source,
            threatType: r.threatType,
            isMalicious: false,
            firstSeen: r.firstSeen,
            lastSeen: r.lastSeen,
        }]));
        return ids.map(id => map.get(id) ?? null);
    });

    // ── Vulnerabilities by UUID ──
    const vulnerabilityLoader = new DataLoader<string, Vulnerability | null>(async (ids) => {
        const rows = await db.select().from(vulnerabilities).where(inArray(vulnerabilities.id, [...ids]));
        const map = new Map(rows.map(r => [r.id, {
            id: r.id,
            cveId: r.cveId,
            description: r.description,
            severity: r.severity,
            cvssScore: r.cvssScore ? parseFloat(String(r.cvssScore)) : null,
            vendor: r.vendorProject ?? null,
            product: r.product ?? null,
            isKev: r.isExploited ?? false,
        }]));
        return ids.map(id => map.get(id) ?? null);
    });

    // ── Techniques by mitre_id (e.g. "T1059") ──
    const techniqueLoader = new DataLoader<string, Technique | null>(async (mitreIds) => {
        const result = await db.execute(
            sql`SELECT * FROM techniques WHERE mitre_id = ANY(${[...mitreIds]})`
        );
        const rows = (result as unknown as { rows: Record<string, unknown>[] }).rows;
        const map = new Map(rows.map(row => [String(row.mitre_id), {
            id: String(row.id),
            mitreId: String(row.mitre_id),
            name: String(row.name),
            description: row.description as string | null,
            platforms: (row.platforms as string[]) ?? [],
            tacticIds: (row.tactic_ids as string[]) ?? [],
            detection: row.detection as string | null,
            url: row.url as string | null,
        }]));
        return mitreIds.map(id => map.get(id) ?? null);
    });

    return { actorLoader, iocLoader, vulnerabilityLoader, techniqueLoader };
}
