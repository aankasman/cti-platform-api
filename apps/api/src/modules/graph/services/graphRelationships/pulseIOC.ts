/**
 * Graph Relationships — Pulse → IOC Links
 */

import { db, inArray, sql } from '@rinjani/db';
import { threatActors, pulses, iocs } from '@rinjani/db/schema';
import type { RelationshipLink } from './types';

/**
 * Get IOC→Actor connections via the pulse adversary chain.
 * IOCs have a pulse_id → the pulse has an adversary name → match to threat_actors.
 */
export async function getPulseIOCLinks(
    actorNames: string[],
    maxIOCsPerActor: number = 15,
): Promise<RelationshipLink[]> {
    if (actorNames.length === 0) return [];

    const links: RelationshipLink[] = [];
    const seenLinks = new Set<string>();

    const actorRows = await db
        .select({ id: threatActors.id, name: threatActors.name })
        .from(threatActors)
        .where(inArray(threatActors.name, actorNames));

    const actorIdByName = new Map<string, string>();
    for (const a of actorRows) {
        actorIdByName.set(a.name.toLowerCase(), a.id);
    }

    for (const actorName of actorNames) {
        const actorId = actorIdByName.get(actorName.toLowerCase());
        if (!actorId) continue;

        const actorPulses = await db
            .select({ otxId: pulses.otxId, name: pulses.name })
            .from(pulses)
            .where(sql`LOWER(${pulses.adversary}) = LOWER(${actorName})`)
            .limit(5);

        if (actorPulses.length === 0) continue;

        const pulseIds = actorPulses.map(p => p.otxId);

        const linkedIOCs = await db
            .select({ id: iocs.id, value: iocs.value, type: iocs.type })
            .from(iocs)
            .where(inArray(iocs.pulseId, pulseIds))
            .limit(maxIOCsPerActor);

        for (const ioc of linkedIOCs) {
            const linkKey = `actor-${actorId}|ioc-${ioc.id}`;
            if (!seenLinks.has(linkKey)) {
                seenLinks.add(linkKey);
                links.push({
                    source: `actor-${actorId}`,
                    target: `ioc-${ioc.id}`,
                    type: 'attributed-ioc',
                    label: `via pulse`,
                });
            }
        }
    }

    return links;
}
