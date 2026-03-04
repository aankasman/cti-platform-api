/**
 * Graph Relationships — Composite Orchestrator
 */

import { createLogger } from '../../lib/logger';
import type { RelationshipLink, RelationshipNode } from './types';
import { getActorRelationships } from './mitre';
import { getPulseIOCLinks } from './pulseIOC';
import { getTagBasedLinks } from './crossEntity';

const log = createLogger('GraphRelationships');

/**
 * Fetch all relationship links for a set of graph entities.
 * Combines MITRE relationships, pulse→IOC chains, and tag-based correlations.
 */
export async function getAllRelationships(
    actors: Record<string, unknown>[],
    iocItems: Record<string, unknown>[],
    cveItems: Record<string, unknown>[],
): Promise<{
    links: RelationshipLink[];
    extraNodes: RelationshipNode[];
}> {
    const allLinks: RelationshipLink[] = [];
    const extraNodes: RelationshipNode[] = [];

    // 1. MITRE Actor → Technique / Malware
    const actorStixIds = actors
        .filter(a => a.stixId || a.stix_id)
        .map(a => String(a.stixId || a.stix_id));

    if (actorStixIds.length > 0) {
        const mitre = await getActorRelationships(actorStixIds, 8);
        allLinks.push(...mitre.links);
        extraNodes.push(...mitre.techniqueNodes);
        extraNodes.push(...mitre.malwareNodes);
    }

    // 2. Pulse → IOC links via adversary attribution
    const actorNames = actors
        .filter(a => a.name)
        .map(a => String(a.name));

    if (actorNames.length > 0) {
        const pulseLinks = await getPulseIOCLinks(actorNames, 10);
        allLinks.push(...pulseLinks);
    }

    // 3. Tag-based cross-entity correlations
    const iocNodesForTags = iocItems.map(i => ({
        id: String(i.id),
        tags: (i.tags || []) as string[],
        threatType: String(i.threatType || i.threat_type || ''),
    }));
    const cveNodesForTags = cveItems.map(c => ({
        id: String(c.id),
        cveId: String(c.cveId || c.cve_id || ''),
        severity: String(c.severity || ''),
    }));

    const tagLinks = await getTagBasedLinks(iocNodesForTags, cveNodesForTags);
    allLinks.push(...tagLinks);

    log.info('Relationships computed', { totalLinks: allLinks.length, hasMITRE: actorStixIds.length > 0, hasPulse: actorNames.length > 0, tagLinks: tagLinks.length });

    return { links: allLinks, extraNodes };
}
