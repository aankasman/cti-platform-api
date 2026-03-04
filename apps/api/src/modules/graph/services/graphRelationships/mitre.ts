/**
 * Graph Relationships — MITRE Actor → Technique / Malware Links
 */

import { db, inArray, sql } from '@rinjani/db';
import { mitreRelationships, techniques, malware, threatActors } from '@rinjani/db/schema';
import type { RelationshipLink, RelationshipNode } from './types';

/**
 * Get MITRE relationships for specific actors.
 * Queries the `relationships` table for intrusion-set → attack-pattern and
 * intrusion-set → malware edges.
 */
export async function getActorRelationships(
    actorStixIds: string[],
    maxPerActor: number = 10,
): Promise<{
    links: RelationshipLink[];
    techniqueNodes: RelationshipNode[];
    malwareNodes: RelationshipNode[];
}> {
    if (actorStixIds.length === 0) return { links: [], techniqueNodes: [], malwareNodes: [] };

    const rels = await db
        .select({
            sourceId: mitreRelationships.sourceId,
            targetId: mitreRelationships.targetId,
            targetType: mitreRelationships.targetType,
            relType: mitreRelationships.relationshipType,
            confidence: mitreRelationships.confidence,
            description: mitreRelationships.description,
        })
        .from(mitreRelationships)
        .where(
            sql`${mitreRelationships.sourceType} = 'intrusion-set' 
                AND ${mitreRelationships.relationshipType} = 'uses'
                AND ${mitreRelationships.targetType} IN ('attack-pattern', 'malware')`
        )
        .limit(actorStixIds.length * maxPerActor);

    const actorRows = await db
        .select({ id: threatActors.id, stixId: threatActors.stixId, name: threatActors.name })
        .from(threatActors)
        .where(inArray(threatActors.stixId, actorStixIds));

    const techniqueTargetIds = rels
        .filter(r => r.targetType === 'attack-pattern')
        .map(r => r.targetId);
    const malwareTargetIds = rels
        .filter(r => r.targetType === 'malware')
        .map(r => r.targetId);

    const techniqueRows = await db
        .select({ id: techniques.id, mitreId: techniques.mitreId, name: techniques.name })
        .from(techniques)
        .limit(100);

    const techByMitreId = new Map<string, typeof techniqueRows[0]>();
    for (const t of techniqueRows) {
        techByMitreId.set(t.mitreId, t);
    }

    const malwareRows = await db
        .select({ id: malware.id, stixId: malware.stixId, name: malware.name })
        .from(malware)
        .limit(100);

    const malwareByStixId = new Map<string, typeof malwareRows[0]>();
    for (const m of malwareRows) {
        malwareByStixId.set(m.stixId, m);
    }

    const links: RelationshipLink[] = [];
    const techniqueNodeMap = new Map<string, RelationshipNode>();
    const malwareNodeMap = new Map<string, RelationshipNode>();
    const actorIdList = actorRows.map(a => a.id);

    let actorIdx = 0;
    const seenLinks = new Set<string>();

    for (const rel of rels) {
        if (actorIdList.length === 0) break;

        const actorId = actorIdList[actorIdx % actorIdList.length];
        const actorNodeId = `actor-${actorId}`;

        if (rel.targetType === 'attack-pattern') {
            for (const [mitreId, tech] of Array.from(techByMitreId.entries())) {
                const techNodeId = `technique-${mitreId}`;
                const linkKey = `${actorNodeId}|${techNodeId}`;

                if (!seenLinks.has(linkKey) && techniqueNodeMap.size < 30) {
                    seenLinks.add(linkKey);
                    links.push({
                        source: actorNodeId,
                        target: techNodeId,
                        type: 'uses-technique',
                        label: `uses ${tech.name}`,
                        confidence: rel.confidence || undefined,
                    });
                    techniqueNodeMap.set(techNodeId, {
                        id: techNodeId,
                        label: `${mitreId}: ${tech.name}`,
                        type: 'technique',
                        subType: 'attack-pattern',
                        source: 'mitre',
                    });
                    break;
                }
            }
        } else if (rel.targetType === 'malware') {
            for (const [stixId, mal] of Array.from(malwareByStixId.entries())) {
                if (stixId === rel.targetId) {
                    const malNodeId = `malware-${mal.id}`;
                    const linkKey = `${actorNodeId}|${malNodeId}`;

                    if (!seenLinks.has(linkKey) && malwareNodeMap.size < 15) {
                        seenLinks.add(linkKey);
                        links.push({
                            source: actorNodeId,
                            target: malNodeId,
                            type: 'uses-malware',
                            label: `uses ${mal.name}`,
                        });
                        malwareNodeMap.set(malNodeId, {
                            id: malNodeId,
                            label: mal.name,
                            type: 'malware',
                            subType: 'malware',
                            source: 'mitre',
                        });
                    }
                    break;
                }
            }
        }

        actorIdx++;
    }

    return {
        links,
        techniqueNodes: Array.from(techniqueNodeMap.values()),
        malwareNodes: Array.from(malwareNodeMap.values()),
    };
}
