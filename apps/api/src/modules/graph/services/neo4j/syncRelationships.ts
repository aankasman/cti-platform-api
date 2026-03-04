/**
 * Neo4j Relationship Sync — MITRE ATT&CK USES edges
 *
 * Resolves STIX UUIDs to MITRE IDs and creates USES edges in Neo4j.
 */

import { db, sql } from '@rinjani/db';
import { mitreRelationships } from '@rinjani/db/schema';
import { getNeo4jDriver } from './driver';
import { createLogger } from '../../../../lib/logger';

const log = createLogger('Neo4j');

export async function syncRelationships(): Promise<number> {
    // The relationships table stores full STIX 2.x IDs (e.g. "intrusion-set--<uuid>")
    // while entity tables use short MITRE IDs (e.g. "mitre--G0007", "T1059").
    // We resolve the mapping by extracting MITRE IDs from relationship descriptions
    // which contain markdown links like [Name](https://attack.mitre.org/groups/G0094).

    // Step 1: Build STIX UUID → MITRE ID mapping
    // The MITRE ATT&CK STIX bundle is the authoritative source for UUID→ID mapping.
    // We fetch it and extract external_references for all entity types.
    const ATTACK_URL = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json';

    const actorLookup = new Map<string, string>();
    const techLookup = new Map<string, string>();
    const malwareLookup = new Map<string, string>();
    const toolLookup = new Map<string, string>();

    try {
        log.info('Fetching MITRE ATT&CK STIX bundle for UUID mapping');
        const resp = await fetch(ATTACK_URL);
        if (!resp.ok) throw new Error(`STIX fetch failed: ${resp.status}`);
        const bundle = await resp.json() as { objects: Array<{ type: string; id: string; external_references?: Array<{ source_name: string; external_id?: string }> }> };

        for (const obj of bundle.objects) {
            const ref = obj.external_references?.find((r: { source_name: string; external_id?: string }) => r.source_name === 'mitre-attack');
            const mitreId = ref?.external_id;
            if (!mitreId) continue;

            switch (obj.type) {
                case 'intrusion-set': actorLookup.set(obj.id, mitreId); break;  // G0094
                case 'attack-pattern': techLookup.set(obj.id, mitreId); break;  // T1059, T1059.001
                case 'malware': malwareLookup.set(obj.id, mitreId); break;      // S0139
                case 'tool': toolLookup.set(obj.id, mitreId); break;            // S0154
            }
        }
        log.info('STIX bundle mapped', { actors: actorLookup.size, techniques: techLookup.size, malware: malwareLookup.size, tools: toolLookup.size });
    } catch (stixErr) {
        // Fallback: use description-based regex if STIX fetch fails
        log.warn('STIX bundle fetch failed, falling back to description regex', { error: stixErr });

        const actorMapping = await db.execute(sql`
            SELECT DISTINCT source_id as stix_uuid,
                substring(description from 'groups/(G[0-9]+)') as mitre_id
            FROM relationships
            WHERE source_type = 'intrusion-set' AND description LIKE '%groups/G%'
        `);
        for (const r of actorMapping as unknown as Record<string, unknown>[]) { if (r.mitre_id) actorLookup.set(String(r.stix_uuid), String(r.mitre_id)); }

        const techMapping = await db.execute(sql`
            SELECT DISTINCT target_id as stix_uuid,
                substring(description from 'techniques/(T[0-9]+\\.?[0-9]*)') as mitre_id
            FROM relationships
            WHERE target_type = 'attack-pattern' AND description LIKE '%techniques/T%'
        `);
        for (const r of techMapping as unknown as Record<string, unknown>[]) { if (r.mitre_id) techLookup.set(String(r.stix_uuid), String(r.mitre_id)); }

        const malwareMapping = await db.execute(sql`
            SELECT DISTINCT target_id as stix_uuid,
                substring(description from 'software/(S[0-9]+)') as mitre_id
            FROM relationships
            WHERE target_type = 'malware' AND description LIKE '%software/S%'
        `);
        for (const r of malwareMapping as unknown as Record<string, unknown>[]) { if (r.mitre_id) malwareLookup.set(String(r.stix_uuid), String(r.mitre_id)); }

        const toolMapping = await db.execute(sql`
            SELECT DISTINCT source_id as stix_uuid,
                substring(description from 'software/(S[0-9]+)') as mitre_id
            FROM relationships
            WHERE source_type = 'tool' AND description LIKE '%software/S%'
        `);
        for (const r of toolMapping as unknown as Record<string, unknown>[]) { if (r.mitre_id) toolLookup.set(String(r.stix_uuid), String(r.mitre_id)); }
    }

    log.info('STIX-MITRE mappings', { actors: actorLookup.size, techniques: techLookup.size, malware: malwareLookup.size, tools: toolLookup.size });

    // Step 2: Get all USES relationships and resolve both sides
    const allRels = await db.select({
        sourceType: mitreRelationships.sourceType,
        sourceId: mitreRelationships.sourceId,
        targetType: mitreRelationships.targetType,
        targetId: mitreRelationships.targetId,
        description: mitreRelationships.description,
    }).from(mitreRelationships)
        .where(sql`${mitreRelationships.relationshipType} = 'uses'`);

    if (allRels.length === 0) return 0;

    // Resolve STIX UUIDs to MITRE IDs using our lookup maps
    const lookupMap: Record<string, Map<string, string>> = {
        'intrusion-set': actorLookup,
        'attack-pattern': techLookup,
        'malware': malwareLookup,
        'tool': toolLookup,
    };

    const labelMap: Record<string, string> = {
        'intrusion-set': 'Actor',
        'attack-pattern': 'Technique',
        'malware': 'Malware',
        'tool': 'Tool',
    };

    // Group resolved edges by source_label|target_label
    const edgeGroups = new Map<string, Array<{ srcId: string; tgtId: string; desc: string }>>();
    let skipped = 0;

    for (const rel of allRels) {
        const srcLookup = lookupMap[rel.sourceType];
        const tgtLookup = lookupMap[rel.targetType];
        const srcLabel = labelMap[rel.sourceType];
        const tgtLabel = labelMap[rel.targetType];

        if (!srcLookup || !tgtLookup || !srcLabel || !tgtLabel) { skipped++; continue; }

        const resolvedSrc = srcLookup.get(rel.sourceId);
        const resolvedTgt = tgtLookup.get(rel.targetId);

        if (!resolvedSrc || !resolvedTgt) { skipped++; continue; }

        const groupKey = `${srcLabel}|${tgtLabel}`;
        if (!edgeGroups.has(groupKey)) edgeGroups.set(groupKey, []);
        edgeGroups.get(groupKey)!.push({
            srcId: resolvedSrc,
            tgtId: resolvedTgt,
            desc: (rel.description || '').slice(0, 300),
        });
    }

    log.info('Relationship resolution done', { resolved: allRels.length - skipped, skipped });

    // Step 3: Create USES edges in Neo4j
    const driver = getNeo4jDriver();
    const session = driver.session();
    let created = 0;

    try {
        for (const [groupKey, edges] of Array.from(edgeGroups.entries())) {
            const [srcLabel, tgtLabel] = groupKey.split('|');
            const BATCH = 500;

            for (let i = 0; i < edges.length; i += BATCH) {
                const batch = edges.slice(i, i + BATCH);
                await session.run(`
                    UNWIND $batch AS row
                    MATCH (src:${srcLabel} {mitreId: row.srcId})
                    MATCH (tgt:${tgtLabel} {mitreId: row.tgtId})
                    MERGE (src)-[r:USES]->(tgt)
                    SET r.description = coalesce(row.desc, ''),
                        r.syncedAt = datetime()
                `, { batch });
                created += batch.length;
            }

            log.info('USES edges created', { count: edges.length, from: srcLabel, to: tgtLabel });
        }

        log.info('Total relationship edges created', { count: created });
        return created;
    } finally {
        await session.close();
    }
}
