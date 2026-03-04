/**
 * Neo4j Graph Analysis — Related Actors, Campaign Detection, Source Influence,
 * Actor Attribution, Raw Cypher
 */

import { getNeo4jDriver } from '../neo4j';
import neo4j from 'neo4j-driver';
import type { Node as Neo4jNode } from 'neo4j-driver';
import { log, toGraphNode, nodeId, dedup } from './graphTypes';
import type { GraphNode, GraphEdge, GraphResult } from './graphTypes';

// ============================================================================
// Related Actors (shared techniques)
// ============================================================================

/**
 * Find actors that share techniques with a given actor.
 */
export async function findRelatedActors(
    actorName: string,
    minShared: number = 1,
): Promise<GraphResult> {
    const driver = getNeo4jDriver();
    const session = driver.session();

    try {
        const result = await session.run(`
            MATCH (a:Actor)
            WHERE toLower(a.name) = toLower($name)
               OR a.stixId = $name
            WITH a LIMIT 1
            MATCH (a)-[:USES]->(t:Technique)<-[:USES]-(related:Actor)
            WHERE related <> a
            WITH a, related, collect(DISTINCT t) AS sharedTechs
            WHERE size(sharedTechs) >= $minShared
            RETURN a, related, sharedTechs
            ORDER BY size(sharedTechs) DESC
            LIMIT 20
        `, { name: actorName, minShared: neo4j.int(minShared) });

        const nodes: GraphNode[] = [];
        const edges: GraphEdge[] = [];

        for (const rec of result.records) {
            const actor = rec.get('a');
            const related = rec.get('related');
            const sharedTechs: Neo4jNode[] = rec.get('sharedTechs') || [];

            if (actor) nodes.push(toGraphNode(actor));
            if (related) nodes.push(toGraphNode(related));

            for (const t of sharedTechs) {
                if (t) {
                    nodes.push(toGraphNode(t));
                    // Add edges: actor→tech, related→tech
                    if (actor) edges.push({
                        source: nodeId(actor),
                        target: nodeId(t),
                        type: 'USES',
                        properties: {},
                    });
                    if (related) edges.push({
                        source: nodeId(related),
                        target: nodeId(t),
                        type: 'USES',
                        properties: {},
                    });
                }
            }
        }

        const { nodes: dn, edges: de } = dedup(nodes, edges);
        return {
            nodes: dn,
            edges: de,
            meta: {
                actor: actorName,
                relatedActorCount: result.records.length,
            },
        };
    } finally {
        await session.close();
    }
}

// ============================================================================
// Campaign Detection (cluster by shared IOCs/timing)
// ============================================================================

/**
 * Detect potential campaigns by clustering WebSource items that share IOCs.
 * Returns groups of web sources connected through common IOC mentions.
 */
export async function campaignDetection(
    minSharedIOCs: number = 2,
    limit: number = 20,
): Promise<GraphResult> {
    const driver = getNeo4jDriver();
    const session = driver.session();

    try {
        const result = await session.run(`
            // Find pairs of WebSources sharing IOC mentions
            MATCH (s1:WebSource)-[:MENTIONED_IN]->(ioc:IOC)<-[:MENTIONED_IN]-(s2:WebSource)
            WHERE id(s1) < id(s2)
            WITH s1, s2, collect(DISTINCT ioc) AS sharedIOCs
            WHERE size(sharedIOCs) >= $minShared
            // Optionally connect to campaigns if already linked
            OPTIONAL MATCH (s1)-[:PART_OF_CAMPAIGN]->(camp:Campaign)
            OPTIONAL MATCH (s2)-[:PART_OF_CAMPAIGN]->(camp2:Campaign)
            // Linked actors via DISCOVERED_BY
            OPTIONAL MATCH (s1)-[:DISCOVERED_BY]->(a1:Actor)
            OPTIONAL MATCH (s2)-[:DISCOVERED_BY]->(a2:Actor)
            RETURN s1, s2, sharedIOCs,
                   camp, camp2,
                   collect(DISTINCT a1) + collect(DISTINCT a2) AS linkedActors,
                   size(sharedIOCs) AS overlap
            ORDER BY overlap DESC
            LIMIT $limit
        `, {
            minShared: neo4j.int(minSharedIOCs),
            limit: neo4j.int(limit),
        });

        const nodes: GraphNode[] = [];
        const edges: GraphEdge[] = [];

        for (const rec of result.records) {
            const s1 = rec.get('s1');
            const s2 = rec.get('s2');
            const sharedIOCs: Neo4jNode[] = rec.get('sharedIOCs') || [];
            const camp = rec.get('camp');
            const camp2 = rec.get('camp2');
            const linkedActors: Neo4jNode[] = (rec.get('linkedActors') || []).filter((a: Neo4jNode | null) => a != null);

            if (s1) nodes.push(toGraphNode(s1));
            if (s2) nodes.push(toGraphNode(s2));
            if (camp) nodes.push(toGraphNode(camp));
            if (camp2 && camp2 !== camp) nodes.push(toGraphNode(camp2));

            // Add linked Actor nodes
            for (const actor of linkedActors) {
                if (actor) {
                    nodes.push(toGraphNode(actor));
                    if (s1) edges.push({ source: nodeId(s1), target: nodeId(actor), type: 'DISCOVERED_BY', properties: {} });
                    if (s2) edges.push({ source: nodeId(s2), target: nodeId(actor), type: 'DISCOVERED_BY', properties: {} });
                }
            }

            for (const ioc of sharedIOCs) {
                if (ioc) {
                    const gn = toGraphNode(ioc);
                    // Attach firstSeen from IOC properties if available
                    if (ioc.properties?.firstSeen) gn.properties.firstSeen = ioc.properties.firstSeen;
                    if (ioc.properties?.lastSeen) gn.properties.lastSeen = ioc.properties.lastSeen;
                    if (ioc.properties?.createdAt) gn.properties.createdAt = ioc.properties.createdAt;
                    nodes.push(gn);
                    if (s1) edges.push({ source: nodeId(s1), target: nodeId(ioc), type: 'MENTIONED_IN', properties: {} });
                    if (s2) edges.push({ source: nodeId(s2), target: nodeId(ioc), type: 'MENTIONED_IN', properties: {} });
                }
            }

            if (s1 && camp) edges.push({ source: nodeId(s1), target: nodeId(camp), type: 'PART_OF_CAMPAIGN', properties: {} });
            if (s2 && camp2) edges.push({ source: nodeId(s2), target: nodeId(camp2), type: 'PART_OF_CAMPAIGN', properties: {} });
        }

        const { nodes: dn, edges: de } = dedup(nodes, edges);
        return {
            nodes: dn,
            edges: de,
            meta: { minSharedIOCs, clusterCount: result.records.length },
        };
    } finally {
        await session.close();
    }
}

// ============================================================================
// Source Influence (rank sources by intel contribution)
// ============================================================================

/**
 * Rank web sources by how many unique IOCs they contributed
 * and how many actors they've helped attribute.
 */
export async function sourceInfluence(
    limit: number = 20,
): Promise<GraphResult> {
    const driver = getNeo4jDriver();
    const session = driver.session();

    try {
        const result = await session.run(`
            MATCH (w:WebSource)
            OPTIONAL MATCH (w)-[:MENTIONED_IN]->(ioc:IOC)
            OPTIONAL MATCH (w)-[:DISCOVERED_BY]->(actor:Actor)
            OPTIONAL MATCH (w)-[:PART_OF_CAMPAIGN]->(camp:Campaign)
            WITH w,
                 count(DISTINCT ioc) AS iocCount,
                 count(DISTINCT actor) AS actorCount,
                 count(DISTINCT camp) AS campaignCount,
                 collect(DISTINCT ioc)[0..5] AS topIOCs,
                 collect(DISTINCT actor)[0..3] AS linkedActors
            RETURN w, iocCount, actorCount, campaignCount, topIOCs, linkedActors
            ORDER BY iocCount DESC, actorCount DESC
            LIMIT $limit
        `, { limit: neo4j.int(limit) });

        const nodes: GraphNode[] = [];
        const edges: GraphEdge[] = [];

        for (const rec of result.records) {
            const w = rec.get('w');
            const topIOCs: Neo4jNode[] = rec.get('topIOCs') || [];
            const linkedActors: Neo4jNode[] = rec.get('linkedActors') || [];

            if (w) {
                const gn = toGraphNode(w);
                gn.properties.iocCount = neo4j.integer.toNumber(rec.get('iocCount') ?? 0);
                gn.properties.actorCount = neo4j.integer.toNumber(rec.get('actorCount') ?? 0);
                gn.properties.campaignCount = neo4j.integer.toNumber(rec.get('campaignCount') ?? 0);
                nodes.push(gn);

                for (const ioc of topIOCs) {
                    if (ioc) {
                        nodes.push(toGraphNode(ioc));
                        edges.push({ source: nodeId(w), target: nodeId(ioc), type: 'MENTIONED_IN', properties: {} });
                    }
                }
                for (const actor of linkedActors) {
                    if (actor) {
                        nodes.push(toGraphNode(actor));
                        edges.push({ source: nodeId(w), target: nodeId(actor), type: 'DISCOVERED_BY', properties: {} });
                    }
                }
            }
        }

        const { nodes: dn, edges: de } = dedup(nodes, edges);
        return { nodes: dn, edges: de, meta: { sourceCount: result.records.length } };
    } finally {
        await session.close();
    }
}

// ============================================================================
// Actor Attribution (IOC → WebSource → Actor chain)
// ============================================================================

/**
 * Given an IOC value, find attribution chains:
 * IOC ← MENTIONED_IN ← WebSource → DISCOVERED_BY → Actor
 */
export async function actorAttribution(
    iocValue: string,
    maxChains: number = 20,
): Promise<GraphResult> {
    const driver = getNeo4jDriver();
    const session = driver.session();

    try {
        const result = await session.run(`
            MATCH (ioc:IOC)
            WHERE ioc.value = $value OR ioc.pgId = $value
            WITH ioc LIMIT 1
            // Direct WebSource mentions
            OPTIONAL MATCH (ws:WebSource)-[m:MENTIONED_IN]->(ioc)
            // Actor attributions from those web sources
            OPTIONAL MATCH (ws)-[d:DISCOVERED_BY]->(actor:Actor)
            // Also check if IOC links through campaign
            OPTIONAL MATCH (ioc)-[:PART_OF_CAMPAIGN]->(camp:Campaign)
            OPTIONAL MATCH (camp)<-[:PART_OF_CAMPAIGN]-(campSource:WebSource)
            OPTIONAL MATCH (campSource)-[:DISCOVERED_BY]->(campActor:Actor)
            RETURN ioc, 
                   collect(DISTINCT ws) AS webSources,
                   collect(DISTINCT actor) AS directActors,
                   collect(DISTINCT camp) AS campaigns,
                   collect(DISTINCT campSource)[0..$limit] AS campaignSources,
                   collect(DISTINCT campActor) AS campaignActors
        `, {
            value: iocValue,
            limit: neo4j.int(maxChains),
        });

        const nodes: GraphNode[] = [];
        const edges: GraphEdge[] = [];

        if (result.records.length > 0) {
            const rec = result.records[0];
            const ioc = rec.get('ioc');
            const webSources: Neo4jNode[] = rec.get('webSources') || [];
            const directActors: Neo4jNode[] = rec.get('directActors') || [];
            const campaignNodes: Neo4jNode[] = rec.get('campaigns') || [];
            const campaignSources: Neo4jNode[] = rec.get('campaignSources') || [];
            const campaignActors: Neo4jNode[] = rec.get('campaignActors') || [];

            if (ioc) nodes.push(toGraphNode(ioc));

            const nodeById = new Map<string, Neo4jNode>();
            if (ioc) nodeById.set(ioc.elementId, ioc);

            const addNodes = (list: Neo4jNode[]) => {
                for (const n of list) {
                    if (n && !nodeById.has(n.elementId)) {
                        nodeById.set(n.elementId, n);
                        nodes.push(toGraphNode(n));
                    }
                }
            };

            addNodes(webSources);
            addNodes(directActors);
            addNodes(campaignNodes);
            addNodes(campaignSources);
            addNodes(campaignActors);

            // WebSource → IOC edges
            for (const ws of webSources) {
                if (ws && ioc) {
                    edges.push({ source: nodeId(ws), target: nodeId(ioc), type: 'MENTIONED_IN', properties: {} });
                }
            }
            // WebSource → Actor edges
            for (const ws of webSources) {
                for (const actor of directActors) {
                    if (ws && actor) {
                        edges.push({ source: nodeId(ws), target: nodeId(actor), type: 'DISCOVERED_BY', properties: {} });
                    }
                }
            }
            // Campaign edges
            if (ioc) {
                for (const camp of campaignNodes) {
                    if (camp) edges.push({ source: nodeId(ioc), target: nodeId(camp), type: 'PART_OF_CAMPAIGN', properties: {} });
                }
            }
            for (const cs of campaignSources) {
                for (const camp of campaignNodes) {
                    if (cs && camp) edges.push({ source: nodeId(cs), target: nodeId(camp), type: 'PART_OF_CAMPAIGN', properties: {} });
                }
                for (const ca of campaignActors) {
                    if (cs && ca) edges.push({ source: nodeId(cs), target: nodeId(ca), type: 'DISCOVERED_BY', properties: {} });
                }
            }
        }

        const { nodes: dn, edges: de } = dedup(nodes, edges);
        return {
            nodes: dn,
            edges: de,
            meta: {
                ioc: iocValue,
                attributionPaths: edges.length,
            },
        };
    } finally {
        await session.close();
    }
}

// ============================================================================
// Raw Cypher (for advanced analysts)
// ============================================================================

/**
 * Execute a read-only Cypher query (for admin/analyst use).
 * Note: Only read operations are allowed.
 */
export async function executeCypher(
    query: string,
    params: Record<string, unknown> = {},
    limit: number = 100,
): Promise<Record<string, unknown>[]> {
    // Safety: block write operations
    const upper = query.toUpperCase().trim();
    if (upper.includes('DELETE') || upper.includes('DETACH') ||
        upper.includes('CREATE') || upper.includes('MERGE') ||
        upper.includes('SET ') || upper.includes('REMOVE')) {
        throw new Error('Write operations are not allowed via the Cypher query endpoint');
    }

    const driver = getNeo4jDriver();
    const session = driver.session({ defaultAccessMode: neo4j.session.READ });
    try {
        const result = await session.run(query, params);
        return result.records.slice(0, limit).map(rec => {
            const obj: Record<string, unknown> = {};
            for (const key of rec.keys as string[]) {
                const val = rec.get(key as string);
                if (val?.properties) {
                    obj[key as string] = { labels: val.labels, ...val.properties };
                } else if (val?.toNumber) {
                    obj[key as string] = val.toNumber();
                } else {
                    obj[key as string] = val;
                }
            }
            return obj;
        });
    } finally {
        await session.close();
    }
}
