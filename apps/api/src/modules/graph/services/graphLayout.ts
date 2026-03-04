/**
 * Graph Layout Service
 * 
 * Server-side force-directed graph layout using d3-force.
 * Pre-computes node positions so the client only needs to render SVG —
 * no force simulation, canvas, or GPU required on the client.
 * 
 * Links are built from REAL CTI relationship data:
 * - MITRE ATT&CK: actor→technique, actor→malware (PostgreSQL)
 * - Pulse attribution: actor→IOC via pulse adversary (PostgreSQL)
 * - Tag correlation: CVE→IOC by threat type (in-memory)
 * - Embedding similarity: entity→entity cosine > 0.75 (OpenSearch knn_vector)
 */

import {
    forceSimulation,
    forceLink,
    forceManyBody,
    forceCenter,
    forceCollide,
    type SimulationNodeDatum,
    type SimulationLinkDatum,
} from 'd3-force';
import { getAllRelationships, type RelationshipLink, type RelationshipNode } from './graphRelationships';
import { createLogger } from '../../../lib/logger';

const log = createLogger('GraphLayout');

// ============================================================================
// Types
// ============================================================================

export interface GraphNode extends SimulationNodeDatum {
    id: string;
    label: string;
    type: 'ioc' | 'actor' | 'cve' | 'technique' | 'malware' | 'pulse';
    subType?: string;
    severity?: string | null;
    source?: string;
    group: number;
    size: number;
}

export interface GraphLink extends SimulationLinkDatum<GraphNode> {
    source: string;
    target: string;
    type: string;
    label?: string;
}

export interface LayoutResult {
    nodes: Array<{
        id: string;
        x: number;
        y: number;
        label: string;
        type: string;
        subType?: string;
        severity?: string | null;
        source?: string;
        group: number;
        size: number;
    }>;
    links: Array<{
        source: string;
        target: string;
        type: string;
        label?: string;
    }>;
    meta: {
        nodeCount: number;
        linkCount: number;
        computeTimeMs: number;
        linkBreakdown: Record<string, number>;
    };
}

// Node type → group mapping for force layout clustering
const TYPE_GROUPS: Record<string, number> = {
    actor: 0,
    technique: 1,
    malware: 2,
    cve: 3,
    ioc: 4,
    pulse: 5,
};

// Node type → default size
const TYPE_SIZES: Record<string, number> = {
    actor: 14,
    technique: 10,
    malware: 10,
    cve: 8,
    ioc: 5,
    pulse: 6,
};

// ============================================================================
// Layout Computation
// ============================================================================

/**
 * Compute a force-directed graph layout server-side with REAL relationship data.
 * 
 * @param iocs - IOC items from OpenSearch
 * @param actors - Threat actor items from OpenSearch  
 * @param cves - CVE/vulnerability items from OpenSearch
 * @param width - Layout width (default 1200)
 * @param height - Layout height (default 800)
 * @returns Pre-computed positions for all nodes and links
 */
export async function computeGraphLayout(
    iocs: Record<string, unknown>[],
    actors: Record<string, unknown>[],
    cves: Record<string, unknown>[],
    width: number = 1200,
    height: number = 800,
): Promise<LayoutResult> {
    const start = Date.now();

    // Build primary nodes
    const nodes: GraphNode[] = [];
    const nodeIds = new Set<string>();

    // Add actor nodes (largest, group 0)
    for (const actor of actors) {
        const id = `actor-${actor.id}`;
        if (!nodeIds.has(id)) {
            nodeIds.add(id);
            nodes.push({
                id,
                label: String(actor.name || actor.value || actor.title || 'Unknown Actor'),
                type: 'actor',
                severity: (actor.severity as string | null) ?? undefined,
                source: actor.source as string | undefined,
                group: TYPE_GROUPS.actor,
                size: TYPE_SIZES.actor,
            });
        }
    }

    // Add CVE nodes (medium, group 3)
    for (const cve of cves) {
        const id = `cve-${cve.id}`;
        if (!nodeIds.has(id)) {
            nodeIds.add(id);
            nodes.push({
                id,
                label: String(cve.cveId || cve.value || cve.title || 'Unknown CVE'),
                type: 'cve',
                severity: (cve.severity as string | null) ?? undefined,
                source: cve.source as string | undefined,
                group: TYPE_GROUPS.cve,
                size: TYPE_SIZES.cve,
            });
        }
    }

    // Add IOC nodes (smallest, group 4)
    for (const ioc of iocs) {
        const id = `ioc-${ioc.id}`;
        if (!nodeIds.has(id)) {
            nodeIds.add(id);
            nodes.push({
                id,
                label: String(ioc.value || ioc.title || 'Unknown IOC'),
                type: 'ioc',
                subType: ioc.type as string | undefined,
                severity: (ioc.severity as string | null) ?? undefined,
                source: ioc.source as string | undefined,
                group: TYPE_GROUPS.ioc,
                size: TYPE_SIZES.ioc,
            });
        }
    }

    // ========================================================================
    // Fetch REAL relationship links from PostgreSQL + OpenSearch
    // ========================================================================

    let relationshipLinks: RelationshipLink[] = [];
    let extraNodes: RelationshipNode[] = [];

    try {
        const relationships = await getAllRelationships(actors, iocs, cves);
        relationshipLinks = relationships.links;
        extraNodes = relationships.extraNodes;
    } catch (error) {
        log.warn('Failed to fetch relationships, using empty links', { error });
    }

    // Add extra nodes (techniques, malware) from relationship queries
    for (const extra of extraNodes) {
        if (!nodeIds.has(extra.id)) {
            nodeIds.add(extra.id);
            nodes.push({
                id: extra.id,
                label: extra.label,
                type: extra.type as GraphNode['type'],
                subType: extra.subType,
                severity: extra.severity,
                source: extra.source,
                group: TYPE_GROUPS[extra.type] ?? 5,
                size: TYPE_SIZES[extra.type] ?? 6,
            });
        }
    }

    // Build links, only keeping those where both endpoints exist as nodes
    const links: GraphLink[] = [];
    const linkSet = new Set<string>();
    const linkBreakdown: Record<string, number> = {};

    for (const rel of relationshipLinks) {
        const key = `${rel.source}|${rel.target}`;
        const reverseKey = `${rel.target}|${rel.source}`;

        if (!linkSet.has(key) && !linkSet.has(reverseKey) &&
            nodeIds.has(rel.source) && nodeIds.has(rel.target)) {
            linkSet.add(key);
            links.push({
                source: rel.source,
                target: rel.target,
                type: rel.type,
                label: rel.label,
            });
            linkBreakdown[rel.type] = (linkBreakdown[rel.type] || 0) + 1;
        }
    }

    log.info('Layout computed', { nodes: nodes.length, links: links.length, linkBreakdown });

    // ========================================================================
    // Run force simulation (synchronous, deterministic)
    // ========================================================================

    const simulation = forceSimulation<GraphNode>(nodes)
        .force('link', forceLink<GraphNode, GraphLink>(links)
            .id((d: GraphNode) => d.id)
            .distance((l: GraphLink) => {
                // Shorter distances for stronger relationships
                const type = l.type || '';
                if (type === 'uses-technique' || type === 'uses-malware') return 60;
                if (type === 'attributed-ioc') return 80;
                if (type === 'threat-correlation') return 100;
                return 90;
            })
            .strength(0.4))
        .force('charge', forceManyBody()
            .strength((d: SimulationNodeDatum) => {
                // Actors repel more strongly to spread the graph
                const gn = d as GraphNode;
                if (gn.type === 'actor') return -200;
                if (gn.type === 'technique' || gn.type === 'malware') return -150;
                return -100;
            }))
        .force('center', forceCenter(width / 2, height / 2))
        .force('collide', forceCollide<GraphNode>()
            .radius((d: GraphNode) => d.size + 6)
            .strength(0.7))
        .stop();

    // Run 300 ticks (deterministic position convergence)
    const ticks = 300;
    for (let i = 0; i < ticks; i++) {
        simulation.tick();
    }

    const computeTimeMs = Date.now() - start;

    return {
        nodes: nodes.map((n) => ({
            id: n.id,
            x: Math.round((n.x || 0) * 100) / 100,
            y: Math.round((n.y || 0) * 100) / 100,
            label: n.label,
            type: n.type,
            subType: n.subType,
            severity: n.severity,
            source: n.source,
            group: n.group,
            size: n.size,
        })),
        links: links.map((l) => ({
            source: typeof l.source === 'object' ? (l.source as GraphNode).id : l.source,
            target: typeof l.target === 'object' ? (l.target as GraphNode).id : l.target,
            type: l.type,
            label: l.label,
        })),
        meta: {
            nodeCount: nodes.length,
            linkCount: links.length,
            computeTimeMs,
            linkBreakdown,
        },
    };
}
