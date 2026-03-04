/**
 * Neo4j Graph — Shared Types & Helpers
 */

import { createLogger } from '../../lib/logger';
import type { Node as Neo4jNode, Relationship as Neo4jRelationship } from 'neo4j-driver';

export const log = createLogger('Neo4jGraph');

// ============================================================================
// Types
// ============================================================================

export interface GraphNode {
    id: string;
    label: string;
    type: string;
    properties: Record<string, unknown>;
}

export interface GraphEdge {
    source: string;
    target: string;
    type: string;
    properties: Record<string, unknown>;
}

export interface GraphResult {
    nodes: GraphNode[];
    edges: GraphEdge[];
    meta?: Record<string, unknown>;
}

// ============================================================================
// Helpers
// ============================================================================

export function nodeId(n: Neo4jNode): string {
    const labels = n.labels?.[0] || 'Unknown';
    const props = n.properties;
    return props.stixId || props.mitreId || props.cveId || props.otxId || props.pgId || `${labels}-${n.elementId}`;
}

export function toGraphNode(n: Neo4jNode): GraphNode {
    const props = { ...n.properties };
    // Convert Neo4j integers
    for (const key of Object.keys(props)) {
        if (props[key]?.toNumber) props[key] = props[key].toNumber();
    }
    return {
        id: nodeId(n),
        label: props.name || props.value || props.cveId || props.mitreId || 'unknown',
        type: (n.labels?.[0] || 'Unknown').toLowerCase(),
        properties: props,
    };
}

export function toGraphEdge(r: Neo4jRelationship, srcNode: Neo4jNode, tgtNode: Neo4jNode): GraphEdge {
    const props = { ...r.properties };
    for (const key of Object.keys(props)) {
        if (props[key]?.toNumber) props[key] = props[key].toNumber();
    }
    return {
        source: nodeId(srcNode),
        target: nodeId(tgtNode),
        type: r.type,
        properties: props,
    };
}

export function dedup(nodes: GraphNode[], edges: GraphEdge[]): { nodes: GraphNode[]; edges: GraphEdge[] } {
    const nodeMap = new Map<string, GraphNode>();
    for (const n of nodes) nodeMap.set(n.id, n);

    const edgeSet = new Set<string>();
    const uniqueEdges: GraphEdge[] = [];
    for (const e of edges) {
        const key = `${e.source}|${e.type}|${e.target}`;
        if (!edgeSet.has(key)) {
            edgeSet.add(key);
            uniqueEdges.push(e);
        }
    }

    return { nodes: Array.from(nodeMap.values()), edges: uniqueEdges };
}
