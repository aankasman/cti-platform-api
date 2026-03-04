/**
 * GraphQL Schema Builder (Pothos)
 * 
 * Type-safe GraphQL schema builder for threat intelligence API.
 * Pothos is ISC licensed (open source, similar to MIT).
 */

import SchemaBuilder from '@pothos/core';
import type { Loaders } from './dataLoaders';

// ============================================================================
// Type Definitions
// ============================================================================

interface ThreatActor {
    id: string;
    stixId: string;
    name: string;
    aliases: string[];
    description?: string | null;
    primaryMotivation?: string | null;
    sophistication?: string | null;
    country?: string | null;
    firstSeen?: Date | null;
    lastSeen?: Date | null;
}

interface Technique {
    id: string;
    mitreId: string;
    name: string;
    description?: string | null;
    platforms: string[];
    tacticIds: string[];
    detection?: string | null;
    url?: string | null;
}

interface Tactic {
    id: string;
    mitreId: string;
    name: string;
    description?: string | null;
    shortName?: string | null;
}

interface Malware {
    id: string;
    stixId: string;
    name: string;
    description?: string | null;
    malwareTypes: string[];
    platforms: string[];
}

interface IOC {
    id: string;
    type: string;
    value: string;
    source: string;
    threatType?: string | null;
    severity?: string | null;
    confidence?: number | null;
    tags?: string[] | null;
    isMalicious: boolean;
    firstSeen?: Date | null;
    lastSeen?: Date | null;
}

interface IOCConnection {
    items: IOC[];
    total: number;
    hasMore: boolean;
}

interface Vulnerability {
    id: string;
    cveId: string;
    description?: string | null;
    severity?: string | null;
    cvssScore?: number | null;
    vendor?: string | null;
    product?: string | null;
    isKev: boolean;
    publishedDate?: Date | null;
}

interface VulnerabilityConnection {
    items: Vulnerability[];
    total: number;
    hasMore: boolean;
}

// ── Sighting types ──

interface SightingGQL {
    id: string;
    iocId: string;
    iocValue: string;
    iocType: string;
    type: string;
    source: string;
    description?: string | null;
    confidence: number;
    count: number;
    observedAt?: Date | null;
    createdAt?: Date | null;
}

interface SightingConnection {
    items: SightingGQL[];
    total: number;
    hasMore: boolean;
}

interface TopIOC {
    iocValue: string;
    count: number;
}

interface SourceCount {
    source: string;
    count: number;
}

interface SightingStats {
    totalSightings: number;
    avgConfidence: number;
    topIOCs: TopIOC[];
    bySource: SourceCount[];
}

// ── Neo4j Graph result types (matches graphTypes.ts interfaces) ──

interface GraphNodeGQL {
    id: string;
    label: string;
    type: string;
    properties: Record<string, unknown>;
}

interface GraphEdgeGQL {
    source: string;
    target: string;
    type: string;
    properties: Record<string, unknown>;
}

interface GraphResultGQL {
    nodes: GraphNodeGQL[];
    edges: GraphEdgeGQL[];
}

// ============================================================================
// Schema Builder — with Context carrying DataLoaders
// ============================================================================

export const builder = new SchemaBuilder<{
    Objects: {
        ThreatActor: ThreatActor;
        Technique: Technique;
        Tactic: Tactic;
        Malware: Malware;
        IOC: IOC;
        Vulnerability: Vulnerability;
        VulnerabilityConnection: VulnerabilityConnection;
        IOCConnection: IOCConnection;
        SightingGQL: SightingGQL;
        SightingConnection: SightingConnection;
        TopIOC: TopIOC;
        SourceCount: SourceCount;
        SightingStats: SightingStats;
        GraphNodeGQL: GraphNodeGQL;
        GraphEdgeGQL: GraphEdgeGQL;
        GraphResultGQL: GraphResultGQL;
    };
    Scalars: {
        Date: {
            Input: Date;
            Output: Date;
        };
        JSON: {
            Input: unknown;
            Output: unknown;
        };
    };
    Context: {
        loaders: Loaders;
    };
}>({});

// ============================================================================
// Custom Scalars
// ============================================================================

builder.scalarType('Date', {
    serialize: (value) => value.toISOString(),
    parseValue: (value: unknown) => new Date(value as string),
});

builder.scalarType('JSON', {
    serialize: (value) => value,
    parseValue: (value: unknown) => value,
});

// ============================================================================
// Object Types — Core CTI entities
// ============================================================================

builder.objectType('ThreatActor', {
    description: 'APT group or threat actor',
    fields: (t) => ({
        id: t.exposeString('id'),
        stixId: t.exposeString('stixId'),
        name: t.exposeString('name'),
        aliases: t.exposeStringList('aliases'),
        description: t.exposeString('description', { nullable: true }),
        primaryMotivation: t.exposeString('primaryMotivation', { nullable: true }),
        sophistication: t.exposeString('sophistication', { nullable: true }),
        country: t.exposeString('country', { nullable: true }),
        firstSeen: t.expose('firstSeen', { type: 'Date', nullable: true }),
        lastSeen: t.expose('lastSeen', { type: 'Date', nullable: true }),
    }),
});

builder.objectType('Technique', {
    description: 'MITRE ATT&CK Technique',
    fields: (t) => ({
        id: t.exposeString('id'),
        mitreId: t.exposeString('mitreId'),
        name: t.exposeString('name'),
        description: t.exposeString('description', { nullable: true }),
        platforms: t.exposeStringList('platforms'),
        tacticIds: t.exposeStringList('tacticIds'),
        detection: t.exposeString('detection', { nullable: true }),
        url: t.exposeString('url', { nullable: true }),
    }),
});

builder.objectType('Tactic', {
    description: 'MITRE ATT&CK Tactic',
    fields: (t) => ({
        id: t.exposeString('id'),
        mitreId: t.exposeString('mitreId'),
        name: t.exposeString('name'),
        description: t.exposeString('description', { nullable: true }),
        shortName: t.exposeString('shortName', { nullable: true }),
    }),
});

builder.objectType('Malware', {
    description: 'Malware family',
    fields: (t) => ({
        id: t.exposeString('id'),
        stixId: t.exposeString('stixId'),
        name: t.exposeString('name'),
        description: t.exposeString('description', { nullable: true }),
        malwareTypes: t.exposeStringList('malwareTypes'),
        platforms: t.exposeStringList('platforms'),
    }),
});

builder.objectType('IOC', {
    description: 'Indicator of Compromise',
    fields: (t) => ({
        id: t.exposeString('id'),
        type: t.exposeString('type'),
        value: t.exposeString('value'),
        source: t.exposeString('source'),
        threatType: t.exposeString('threatType', { nullable: true }),
        severity: t.exposeString('severity', { nullable: true }),
        confidence: t.exposeInt('confidence', { nullable: true }),
        tags: t.exposeStringList('tags', { nullable: true }),
        isMalicious: t.exposeBoolean('isMalicious'),
        firstSeen: t.expose('firstSeen', { type: 'Date', nullable: true }),
        lastSeen: t.expose('lastSeen', { type: 'Date', nullable: true }),
    }),
});

builder.objectType('Vulnerability', {
    description: 'CVE/KEV Vulnerability',
    fields: (t) => ({
        id: t.exposeString('id'),
        cveId: t.exposeString('cveId'),
        description: t.exposeString('description', { nullable: true }),
        severity: t.exposeString('severity', { nullable: true }),
        cvssScore: t.exposeFloat('cvssScore', { nullable: true }),
        vendor: t.exposeString('vendor', { nullable: true }),
        product: t.exposeString('product', { nullable: true }),
        isKev: t.exposeBoolean('isKev'),
        publishedDate: t.expose('publishedDate', { type: 'Date', nullable: true }),
    }),
});

builder.objectType('VulnerabilityConnection', {
    description: 'Paginated vulnerability results',
    fields: (t) => ({
        items: t.field({ type: ['Vulnerability'], resolve: (parent) => parent.items }),
        total: t.exposeInt('total'),
        hasMore: t.exposeBoolean('hasMore'),
    }),
});

builder.objectType('IOCConnection', {
    description: 'Paginated IOC results',
    fields: (t) => ({
        items: t.field({ type: ['IOC'], resolve: (parent) => parent.items }),
        total: t.exposeInt('total'),
        hasMore: t.exposeBoolean('hasMore'),
    }),
});

// ============================================================================
// Object Types — Sightings
// ============================================================================

builder.objectType('SightingGQL', {
    description: 'An IOC sighting observation',
    fields: (t) => ({
        id: t.exposeString('id'),
        iocId: t.exposeString('iocId'),
        iocValue: t.exposeString('iocValue'),
        iocType: t.exposeString('iocType'),
        type: t.exposeString('type'),
        source: t.exposeString('source'),
        description: t.exposeString('description', { nullable: true }),
        confidence: t.exposeInt('confidence'),
        count: t.exposeInt('count'),
        observedAt: t.expose('observedAt', { type: 'Date', nullable: true }),
        createdAt: t.expose('createdAt', { type: 'Date', nullable: true }),
    }),
});

builder.objectType('SightingConnection', {
    description: 'Paginated sighting results',
    fields: (t) => ({
        items: t.field({ type: ['SightingGQL'], resolve: (parent) => parent.items }),
        total: t.exposeInt('total'),
        hasMore: t.exposeBoolean('hasMore'),
    }),
});

builder.objectType('TopIOC', {
    description: 'IOC with observation count',
    fields: (t) => ({
        iocValue: t.exposeString('iocValue'),
        count: t.exposeInt('count'),
    }),
});

builder.objectType('SourceCount', {
    description: 'Source with sighting count',
    fields: (t) => ({
        source: t.exposeString('source'),
        count: t.exposeInt('count'),
    }),
});

builder.objectType('SightingStats', {
    description: 'Sighting aggregate statistics',
    fields: (t) => ({
        totalSightings: t.exposeInt('totalSightings'),
        avgConfidence: t.exposeInt('avgConfidence'),
        topIOCs: t.field({ type: ['TopIOC'], resolve: (parent) => parent.topIOCs }),
        bySource: t.field({ type: ['SourceCount'], resolve: (parent) => parent.bySource }),
    }),
});

// ============================================================================
// Object Types — Neo4j Graph Results
// ============================================================================

builder.objectType('GraphNodeGQL', {
    description: 'A node in the Neo4j knowledge graph',
    fields: (t) => ({
        id: t.exposeString('id'),
        label: t.exposeString('label'),
        type: t.exposeString('type'),
        properties: t.expose('properties', { type: 'JSON' }),
    }),
});

builder.objectType('GraphEdgeGQL', {
    description: 'An edge (relationship) in the Neo4j knowledge graph',
    fields: (t) => ({
        source: t.exposeString('source'),
        target: t.exposeString('target'),
        type: t.exposeString('type'),
        properties: t.expose('properties', { type: 'JSON' }),
    }),
});

builder.objectType('GraphResultGQL', {
    description: 'A graph result containing nodes and edges',
    fields: (t) => ({
        nodes: t.field({ type: ['GraphNodeGQL'], resolve: (parent) => parent.nodes }),
        edges: t.field({ type: ['GraphEdgeGQL'], resolve: (parent) => parent.edges }),
    }),
});

// ============================================================================
// Union Types
// ============================================================================

export const SearchResultType = builder.unionType('SearchResult', {
    types: ['ThreatActor', 'IOC', 'Vulnerability'],
    resolveType: (value) => {
        if ('stixId' in value && 'aliases' in value) return 'ThreatActor';
        if ('cveId' in value) return 'Vulnerability';
        return 'IOC';
    },
});

// Export types for resolvers
export type { ThreatActor, Technique, Tactic, Malware, IOC, IOCConnection, Vulnerability, VulnerabilityConnection, SightingGQL, SightingConnection, SightingStats, TopIOC, SourceCount, GraphNodeGQL, GraphEdgeGQL, GraphResultGQL };
