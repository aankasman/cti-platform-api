/**
 * GraphQL Schema Introspection Tests
 *
 * Validates that the Pothos schema contains the expected types, fields,
 * and queries after the Phase 1 enrichment (relationships + Neo4j).
 * Schema-only — no database or Neo4j connection required.
 *
 * We check type names via constructor.name rather than instanceof to avoid
 * issues with duplicate graphql package instances in pnpm monorepo.
 */

import { describe, it, expect } from 'vitest';
import { schema } from '../graphql/resolvers';
import type { GraphQLObjectType, GraphQLUnionType } from 'graphql';

// ============================================================================
// Helpers
// ============================================================================

function getType(name: string) {
    return schema.getType(name);
}

function getQueryFields() {
    const queryType = schema.getQueryType();
    expect(queryType).toBeDefined();
    return queryType!.getFields();
}

function assertTypeName(type: unknown, expectedConstructor: string) {
    expect(type).toBeDefined();
    expect((type as { constructor: { name: string } }).constructor.name).toBe(expectedConstructor);
}

// ============================================================================
// Core CTI Object Types
// ============================================================================

describe('GraphQL Schema — Core Types', () => {
    it.each([
        'ThreatActor',
        'Technique',
        'Tactic',
        'Malware',
        'IOC',
        'Vulnerability',
    ])('has object type %s', (typeName) => {
        assertTypeName(getType(typeName), 'GraphQLObjectType');
    });

    it('Stats type is defined', () => {
        assertTypeName(getType('Stats'), 'GraphQLObjectType');
    });
});

// ============================================================================
// Graph Result Types (new in Phase 1)
// ============================================================================

describe('GraphQL Schema — Graph Types', () => {
    it.each([
        'GraphNodeGQL',
        'GraphEdgeGQL',
        'GraphResultGQL',
    ])('has graph object type %s', (typeName) => {
        assertTypeName(getType(typeName), 'GraphQLObjectType');
    });

    it('GraphNodeGQL has expected fields', () => {
        const t = getType('GraphNodeGQL') as GraphQLObjectType;
        const fields = t.getFields();
        expect(fields.id).toBeDefined();
        expect(fields.label).toBeDefined();
        expect(fields.type).toBeDefined();
        expect(fields.properties).toBeDefined();
    });

    it('GraphEdgeGQL has expected fields', () => {
        const t = getType('GraphEdgeGQL') as GraphQLObjectType;
        const fields = t.getFields();
        expect(fields.source).toBeDefined();
        expect(fields.target).toBeDefined();
        expect(fields.type).toBeDefined();
        expect(fields.properties).toBeDefined();
    });

    it('GraphResultGQL has nodes and edges lists', () => {
        const t = getType('GraphResultGQL') as GraphQLObjectType;
        const fields = t.getFields();
        expect(fields.nodes).toBeDefined();
        expect(fields.edges).toBeDefined();
    });
});

// ============================================================================
// SearchResult Union (new in Phase 1)
// ============================================================================

describe('GraphQL Schema — SearchResult Union', () => {
    it('SearchResult union type exists', () => {
        assertTypeName(getType('SearchResult'), 'GraphQLUnionType');
    });

    it('SearchResult includes ThreatActor, IOC, Vulnerability', () => {
        const t = getType('SearchResult') as GraphQLUnionType;
        const memberNames = t.getTypes().map(m => m.name).sort();
        expect(memberNames).toEqual(['IOC', 'ThreatActor', 'Vulnerability']);
    });
});

// ============================================================================
// Custom Scalars
// ============================================================================

describe('GraphQL Schema — Scalars', () => {
    it.each(['Date', 'JSON'])('has custom scalar %s', (name) => {
        assertTypeName(getType(name), 'GraphQLScalarType');
    });
});

// ============================================================================
// Relationship Fields (new in Phase 1)
// ============================================================================

describe('GraphQL Schema — Relationship Fields', () => {
    it('ThreatActor has iocs relationship field', () => {
        const t = getType('ThreatActor') as GraphQLObjectType;
        expect(t.getFields().iocs).toBeDefined();
    });

    it('ThreatActor has techniques relationship field', () => {
        const t = getType('ThreatActor') as GraphQLObjectType;
        expect(t.getFields().techniques).toBeDefined();
    });

    it('ThreatActor has relatedActors relationship field', () => {
        const t = getType('ThreatActor') as GraphQLObjectType;
        expect(t.getFields().relatedActors).toBeDefined();
    });

    it('IOC has relatedActors relationship field', () => {
        const t = getType('IOC') as GraphQLObjectType;
        expect(t.getFields().relatedActors).toBeDefined();
    });

    it('Vulnerability has relatedIocs relationship field', () => {
        const t = getType('Vulnerability') as GraphQLObjectType;
        expect(t.getFields().relatedIocs).toBeDefined();
    });
});

// ============================================================================
// Queries — Existing + New Graph Queries
// ============================================================================

describe('GraphQL Schema — Queries', () => {
    // Existing queries still present
    it.each([
        'threatActors',
        'threatActor',
        'techniques',
        'tactics',
        'iocs',
        'vulnerabilities',
        'search',
        'stats',
    ])('has existing query %s', (queryName) => {
        const fields = getQueryFields();
        expect(fields[queryName]).toBeDefined();
    });

    // New Neo4j graph queries
    it.each([
        'graphSearch',
        'graphExplore',
        'graphShortestPath',
        'attackTree',
        'iocPivot',
    ])('has new graph query %s', (queryName) => {
        const fields = getQueryFields();
        expect(fields[queryName]).toBeDefined();
    });
});
