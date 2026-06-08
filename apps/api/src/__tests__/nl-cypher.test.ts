/**
 * NL→Cypher safety guard + extractor tests.
 *
 * These are the lines of defense between user input and the Neo4j
 * driver; they MUST be tight.
 */
import { describe, it, expect } from 'vitest';
import { isReadOnlyCypher, __testing } from '../services/nlCypher';
import { NlCypherSchema } from '../lib/schemas';

const { extractCypher } = __testing;

describe('isReadOnlyCypher — accepts', () => {
    it('a plain MATCH ... RETURN', () => {
        expect(isReadOnlyCypher(`MATCH (a:Actor)-[:USES]->(m:Malware) RETURN a.name, m.name LIMIT 25`).ok).toBe(true);
    });

    it('a query starting with a `//` comment', () => {
        expect(isReadOnlyCypher(`// list APT28 malware\nMATCH (a:Actor {name:'APT28'})-[:USES]->(m:Malware) RETURN m LIMIT 10`).ok).toBe(true);
    });

    it('a property name that contains a write-keyword substring (DELETED_AT)', () => {
        // No word-boundary write keyword in this property name → must pass.
        expect(isReadOnlyCypher(`MATCH (n:IOC) WHERE n.deletedAt IS NULL RETURN n LIMIT 5`).ok).toBe(true);
    });

    it('a query using COUNT aggregation without LIMIT', () => {
        expect(isReadOnlyCypher(`MATCH (n:Actor) RETURN count(n)`).ok).toBe(true);
    });
});

describe('isReadOnlyCypher — rejects', () => {
    it('an explicit CREATE', () => {
        const r = isReadOnlyCypher(`CREATE (n:Actor {name:'evil'}) RETURN n`);
        expect(r.ok).toBe(false);
    });

    it('a sneaky MERGE inside a MATCH ... RETURN', () => {
        const r = isReadOnlyCypher(`MATCH (a:Actor) MERGE (a)-[:USES]->(m:Malware) RETURN a`);
        expect(r.ok).toBe(false);
    });

    it('a SET on a matched node', () => {
        const r = isReadOnlyCypher(`MATCH (n) SET n.evil=true RETURN n`);
        expect(r.ok).toBe(false);
    });

    it('a DELETE', () => {
        expect(isReadOnlyCypher(`MATCH (n) DELETE n`).ok).toBe(false);
    });

    it('a DETACH DELETE', () => {
        expect(isReadOnlyCypher(`MATCH (n) DETACH DELETE n`).ok).toBe(false);
    });

    it('a REMOVE property', () => {
        expect(isReadOnlyCypher(`MATCH (n) REMOVE n.tag RETURN n`).ok).toBe(false);
    });

    it('a DROP CONSTRAINT', () => {
        expect(isReadOnlyCypher(`DROP CONSTRAINT actor_unique`).ok).toBe(false);
    });

    it('a CALL apoc.create.relationship procedure', () => {
        const r = isReadOnlyCypher(`MATCH (a),(b) CALL apoc.create.relationship(a,'X',{},b) YIELD rel RETURN rel`);
        expect(r.ok).toBe(false);
    });

    it('a CALL dbms.security procedure', () => {
        const r = isReadOnlyCypher(`CALL dbms.security.createUser('bad','pwd')`);
        expect(r.ok).toBe(false);
    });

    it('an empty string', () => {
        expect(isReadOnlyCypher('').ok).toBe(false);
    });

    it('the LLM "unanswerable" sentinel', () => {
        expect(isReadOnlyCypher('// unanswerable').ok).toBe(false);
    });

    it('a query without MATCH or RETURN', () => {
        expect(isReadOnlyCypher(`WITH 1 AS x`).ok).toBe(false);
    });
});

describe('extractCypher', () => {
    it('strips a ```cypher fence', () => {
        const raw = '```cypher\nMATCH (n) RETURN n LIMIT 5\n```';
        expect(extractCypher(raw)).toBe('MATCH (n) RETURN n LIMIT 5');
    });

    it('strips a plain ``` fence', () => {
        expect(extractCypher('```\nMATCH (n) RETURN n\n```')).toBe('MATCH (n) RETURN n');
    });

    it('strips a "Cypher:" prose prefix', () => {
        expect(extractCypher('Cypher: MATCH (n) RETURN n')).toBe('MATCH (n) RETURN n');
    });

    it('strips a "Here is the query:" prose prefix', () => {
        expect(extractCypher('Here is the query: MATCH (n) RETURN n')).toBe('MATCH (n) RETURN n');
    });

    it('leaves a clean query untouched', () => {
        expect(extractCypher('MATCH (n) RETURN n LIMIT 25')).toBe('MATCH (n) RETURN n LIMIT 25');
    });
});

describe('NlCypherSchema', () => {
    it('requires a non-empty question', () => {
        expect(() => NlCypherSchema.parse({ question: '' })).toThrow();
    });

    it('defaults limit to 25', () => {
        const r = NlCypherSchema.parse({ question: 'show me apt28 malware' });
        expect(r.limit).toBe(25);
    });

    it('coerces string limit', () => {
        expect(NlCypherSchema.parse({ question: 'x', limit: '50' }).limit).toBe(50);
    });

    it('caps limit at 500', () => {
        expect(() => NlCypherSchema.parse({ question: 'x', limit: 1000 })).toThrow();
    });

    it('rejects unknown provider', () => {
        expect(() => NlCypherSchema.parse({ question: 'x', provider: 'gpt-4' })).toThrow();
    });
});
