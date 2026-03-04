
import { driver, auth } from 'neo4j-driver';

// Use env vars if available, otherwise default to local
const URI = process.env.NEO4J_URI || 'neo4j://localhost:7687';
const USER = process.env.NEO4J_USER || 'neo4j';
const PASS = process.env.NEO4J_PASSWORD || 'rinjani1';

console.log(`Connecting to ${URI} as ${USER}...`);

const d = driver(URI, auth.basic(USER, PASS));

async function debugContent() {
    const session = d.session();
    try {
        console.log('--- Checking Total Counts ---');
        const countRes = await session.run('MATCH (n) RETURN count(n) as count');
        console.log('Total Nodes:', countRes.records[0].get('count').toString());

        console.log('\n--- Searching for "Cobalt Strike" (Exact) ---');
        const exactRes = await session.run(`
            MATCH (n) 
            WHERE toLower(n.name) = 'cobalt strike' 
               OR toLower(n.value) = 'cobalt strike'
            RETURN labels(n) as labels, n.name as name, n.stixId as stixId, n.elementId as id
        `);

        if (exactRes.records.length === 0) {
            console.log('No exact match found.');

            console.log('\n--- Searching for "Cobalt Strike" (Contains) ---');
            const fuzzyRes = await session.run(`
                MATCH (n) 
                WHERE toLower(n.name) CONTAINS 'cobalt strike'
                RETURN labels(n) as labels, n.name as name, n.stixId as stixId
                LIMIT 5
            `);

            if (fuzzyRes.records.length === 0) {
                console.log('No partial match found either.');
            } else {
                console.log('Found partial matches:', fuzzyRes.records.map(r => r.toObject()));
            }

        } else {
            console.log('Found exact match:', exactRes.records.map(r => r.toObject()));

            console.log('\n--- Checking Relationships for Cobalt Strike ---');
            const relRes = await session.run(`
                MATCH (n)-[r]-(m)
                WHERE toLower(n.name) = 'cobalt strike' 
                   OR n.name = 'Cobalt Strike'
                   OR n.value = 'Cobalt Strike'
                RETURN type(r) as type, labels(m) as neighborLabels, m.name as neighborName
                LIMIT 5
            `);
            console.log('Relationships found:', relRes.records.length);
            relRes.records.forEach(r => console.log(r.toObject()));
        }


        console.log('\n--- Testing Backend Cypher Query ---');
        const id = 'Cobalt Strike';
        const limit = 100;
        const query = `
            MATCH (start)
            WHERE start.stixId = $id
               OR start.mitreId = $id
               OR start.cveId = $id
               OR start.otxId = $id
               OR start.pgId = $id
               OR start.value = $id
               OR toLower(start.name) = toLower($id)
            WITH start LIMIT 1
            CALL {
                WITH start
                MATCH path = (start)-[*1..1]-(connected)
                RETURN path
                LIMIT $limit
            }
            WITH start, path
            UNWIND nodes(path) AS n
            UNWIND relationships(path) AS r
            WITH collect(DISTINCT n) AS allNodes, collect(DISTINCT r) AS allRels
            RETURN allNodes, allRels
        `;

        const cypherRes = await session.run(query, { id, limit: apiIntFixed(limit) });
        console.log('Backend Query Result Rows:', cypherRes.records.length);
        if (cypherRes.records.length > 0) {
            const row = cypherRes.records[0];
            const nodes = row.get('allNodes');
            const rels = row.get('allRels');
            console.log(`Returned Nodes: ${nodes ? nodes.length : 0}`);
            console.log(`Returned Rels: ${rels ? rels.length : 0}`);
        }

    } catch (err) {
        console.error('Query failed:', err);
    } finally {
        await session.close();
        await d.close();
    }
}

// Mock neo4j.int
function apiInt(n: number) {
    const { int } = require('neo4j-driver');
    return int(n);
}

// In ESM we might not have require, so let's try to get it from the top import if possible or just use BigInt if the driver supports it
// or just re-import using dynamic import
import { int } from 'neo4j-driver';

function apiIntFixed(n: number) {
    return int(n);
}

debugContent();
