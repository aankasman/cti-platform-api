import { getNeo4jDriver } from './apps/api/src/services/neo4j';
import { config } from 'dotenv';
config();

async function run() {
    const driver = getNeo4jDriver();
    const session = driver.session();
    try {
        const res1 = await session.run('MATCH (w:WebSource) RETURN count(w) as c');
        console.log('WebSources:', res1.records[0].get('c').toNumber());
        const res2 = await session.run('MATCH (i:IOC) RETURN count(i) as c');
        console.log('IOCs:', res2.records[0].get('c').toNumber());
        const res3 = await session.run('MATCH ()-[r:MENTIONED_IN]->() RETURN count(r) as c');
        console.log('MENTIONED_IN relations:', res3.records[0].get('c').toNumber());
    } finally {
        await session.close();
        await driver.close();
    }
}
run().catch(console.error);
