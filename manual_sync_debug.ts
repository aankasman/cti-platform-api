
require('ts-node').register();
const { db } = require('@rinjani/db');
const { iocs } = require('@rinjani/db/schema');
const { eq } = require('drizzle-orm');
const neo4jService = require('./apps/api/src/services/neo4j.ts');

async function manualSync() {
    console.log('Starting manual sync for 8.8.8.8 and recent IOCs...');

    // 1. Get 8.8.8.8 specifically
    const targetIOCs = await db.select().from(iocs).where(eq(iocs.value, '8.8.8.8')).limit(1);

    if (targetIOCs.length === 0) {
        console.log('8.8.8.8 not found in DB! Creating it for testing...');
        // Insert it if missing
        const [newIoc] = await db.insert(iocs).values({
            value: '8.8.8.8',
            type: 'ip',
            threatType: 'malware_hosting',
            severity: 'high',
            confidence: 90,
            tlp: 'white'
        }).returning();
        targetIOCs.push(newIoc);
    }

    console.log(`Syncing ${targetIOCs.length} specific IOCs to Neo4j...`);

    const driver = neo4jService.getNeo4jDriver();
    const session = driver.session();

    try {
        await session.run(`
            UNWIND $batch AS row
            MERGE (i:IOC {pgId: row.id})
            SET i.value = row.value,
                i.type = row.type,
                i.threatType = coalesce(row.threatType, 'unknown'),
                i.severity = coalesce(row.severity, 'unknown'),
                i.syncedAt = datetime()
        `, {
            batch: targetIOCs.map(r => ({
                id: r.id,
                value: r.value,
                type: r.type,
                threatType: r.threatType || 'unknown',
                severity: r.severity || 'unknown',
            }))
        });
        console.log('Successfully synced 8.8.8.8 to Neo4j');

        // Verify
        const result = await session.run(`MATCH (n:IOC {value: '8.8.8.8'}) RETURN n`);
        console.log('Verification result:', result.records.length > 0 ? 'Found in Graph' : 'NOT Found');

    } catch (err) {
        console.error('Sync failed:', err);
    } finally {
        await session.close();
        await neo4jService.closeNeo4j();
        process.exit(0);
    }
}

manualSync();
