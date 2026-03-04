/**
 * Neo4j Sync — Tools
 */

import { db } from '@rinjani/db';
import { mitreTools } from '@rinjani/db/schema';
import { getNeo4jDriver } from '../driver';
import { createLogger } from '../../../lib/logger';

const log = createLogger('Neo4j');

export async function syncTools(): Promise<number> {
    const rows = await db.select({
        id: mitreTools.id,
        mitreId: mitreTools.mitreId,
        name: mitreTools.name,
        aliases: mitreTools.aliases,
        platforms: mitreTools.platforms,
        type: mitreTools.type,
    }).from(mitreTools);

    if (rows.length === 0) return 0;

    const driver = getNeo4jDriver();
    const session = driver.session();
    try {
        await session.run(`
            UNWIND $batch AS row
            MERGE (t:Tool {mitreId: row.mitreId})
            SET t.pgId = row.id,
                t.name = row.name,
                t.aliases = coalesce(row.aliases, []),
                t.platforms = coalesce(row.platforms, []),
                t.type = coalesce(row.type, 'unknown'),
                t.syncedAt = datetime()
        `, {
            batch: rows.map(r => ({
                id: r.id,
                mitreId: r.mitreId || r.id,
                name: r.name,
                aliases: r.aliases || [],
                platforms: r.platforms || [],
                type: r.type || 'unknown',
            }))
        });

        log.info('Tools synced', { count: rows.length });
        return rows.length;
    } finally {
        await session.close();
    }
}
