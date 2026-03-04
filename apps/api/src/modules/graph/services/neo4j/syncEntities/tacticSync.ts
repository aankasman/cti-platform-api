/**
 * Neo4j Sync — Tactics
 */

import { db } from '@rinjani/db';
import { tactics } from '@rinjani/db/schema';
import { getNeo4jDriver } from '../driver';
import { createLogger } from '../../../../../lib/logger';

const log = createLogger('Neo4j');

export async function syncTactics(): Promise<number> {
    const rows = await db.select({
        id: tactics.id,
        mitreId: tactics.mitreId,
        name: tactics.name,
        shortName: tactics.shortName,
        description: tactics.description,
    }).from(tactics);

    if (rows.length === 0) return 0;

    const driver = getNeo4jDriver();
    const session = driver.session();
    try {
        await session.run(`
            UNWIND $batch AS row
            MERGE (t:Tactic {mitreId: row.mitreId})
            SET t.pgId = row.id,
                t.name = row.name,
                t.shortName = row.shortName,
                t.description = coalesce(row.description, ''),
                t.syncedAt = datetime()
        `, { batch: rows });

        log.info('Tactics synced', { count: rows.length });
        return rows.length;
    } finally {
        await session.close();
    }
}
