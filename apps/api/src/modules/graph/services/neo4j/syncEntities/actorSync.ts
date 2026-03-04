/**
 * Neo4j Sync — Actors
 */

import { db } from '@rinjani/db';
import { threatActors } from '@rinjani/db/schema';
import { getNeo4jDriver } from '../driver';
import { createLogger } from '../../../../../lib/logger';

const log = createLogger('Neo4j');

export async function syncActors(onProgress?: (pct: number) => void): Promise<number> {
    const rows = await db.select({
        id: threatActors.id,
        stixId: threatActors.stixId,
        name: threatActors.name,
        aliases: threatActors.aliases,
        sophistication: threatActors.sophistication,
        origin: threatActors.primaryMotivation,
        description: threatActors.description,
    }).from(threatActors);

    if (rows.length === 0) return 0;

    const driver = getNeo4jDriver();
    const session = driver.session();
    try {
        const batch = rows.map(r => ({
            pgId: r.id,
            stixId: r.stixId,
            mitreId: (r.stixId || '').replace('mitre--', ''),
            name: r.name,
            aliases: r.aliases || [],
            sophistication: r.sophistication || 'unknown',
            origin: r.origin || 'unknown',
            description: (r.description || '').slice(0, 500),
        }));

        await session.run(`
            UNWIND $batch AS row
            MERGE (a:Actor {stixId: row.stixId})
            SET a.pgId = row.pgId,
                a.mitreId = row.mitreId,
                a.name = row.name,
                a.aliases = row.aliases,
                a.sophistication = row.sophistication,
                a.origin = row.origin,
                a.description = row.description,
                a.syncedAt = datetime()
        `, { batch });

        onProgress?.(100);
        log.info('Actors synced', { count: batch.length });
        return batch.length;
    } finally {
        await session.close();
    }
}
