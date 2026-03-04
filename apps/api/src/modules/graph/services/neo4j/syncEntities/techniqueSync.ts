/**
 * Neo4j Sync — Techniques (+ BELONGS_TO Tactic, PARENT_OF sub-techniques)
 */

import { db } from '@rinjani/db';
import { techniques } from '@rinjani/db/schema';
import { getNeo4jDriver } from '../driver';
import { createLogger } from '../../../../../lib/logger';

const log = createLogger('Neo4j');

export async function syncTechniques(): Promise<number> {
    const rows = await db.select({
        id: techniques.id,
        mitreId: techniques.mitreId,
        name: techniques.name,
        platforms: techniques.platforms,
        isSubtechnique: techniques.isSubtechnique,
        parentId: techniques.parentId,
        tacticIds: techniques.tacticIds,
        description: techniques.description,
    }).from(techniques);

    if (rows.length === 0) return 0;

    const driver = getNeo4jDriver();
    const session = driver.session();
    try {
        await session.run(`
            UNWIND $batch AS row
            MERGE (t:Technique {mitreId: row.mitreId})
            SET t.pgId = row.id,
                t.name = row.name,
                t.platforms = coalesce(row.platforms, []),
                t.isSubtechnique = coalesce(row.isSubtechnique, false),
                t.description = coalesce(row.description, ''),
                t.syncedAt = datetime()
        `, {
            batch: rows.map(r => ({
                id: r.id,
                mitreId: r.mitreId,
                name: r.name,
                platforms: r.platforms || [],
                isSubtechnique: r.isSubtechnique || false,
                description: (r.description || '').slice(0, 500),
            }))
        });

        // BELONGS_TO tactic edges
        const techTactics: Array<{ techId: string; tacticId: string }> = [];
        for (const r of rows) {
            if (r.tacticIds && Array.isArray(r.tacticIds)) {
                for (const tid of r.tacticIds) {
                    techTactics.push({ techId: r.mitreId, tacticId: tid as string });
                }
            }
        }
        if (techTactics.length > 0) {
            await session.run(`
                UNWIND $batch AS row
                MATCH (tech:Technique {mitreId: row.techId})
                MATCH (tac:Tactic {mitreId: row.tacticId})
                MERGE (tech)-[:BELONGS_TO]->(tac)
            `, { batch: techTactics });
        }

        // PARENT_OF edges for sub-techniques
        const subTechs = rows
            .filter(r => r.isSubtechnique && r.parentId)
            .map(r => ({ childId: r.mitreId, parentId: r.parentId! }));
        if (subTechs.length > 0) {
            await session.run(`
                UNWIND $batch AS row
                MATCH (parent:Technique {mitreId: row.parentId})
                MATCH (child:Technique {mitreId: row.childId})
                MERGE (parent)-[:PARENT_OF]->(child)
            `, { batch: subTechs });
        }

        log.info('Techniques synced', { techniques: rows.length, tacticLinks: techTactics.length, parentLinks: subTechs.length });
        return rows.length;
    } finally {
        await session.close();
    }
}
