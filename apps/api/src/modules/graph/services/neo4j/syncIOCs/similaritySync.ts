/**
 * Neo4j Sync — Embedding Similarity Links (IOC ↔ IOC via OpenSearch k-NN)
 */

import neo4j from 'neo4j-driver';
import { getNeo4jDriver } from '../driver';
import { createLogger } from '../../../../../lib/logger';

const log = createLogger('Neo4j');

export async function syncSimilarIOCs(
    maxIOCs: number = 500,
    minScore: number = 0.75,
    topK: number = 5,
): Promise<number> {
    const driver = getNeo4jDriver();

    const session = driver.session();
    try {
        const iocResult = await session.run(`
            MATCH (i:IOC)
            WHERE i.pgId IS NOT NULL
            OPTIONAL MATCH (i)-[:FOUND_IN]->(p:Pulse)
            RETURN i.pgId AS pgId, i.value AS value, i.type AS type,
                   count(p) AS pulseCount
            ORDER BY pulseCount DESC, i.pgId
            LIMIT $limit
        `, { limit: neo4j.int(maxIOCs) });

        const iocNodes = iocResult.records.map(r => ({
            pgId: neo4j.integer.toNumber(r.get('pgId') ?? 0),
            value: r.get('value') as string,
            type: r.get('type') as string,
        }));

        if (iocNodes.length === 0) {
            log.info('No IOC nodes found for similarity linking');
            return 0;
        }

        log.info('Computing similarity links', { iocCount: iocNodes.length, minScore, topK });

        const { findSimilar } = await import('../../opensearch');

        const similarityEdges: Array<{ srcId: number; tgtId: number; score: number }> = [];
        let processed = 0;
        const seenPairs = new Set<string>();

        for (const ioc of iocNodes) {
            try {
                const osDocId = `ioc-${ioc.pgId}`;
                const result = await findSimilar(osDocId, topK, 'ioc');

                for (const item of result.items) {
                    const score = item._score as number;
                    if (score < minScore) continue;

                    const tgtPgId = item.id as number;
                    if (!tgtPgId || tgtPgId === ioc.pgId) continue;

                    const pairKey = [Math.min(ioc.pgId, tgtPgId), Math.max(ioc.pgId, tgtPgId)].join('-');
                    if (seenPairs.has(pairKey)) continue;
                    seenPairs.add(pairKey);

                    similarityEdges.push({ srcId: ioc.pgId, tgtId: tgtPgId, score });
                }
            } catch {
                // Skip IOCs not found in OpenSearch
            }

            processed++;
            if (processed % 100 === 0) {
                log.info('Similarity progress', { processed, total: iocNodes.length, edgesFound: similarityEdges.length });
            }
        }

        if (similarityEdges.length === 0) {
            log.info('No similarity edges found above threshold');
            return 0;
        }

        const BATCH_SIZE = 500;
        for (let i = 0; i < similarityEdges.length; i += BATCH_SIZE) {
            const batch = similarityEdges.slice(i, i + BATCH_SIZE);
            await session.run(`
                UNWIND $batch AS row
                MATCH (src:IOC {pgId: row.srcId})
                MATCH (tgt:IOC {pgId: row.tgtId})
                MERGE (src)-[r:SIMILAR_TO]-(tgt)
                SET r.score = row.score,
                    r.syncedAt = datetime()
            `, { batch });
        }

        log.info('SIMILAR_TO edges created', { count: similarityEdges.length });
        return similarityEdges.length;
    } finally {
        await session.close();
    }
}
