/**
 * Web Search Worker — Fan-out Persistence
 *
 * Handles partial-failure-safe writes to OpenSearch and Neo4j.
 */

import { createLogger } from '../lib/logger';
import { sendToDeadLetterQueue } from '../lib/errors';
import { getOpenSearchClient } from '../services/opensearch';
import type { WebSearchResult } from '../lib/schemas';

/**
 * Persist search results to OpenSearch and Neo4j (partial failure safe).
 */
export async function persistResults(
    result: WebSearchResult,
    correlationId: string,
    query: string,
    jobId: string,
    jobLog: ReturnType<typeof createLogger>,
): Promise<{ opensearch: boolean; neo4j: boolean }> {
    const persistenceResults = { opensearch: false, neo4j: false };

    // OpenSearch write
    try {
        const osClient = getOpenSearchClient();
        const body = result.items.flatMap((item, idx) => [
            { index: { _index: 'rinjani-web-search', _id: `ws-${correlationId}-${idx}` } },
            {
                ...item,
                query,
                correlationId,
                entityType: 'web-search-result',
                indexedAt: new Date().toISOString(),
            },
        ]);
        await osClient.bulk({ body, refresh: false });
        persistenceResults.opensearch = true;
        jobLog.info('OpenSearch write succeeded', { documentCount: result.items.length });
    } catch (err) {
        jobLog.error('OpenSearch write failed (non-fatal)', err);
        await sendToDeadLetterQueue({
            queue: 'web-search',
            jobId,
            error: err instanceof Error ? err.message : String(err),
            payload: { target: 'opensearch', correlationId, query },
            failedAt: new Date().toISOString(),
            partialResults: { itemCount: result.items.length },
        });
    }

    // Neo4j write
    try {
        const { getNeo4jDriver } = await import('../services/neo4j');
        const driver = getNeo4jDriver();
        const session = driver.session();
        try {
            const batch = result.items.map((item, idx) => ({
                itemId: `ws-${correlationId}-${idx}`,
                title: item.title,
                url: item.url,
                snippet: (item.snippet || '').slice(0, 500),
                source: item.source || 'searxng',
                query,
            }));

            await session.run(`
                UNWIND $batch AS row
                MERGE (w:WebSource {itemId: row.itemId})
                SET w.title = row.title,
                    w.url = row.url,
                    w.snippet = row.snippet,
                    w.source = row.source,
                    w.query = row.query,
                    w.syncedAt = datetime()
            `, { batch });

            persistenceResults.neo4j = true;
            jobLog.info('Neo4j write succeeded', { nodeCount: batch.length });
        } finally {
            await session.close();
        }
    } catch (err) {
        jobLog.error('Neo4j write failed (non-fatal)', err);
        await sendToDeadLetterQueue({
            queue: 'web-search',
            jobId,
            error: err instanceof Error ? err.message : String(err),
            payload: { target: 'neo4j', correlationId, query },
            failedAt: new Date().toISOString(),
            partialResults: { itemCount: result.items.length },
        });
    }

    return persistenceResults;
}
