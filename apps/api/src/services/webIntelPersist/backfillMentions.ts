/**
 * Web Intelligence — IOC Mention Backfill
 *
 * Retroactively extracts IOCs from existing web_intel_items,
 * populates web_intel_mentions, and creates Neo4j IOC nodes +
 * MENTIONED_IN edges for campaign detection.
 */

import { db, sql } from '@rinjani/db';
import { webIntelItems } from '@rinjani/db/schema';
import { extractIOCs } from '../iocExtractor';
import { getNeo4jDriver } from '../neo4j';
import { createLogger } from '../../lib/logger';

const log = createLogger('WebIntel:Backfill');

export interface BackfillResult {
    itemsProcessed: number;
    mentionsCreated: number;
    iocNodesCreated: number;
    edgesCreated: number;
    byType: Record<string, number>;
}

/**
 * Extract IOCs from all web_intel_items that have textContent,
 * save mentions to PG, create IOC nodes + MENTIONED_IN edges in Neo4j.
 */
export async function backfillMentions(
    batchSize: number = 50,
): Promise<BackfillResult> {
    log.info('Starting IOC mention backfill');

    // Count items with text content
    const countResult = await db.execute(
        sql`SELECT COUNT(*) as total FROM web_intel_items WHERE text_content IS NOT NULL AND text_content != ''`
    );
    const rows = Array.isArray(countResult) ? countResult : [];
    const totalItems = Number(rows[0]?.total || 0);

    if (totalItems === 0) {
        log.info('No web intel items with text content found');
        return { itemsProcessed: 0, mentionsCreated: 0, iocNodesCreated: 0, edgesCreated: 0, byType: {} };
    }

    log.info('Items to process', { total: totalItems });

    const driver = getNeo4jDriver();
    const session = driver.session();
    let itemsProcessed = 0;
    let mentionsCreated = 0;
    let iocNodesCreated = 0;
    let edgesCreated = 0;
    const globalByType: Record<string, number> = {};

    try {
        for (let offset = 0; offset < totalItems; offset += batchSize) {
            const items = await db.select({
                id: webIntelItems.id,
                title: webIntelItems.title,
                textContent: webIntelItems.textContent,
            }).from(webIntelItems)
                .where(sql`${webIntelItems.textContent} IS NOT NULL AND ${webIntelItems.textContent} != ''`)
                .limit(batchSize)
                .offset(offset);

            if (items.length === 0) break;

            for (const item of items) {
                const text = [
                    item.title || '',
                    item.textContent || '',
                ].join('\n');

                const result = extractIOCs(text);
                if (result.iocs.length === 0) continue;

                // 1. Insert IOC mentions into PG (skip duplicates)
                for (const ioc of result.iocs) {
                    try {
                        await db.execute(sql`
                            INSERT INTO web_intel_mentions (item_id, type, value, canonical_id, confidence, context)
                            VALUES (${item.id}, ${ioc.type}, ${ioc.value}, ${ioc.canonicalId}, ${ioc.confidence}, ${(ioc.context || '').slice(0, 500)})
                            ON CONFLICT DO NOTHING
                        `);
                        mentionsCreated++;
                    } catch {
                        // duplicate — skip
                    }
                }

                // 2. Create IOC nodes in Neo4j for extracted values
                const iocBatch = result.iocs.map(ioc => ({
                    id: ioc.canonicalId,
                    value: ioc.value,
                    type: ioc.type,
                    confidence: ioc.confidence,
                }));

                await session.run(`
                    UNWIND $batch AS row
                    MERGE (i:IOC {value: row.value})
                    ON CREATE SET
                        i.pgId = row.id,
                        i.type = row.type,
                        i.confidence = row.confidence,
                        i.source = 'extracted',
                        i.syncedAt = datetime()
                `, { batch: iocBatch });
                iocNodesCreated += iocBatch.length;

                // 3. Create MENTIONED_IN edges (WebSource → IOC)
                const edgeBatch = result.iocs.map(ioc => ({
                    webSourcePgId: item.id,
                    iocValue: ioc.value,
                    iocType: ioc.type,
                    confidence: ioc.confidence,
                }));

                const edgeResult = await session.run(`
                    UNWIND $batch AS row
                    MATCH (w:WebSource {pgId: row.webSourcePgId})
                    MATCH (i:IOC {value: row.iocValue})
                    MERGE (w)-[r:MENTIONED_IN]->(i)
                    SET r.confidence = row.confidence,
                        r.iocType = row.iocType,
                        r.syncedAt = datetime()
                    RETURN count(r) as created
                `, { batch: edgeBatch });

                const batchEdges = edgeResult.records[0]?.get('created')?.toNumber?.() ?? 0;
                edgesCreated += batchEdges;

                // Aggregate stats
                for (const [type, count] of Object.entries(result.stats.byType)) {
                    globalByType[type] = (globalByType[type] || 0) + count;
                }

                itemsProcessed++;
            }

            // Mark items as extracted
            const itemIds = items.map(i => i.id);
            await db.update(webIntelItems)
                .set({ iocExtracted: true, updatedAt: new Date() })
                .where(sql`${webIntelItems.id} IN (${sql.join(itemIds.map(id => sql`${id}`), sql`, `)})`);

            log.info('Batch complete', {
                processed: itemsProcessed,
                total: totalItems,
                mentionsSoFar: mentionsCreated,
                edgesSoFar: edgesCreated,
            });
        }
    } finally {
        await session.close();
    }

    log.info('Backfill complete', { itemsProcessed, mentionsCreated, iocNodesCreated, edgesCreated, byType: globalByType });
    return { itemsProcessed, mentionsCreated, iocNodesCreated, edgesCreated, byType: globalByType };
}
