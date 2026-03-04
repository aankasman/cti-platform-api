/**
 * Neo4j Sync — Web Intelligence Items → WebSource nodes
 */

import { db, inArray } from '@rinjani/db';
import { webIntelItems, webIntelMentions } from '@rinjani/db/schema';
import { getNeo4jDriver } from '../driver';
import { createLogger } from '../../../lib/logger';

const log = createLogger('Neo4j');

/**
 * Sync web_intel_items + their IOC mentions into the Neo4j graph.
 *
 * Creates:
 *   (:WebSource) — one per web intel item
 *   (:WebSource)-[:MENTIONED_IN]->(:IOC) — IOC mention links
 *   (:WebSource)-[:DISCOVERED_BY]->(:Actor) — if actor name in enrichments
 */
export async function syncWebIntelToNeo4j(
    batchSize: number = 200,
    onProgress?: (pct: number) => void,
): Promise<{ sources: number; mentionLinks: number }> {
    const driver = getNeo4jDriver();

    const items = await db.select({
        id: webIntelItems.id,
        exaItemId: webIntelItems.exaItemId,
        category: webIntelItems.category,
        title: webIntelItems.title,
        url: webIntelItems.url,
        sourceUrl: webIntelItems.sourceUrl,
        platform: webIntelItems.platform,
        severity: webIntelItems.severity,
        author: webIntelItems.author,
        publishedAt: webIntelItems.publishedAt,
        enrichments: webIntelItems.enrichments,
    }).from(webIntelItems)
        .limit(batchSize);

    if (items.length === 0) return { sources: 0, mentionLinks: 0 };

    const session = driver.session();
    try {
        await session.run(`
            UNWIND $batch AS row
            MERGE (w:WebSource {itemId: row.itemId})
            SET w.pgId = row.id,
                w.title = coalesce(row.title, ''),
                w.url = coalesce(row.url, ''),
                w.sourceUrl = coalesce(row.sourceUrl, ''),
                w.category = coalesce(row.category, ''),
                w.platform = coalesce(row.platform, 'unknown'),
                w.severity = coalesce(row.severity, 'unknown'),
                w.author = coalesce(row.author, ''),
                w.publishedAt = row.publishedAt,
                w.syncedAt = datetime()
        `, {
            batch: items.map(r => ({
                id: r.id,
                itemId: r.exaItemId || `pg-${r.id}`,
                title: (r.title || '').slice(0, 500),
                url: r.url || '',
                sourceUrl: r.sourceUrl || '',
                category: r.category,
                platform: r.platform || 'unknown',
                severity: r.severity || 'unknown',
                author: r.author || '',
                publishedAt: r.publishedAt ? r.publishedAt.toISOString() : null,
            }))
        });

        onProgress?.(40);

        // IOC mentions
        const itemIds = items.map(i => i.id);
        const mentions = await db.select({
            itemId: webIntelMentions.itemId,
            type: webIntelMentions.type,
            value: webIntelMentions.value,
            confidence: webIntelMentions.confidence,
        }).from(webIntelMentions)
            .where(inArray(webIntelMentions.itemId, itemIds));

        if (mentions.length > 0) {
            const itemIdToExaId = new Map(items.map(i => [i.id, i.exaItemId || `pg-${i.id}`]));
            const mentionBatch = mentions
                .filter(m => itemIdToExaId.has(m.itemId))
                .map(m => ({
                    sourceItemId: itemIdToExaId.get(m.itemId)!,
                    iocValue: m.value,
                    iocType: m.type,
                    confidence: m.confidence ?? 0,
                }));

            if (mentionBatch.length > 0) {
                await session.run(`
                    UNWIND $batch AS row
                    MATCH (w:WebSource {itemId: row.sourceItemId})
                    MATCH (i:IOC) WHERE i.value = row.iocValue
                    MERGE (w)-[r:MENTIONED_IN]->(i)
                    SET r.confidence = row.confidence,
                        r.iocType = row.iocType,
                        r.syncedAt = datetime()
                `, { batch: mentionBatch });
            }
        }

        onProgress?.(70);

        // WebSource → Actor links
        const actorLinks: Array<{ sourceItemId: string; actorName: string }> = [];
        for (const item of items) {
            const enrichments = (item.enrichments || {}) as Record<string, unknown>;
            const actorName = enrichments.actorName || enrichments.threat_actor;
            if (actorName && typeof actorName === 'string') {
                actorLinks.push({
                    sourceItemId: item.exaItemId || `pg-${item.id}`,
                    actorName: actorName,
                });
            }
        }

        if (actorLinks.length > 0) {
            await session.run(`
                UNWIND $batch AS row
                MATCH (w:WebSource {itemId: row.sourceItemId})
                MATCH (a:Actor) WHERE toLower(a.name) = toLower(row.actorName)
                MERGE (w)-[:DISCOVERED_BY]->(a)
            `, { batch: actorLinks });
        }

        onProgress?.(90);

        await db.update(webIntelItems)
            .set({ neo4jSynced: true, updatedAt: new Date() })
            .where(inArray(webIntelItems.id, itemIds));

        onProgress?.(100);

        const mentionCount = mentions.length;
        log.info('WebSource nodes synced', { nodes: items.length, mentions: mentionCount, discoveredBy: actorLinks.length });
        return { sources: items.length, mentionLinks: mentionCount };
    } finally {
        await session.close();
    }
}
