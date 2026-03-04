/**
 * Web Intelligence Persistence — Background Post-Save Processing
 *
 * Called by BullMQ worker after saveScrapeResult completes.
 * Generates embeddings, indexes to OpenSearch, syncs to Neo4j.
 */

import { db, eq } from '@rinjani/db';
import { webIntelItems, webIntelMentions } from '@rinjani/db/schema';
import { generateEmbedding } from '../embedding';
import { getOpenSearchClient } from '../opensearch';
import { getNeo4jDriver } from '../neo4j';
import { createLogger } from '../../../../lib/logger';

const log = createLogger('WebIntelPersist:postSave');

/**
 * Process a saved scrape result: generate embeddings, index to OpenSearch,
 * sync to Neo4j graph.
 */
export async function processPostSave(itemId: string): Promise<void> {
    log.info('Processing item', { itemId });

    // 1. Fetch the item from Postgres
    const [item] = await db.select()
        .from(webIntelItems)
        .where(eq(webIntelItems.id, itemId))
        .limit(1);

    if (!item) {
        log.error('Item not found', new Error(`Item ${itemId} not found`));
        return;
    }

    // 2. Generate embedding and index to OpenSearch
    try {
        const embeddingText = [
            item.title || '',
            item.aiSummary || item.summary || '',
            item.textContent?.slice(0, 400) || '',
        ].filter(Boolean).join('. ');

        if (embeddingText.trim()) {
            const embedding = await generateEmbedding(embeddingText);
            const osClient = getOpenSearchClient();

            await osClient.index({
                index: 'rinjani-unified',
                id: `webintel-${itemId}`,
                body: {
                    id: itemId,
                    entityType: 'web-intel',
                    type: 'osint-scrape',
                    value: item.url || '',
                    title: item.title || '',
                    description: item.aiSummary || item.summary || '',
                    severity: item.severity || 'medium',
                    source: 'searxng',
                    tags: Object.keys((item.extractedEntities as Record<string, string[]>) || {}),
                    createdAt: item.createdAt?.toISOString(),
                    updatedAt: item.updatedAt?.toISOString(),
                    url: item.url,
                    platform: item.platform,
                    sourceProvider: item.sourceProvider,
                    aiSummary: item.aiSummary,
                    extractedEntities: item.extractedEntities,
                    embedding,
                },
                refresh: true,
            });

            await db.update(webIntelItems)
                .set({ embeddingGenerated: true })
                .where(eq(webIntelItems.id, itemId));

            log.info('Indexed to OpenSearch', { documentId: `webintel-${itemId}` });
        }
    } catch (err) {
        log.warn('OpenSearch indexing failed', { error: (err as Error).message });
    }

    // 3. Sync to Neo4j — create :WebSource node + edges
    try {
        const driver = getNeo4jDriver();
        const session = driver.session();

        try {
            // Create WebSource node
            await session.run(`
                MERGE (w:WebSource {pgId: $id})
                SET w.title = $title,
                    w.url = $url,
                    w.category = 'osint-scrape',
                    w.platform = $platform,
                    w.sourceProvider = 'searxng',
                    w.aiSummary = $aiSummary,
                    w.syncedAt = datetime()
            `, {
                id: itemId,
                title: (item.title || '').slice(0, 500),
                url: item.url || '',
                platform: item.platform || 'unknown',
                aiSummary: (item.aiSummary || '').slice(0, 2000),
            });

            // Create MENTIONED_IN edges to existing IOCs
            const mentions = await db.select({
                type: webIntelMentions.type,
                value: webIntelMentions.value,
                confidence: webIntelMentions.confidence,
            })
                .from(webIntelMentions)
                .where(eq(webIntelMentions.itemId, itemId));

            if (mentions.length > 0) {
                await session.run(`
                    UNWIND $batch AS row
                    MATCH (w:WebSource {pgId: $itemId})
                    MATCH (i:IOC) WHERE i.value = row.value
                    MERGE (w)-[r:MENTIONED_IN]->(i)
                    SET r.confidence = row.confidence,
                        r.iocType = row.type,
                        r.syncedAt = datetime()
                `, {
                    itemId,
                    batch: mentions.map(m => ({
                        value: m.value,
                        type: m.type,
                        confidence: m.confidence ?? 80,
                    })),
                });
            }

            // Create edges to Actors from extracted entities
            const entities = (item.extractedEntities as Record<string, string[]>) || {};
            const actorNames = entities.threatActors || [];

            if (actorNames.length > 0) {
                await session.run(`
                    UNWIND $actors AS actorName
                    MATCH (w:WebSource {pgId: $itemId})
                    MATCH (a:Actor) WHERE toLower(a.name) = toLower(actorName)
                    MERGE (w)-[:DISCOVERED_BY]->(a)
                `, {
                    itemId,
                    actors: actorNames,
                });
            }

            // Create edges to Malware families from extracted entities
            const malwareNames = entities.malwareFamilies || [];

            if (malwareNames.length > 0) {
                await session.run(`
                    UNWIND $names AS malwareName
                    MATCH (w:WebSource {pgId: $itemId})
                    MERGE (m:Malware {name: malwareName})
                    MERGE (w)-[:REFERENCES]->(m)
                `, {
                    itemId,
                    names: malwareNames,
                });
            }

            await db.update(webIntelItems)
                .set({ neo4jSynced: true })
                .where(eq(webIntelItems.id, itemId));

            log.info('Neo4j synced', { itemId, iocEdges: mentions.length, actorEdges: actorNames.length, malwareEdges: malwareNames.length });
        } finally {
            await session.close();
        }
    } catch (err) {
        log.warn('Neo4j sync failed', { error: (err as Error).message });
    }
}
