/**
 * Neo4j Sync — Campaigns → Campaign nodes + IOC/WebSource edges
 */

import { db, inArray } from '@rinjani/db';
import {
    campaigns, campaignIndicators, webIntelItems, webIntelMentions,
} from '@rinjani/db/schema';
import { getNeo4jDriver } from '../driver';
import { createLogger } from '../../../lib/logger';

const log = createLogger('Neo4j');

/**
 * Sync campaigns and their indicators into the Neo4j graph.
 *
 * Creates:
 *   (:Campaign) — one per campaign
 *   (:WebSource)-[:PART_OF_CAMPAIGN]->(:Campaign) — items linked to campaign
 *   (:IOC)-[:PART_OF_CAMPAIGN]->(:Campaign) — IOCs linked via mentions
 */
export async function syncCampaignsToNeo4j(): Promise<{ campaigns: number; links: number }> {
    const driver = getNeo4jDriver();

    const campaignRows = await db.select({
        id: campaigns.id,
        name: campaigns.name,
        description: campaigns.description,
        status: campaigns.status,
        severity: campaigns.severity,
        firstSeen: campaigns.firstSeen,
        lastSeen: campaigns.lastSeen,
        indicatorCount: campaigns.indicatorCount,
    }).from(campaigns);

    if (campaignRows.length === 0) return { campaigns: 0, links: 0 };

    const session = driver.session();
    try {
        await session.run(`
            UNWIND $batch AS row
            MERGE (c:Campaign {pgId: row.id})
            SET c.name = row.name,
                c.description = coalesce(row.description, ''),
                c.status = coalesce(row.status, 'active'),
                c.severity = coalesce(row.severity, 'unknown'),
                c.firstSeen = row.firstSeen,
                c.lastSeen = row.lastSeen,
                c.indicatorCount = coalesce(row.indicatorCount, 0),
                c.syncedAt = datetime()
        `, {
            batch: campaignRows.map(r => ({
                id: r.id,
                name: r.name,
                description: (r.description || '').slice(0, 500),
                status: r.status,
                severity: r.severity || 'unknown',
                firstSeen: r.firstSeen ? r.firstSeen.toISOString() : null,
                lastSeen: r.lastSeen ? r.lastSeen.toISOString() : null,
                indicatorCount: r.indicatorCount || 0,
            }))
        });

        const campaignIds = campaignRows.map(c => c.id);
        const indicators = await db.select({
            campaignId: campaignIndicators.campaignId,
            itemId: campaignIndicators.itemId,
            mentionId: campaignIndicators.mentionId,
        }).from(campaignIndicators)
            .where(inArray(campaignIndicators.campaignId, campaignIds));

        let links = 0;

        // Link WebSource items → Campaign
        const itemLinks = indicators
            .filter(i => i.itemId)
            .map(i => ({ campaignId: i.campaignId, itemId: i.itemId! }));

        if (itemLinks.length > 0) {
            const linkedItemIds = [...new Set(itemLinks.map(l => l.itemId))];
            const linkedItems = await db.select({
                id: webIntelItems.id,
                exaItemId: webIntelItems.exaItemId,
            }).from(webIntelItems)
                .where(inArray(webIntelItems.id, linkedItemIds));

            const idToExa = new Map(linkedItems.map(i => [i.id, i.exaItemId]));

            const batch = itemLinks
                .filter(l => idToExa.has(l.itemId))
                .map(l => ({
                    campaignId: l.campaignId,
                    sourceItemId: idToExa.get(l.itemId)!,
                }));

            if (batch.length > 0) {
                await session.run(`
                    UNWIND $batch AS row
                    MATCH (w:WebSource {itemId: row.sourceItemId})
                    MATCH (c:Campaign {pgId: row.campaignId})
                    MERGE (w)-[:PART_OF_CAMPAIGN]->(c)
                `, { batch });
                links += batch.length;
            }
        }

        // Link IOCs (via mentions) → Campaign
        const mentionLinks = indicators
            .filter(i => i.mentionId)
            .map(i => ({ campaignId: i.campaignId, mentionId: i.mentionId! }));

        if (mentionLinks.length > 0) {
            const linkedMentionIds = [...new Set(mentionLinks.map(l => l.mentionId))];
            const linkedMentions = await db.select({
                id: webIntelMentions.id,
                value: webIntelMentions.value,
            }).from(webIntelMentions)
                .where(inArray(webIntelMentions.id, linkedMentionIds));

            const mentionIdToValue = new Map(linkedMentions.map(m => [m.id, m.value]));

            const batch = mentionLinks
                .filter(l => mentionIdToValue.has(l.mentionId))
                .map(l => ({
                    campaignId: l.campaignId,
                    iocValue: mentionIdToValue.get(l.mentionId)!,
                }));

            if (batch.length > 0) {
                await session.run(`
                    UNWIND $batch AS row
                    MATCH (i:IOC) WHERE i.value = row.iocValue
                    MATCH (c:Campaign {pgId: row.campaignId})
                    MERGE (i)-[:PART_OF_CAMPAIGN]->(c)
                `, { batch });
                links += batch.length;
            }
        }

        log.info('Campaign nodes synced', { campaigns: campaignRows.length, links });
        return { campaigns: campaignRows.length, links };
    } finally {
        await session.close();
    }
}
