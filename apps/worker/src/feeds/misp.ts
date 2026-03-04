/**
 * MISP Sync Worker
 * 
 * Fetches threat intelligence from MISP (Malware Information Sharing Platform).
 * https://www.misp-project.org/
 * 
 * API Key: Configured in .env (MISP_API_KEY)
 * Format: STIX 2.1
 * 
 * MISP provides community-driven threat intelligence including:
 * - IOCs (IPs, domains, URLs, hashes)
 * - Threat actors
 * - Campaigns
 * - Attack patterns
 */

import { db } from '@rinjani/db';
import { iocs, syncLogs } from '@rinjani/db/schema';

// =============================================================================
// Configuration
// =============================================================================

const MISP_URL = process.env.MISP_URL || 'https://misp.gsma.com';
const MISP_API_KEY = process.env.MISP_API_KEY || '';
const BATCH_SIZE = 100;
const DAYS_TO_SYNC = 7; // Sync events from last 7 days

// =============================================================================
// Types
// =============================================================================

interface MISPEvent {
    Event: {
        id: string;
        info: string;
        threat_level_id: string;
        published: boolean;
        date: string;
        Attribute: MISPAttribute[];
        Tag?: Array<{ name: string }>;
    };
}

interface MISPAttribute {
    id: string;
    type: string;
    category: string;
    value: string;
    comment: string;
    to_ids: boolean;
    timestamp: string;
}

interface SyncResult {
    processed: number;
    failed: number;
    errors: string[];
}

// =============================================================================
// API Functions
// =============================================================================

async function fetchRecentEvents(): Promise<MISPEvent[]> {
    if (!MISP_API_KEY) {
        throw new Error('MISP API key not configured');
    }

    // Calculate date range
    const toDate = new Date();
    const fromDate = new Date();
    fromDate.setDate(fromDate.getDate() - DAYS_TO_SYNC);

    const searchParams = {
        returnFormat: 'json',
        published: true,
        to_ids: true, // Only IOCs marked for detection
        from: fromDate.toISOString().split('T')[0],
        to: toDate.toISOString().split('T')[0],
    };

    const response = await fetch(`${MISP_URL}/events/restSearch`, {
        method: 'POST',
        headers: {
            'Authorization': MISP_API_KEY,
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(searchParams),
    });

    if (!response.ok) {
        throw new Error(`MISP API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json() as { response?: MISPEvent[] };
    return data.response || [];
}

// Map MISP attribute types to our IOC types
function mapMISPType(mispType: string): string {
    const typeMap: Record<string, string> = {
        'ip-src': 'ip',
        'ip-dst': 'ip',
        'domain': 'domain',
        'hostname': 'domain',
        'url': 'url',
        'md5': 'hash',
        'sha1': 'hash',
        'sha256': 'hash',
        'sha512': 'hash',
    };
    return typeMap[mispType] || 'unknown';
}

// Map MISP threat level to severity
function mapThreatLevel(levelId: string): string {
    const levelMap: Record<string, string> = {
        '1': 'high',    // High
        '2': 'medium',  // Medium
        '3': 'low',     // Low
        '4': 'low',     // Undefined
    };
    return levelMap[levelId] || 'medium';
}

// =============================================================================
// Sync Functions
// =============================================================================

export async function syncMISP(): Promise<SyncResult> {
    console.log('[MISP] Starting sync...');
    console.log(`[MISP] URL: ${MISP_URL}`);

    if (!MISP_API_KEY) {
        console.warn('[MISP] ⚠️  No API key configured');
        console.warn('[MISP] Set MISP_API_KEY in .env to enable sync');
        return { processed: 0, failed: 0, errors: ['No API key configured'] };
    }

    const result: SyncResult = { processed: 0, failed: 0, errors: [] };

    try {
        console.log(`[MISP] Fetching events from last ${DAYS_TO_SYNC} days...`);
        const events = await fetchRecentEvents();
        console.log(`[MISP] Fetched ${events.length} events`);

        // Process all attributes from all events
        const iocBatch: any[] = [];
        let totalAttributes = 0;

        for (const eventData of events) {
            const event = eventData.Event;

            if (!event.Attribute || event.Attribute.length === 0) {
                continue;
            }

            totalAttributes += event.Attribute.length;

            for (const attr of event.Attribute) {
                try {
                    // Skip if not marked for IDS
                    if (!attr.to_ids) {
                        continue;
                    }

                    const iocType = mapMISPType(attr.type);

                    // Skip unknown types
                    if (iocType === 'unknown') {
                        continue;
                    }

                    const severity = mapThreatLevel(event.threat_level_id);

                    // Extract tags
                    const tags = event.Tag?.map(t => t.name) || [];

                    const iocRecord = {
                        type: iocType,
                        value: attr.value,
                        source: 'misp',
                        threatType: attr.category.toLowerCase(),
                        confidence: event.published ? 90 : 70,
                        severity: severity,
                        firstSeen: new Date(event.date),
                        lastSeen: new Date(parseInt(attr.timestamp) * 1000),
                        tags: [
                            'misp',
                            attr.type,
                            attr.category,
                            ...tags,
                        ],
                        metadata: {
                            misp_event_id: event.id,
                            misp_event_info: event.info,
                            misp_attribute_id: attr.id,
                            comment: attr.comment,
                            category: attr.category,
                            published: event.published,
                        },
                    };

                    iocBatch.push(iocRecord);

                    // Batch insert when batch is full
                    if (iocBatch.length >= BATCH_SIZE) {
                        await insertBatch(iocBatch, result);
                        iocBatch.length = 0; // Clear batch
                    }
                } catch (attrError) {
                    result.failed++;
                    const errorMsg = attrError instanceof Error ? attrError.message : String(attrError);
                    if (result.errors.length < 10) {
                        result.errors.push(`Attribute ${attr.id}: ${errorMsg}`);
                    }
                }
            }
        }

        // Insert remaining IOCs
        if (iocBatch.length > 0) {
            await insertBatch(iocBatch, result);
        }

        console.log(`[MISP] Processed ${totalAttributes} attributes from ${events.length} events`);

    } catch (error) {
        console.error('[MISP] Error fetching events:', error);
        const errorMsg = error instanceof Error ? error.message : (error as Error).message;
        result.errors.push(`Fetch error: ${errorMsg}`);
    }

    console.log(`[MISP] Sync completed: ${result.processed} IOCs, ${result.failed} failed`);
    return result;
}

async function insertBatch(batch: any[], result: SyncResult): Promise<void> {
    try {
        console.log(`[MISP] Batch inserting ${batch.length} IOCs...`);

        await db.insert(iocs)
            .values(batch)
            .onConflictDoUpdate({
                target: iocs.value,
                set: {
                    lastSeen: new Date(),
                    updatedAt: new Date(),
                },
            });

        result.processed += batch.length;
    } catch (batchError) {
        console.error(`[MISP] Batch insert error:`, batchError);
        const errorMsg = batchError instanceof Error ? batchError.message : String(batchError);
        result.errors.push(`Batch insert failed: ${errorMsg}`);
        result.failed += batch.length;
    }
}

// Log sync results
async function logSync(result: SyncResult, startedAt: Date): Promise<void> {
    await db.insert(syncLogs).values({
        entityType: 'misp',
        status: result.failed === 0 ? 'success' : 'partial',
        itemsProcessed: result.processed,
        itemsFailed: result.failed,
        errorMessage: result.errors.length > 0 ? result.errors.slice(0, 5).join('\n') : null,
        startedAt,
        completedAt: new Date(),
    });
}

// Main runner
export async function runMISPSync(): Promise<void> {
    const startedAt = new Date();
    console.log('[MISP] Starting full sync...');

    try {
        const result = await syncMISP();
        await logSync(result, startedAt);
        console.log('[MISP] Full sync completed!');
    } catch (error) {
        console.error('[MISP] Sync failed:', error);
        await logSync({ processed: 0, failed: 1, errors: [(error as Error).message] }, startedAt);
    }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
    runMISPSync()
        .then(() => process.exit(0))
        .catch((error) => {
            console.error(error);
            process.exit(1);
        });
}
