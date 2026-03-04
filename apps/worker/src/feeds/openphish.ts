/**
 * OpenPhish Sync Worker
 * 
 * Fetches phishing URLs from OpenPhish public feed.
 * https://openphish.com/
 * 
 * Feed URL: https://openphish.com/feed.txt (no API key required)
 * Updates: Every hour
 * Format: Plain text, one URL per line
 */

import { db } from '@rinjani/db';
import { iocs, syncLogs } from '@rinjani/db/schema';
import { createLogger } from '../lib/logger';

const log = createLogger('OpenPhish');

// =============================================================================
// Configuration
// =============================================================================

const OPENPHISH_FEED_URL = 'https://openphish.com/feed.txt';
const BATCH_SIZE = 100;

// =============================================================================
// Types
// =============================================================================

interface SyncResult {
    processed: number;
    failed: number;
    errors: string[];
}

// =============================================================================
// API Functions
// =============================================================================

async function fetchPhishingURLs(): Promise<string[]> {
    const response = await fetch(OPENPHISH_FEED_URL);

    if (!response.ok) {
        throw new Error(`OpenPhish API error: ${response.status} ${response.statusText}`);
    }

    const text = await response.text();

    // Parse URLs (one per line, skip empty lines)
    const urls = text
        .split('\n')
        .map(line => line.trim())
        .filter(line => line.length > 0 && line.startsWith('http'));

    return urls;
}

// =============================================================================
// Sync Functions
// =============================================================================

export async function syncOpenPhish(): Promise<SyncResult> {
    log.info('Starting sync', { feedUrl: OPENPHISH_FEED_URL });

    const result: SyncResult = { processed: 0, failed: 0, errors: [] };

    try {
        const urls = await fetchPhishingURLs();
        log.info('Fetched phishing URLs', { count: urls.length });

        // Batch process URLs
        const iocBatch: any[] = [];

        for (const url of urls) {
            try {
                // Extract domain from URL
                let domain = '';
                try {
                    const urlObj = new URL(url);
                    domain = urlObj.hostname;
                } catch {
                    domain = 'unknown';
                }

                const iocRecord = {
                    type: 'url',
                    value: url,
                    source: 'openphish',
                    threatType: 'phishing',
                    confidence: 90, // OpenPhish has high confidence
                    severity: 'high',
                    firstSeen: new Date(),
                    lastSeen: new Date(),
                    tags: [
                        'openphish',
                        'phishing',
                        domain,
                    ],
                    metadata: {
                        domain: domain,
                        feed_source: 'openphish',
                        detected_at: new Date().toISOString(),
                    },
                };

                iocBatch.push(iocRecord);

                // Batch insert when batch is full
                if (iocBatch.length >= BATCH_SIZE) {
                    await insertBatch(iocBatch, result);
                    iocBatch.length = 0; // Clear batch
                }
            } catch (iocError) {
                result.failed++;
                const errorMsg = iocError instanceof Error ? iocError.message : String(iocError);
                if (result.errors.length < 10) {
                    result.errors.push(`URL ${url}: ${errorMsg}`);
                }
            }
        }

        // Insert remaining URLs
        if (iocBatch.length > 0) {
            await insertBatch(iocBatch, result);
        }

    } catch (error) {
        log.error('Error fetching URLs', error);
        const errorMsg = error instanceof Error ? error.message : (error as Error).message;
        result.errors.push(`Fetch error: ${errorMsg}`);
    }

    log.info('Sync completed', { processed: result.processed, failed: result.failed });
    return result;
}

async function insertBatch(batch: any[], result: SyncResult): Promise<void> {
    try {
        log.debug('Batch inserting URLs', { count: batch.length });

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
        log.error('Batch insert error', batchError);
        const errorMsg = batchError instanceof Error ? batchError.message : String(batchError);
        result.errors.push(`Batch insert failed: ${errorMsg}`);
        result.failed += batch.length;
    }
}

// Log sync results
async function logSync(result: SyncResult, startedAt: Date): Promise<void> {
    await db.insert(syncLogs).values({
        entityType: 'openphish',
        status: result.failed === 0 ? 'success' : 'partial',
        itemsProcessed: result.processed,
        itemsFailed: result.failed,
        errorMessage: result.errors.length > 0 ? result.errors.slice(0, 5).join('\n') : null,
        startedAt,
        completedAt: new Date(),
    });
}

// Main runner
export async function runOpenPhishSync(): Promise<void> {
    const startedAt = new Date();
    log.info('Starting full sync');

    try {
        const result = await syncOpenPhish();
        await logSync(result, startedAt);
        log.info('Full sync completed');
    } catch (error) {
        log.error('Sync failed', error);
        await logSync({ processed: 0, failed: 1, errors: [(error as Error).message] }, startedAt);
    }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
    runOpenPhishSync()
        .then(() => process.exit(0))
        .catch((error) => {
            console.error(error);
            process.exit(1);
        });
}
