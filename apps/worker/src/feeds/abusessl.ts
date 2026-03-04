/**
 * Abuse.ch SSL Blacklist Sync Worker
 * 
 * Fetches malicious SSL certificate IPs from Abuse.ch SSL Blacklist.
 * https://sslbl.abuse.ch/
 */

import { db } from '@rinjani/db';
import { iocs, syncLogs } from '@rinjani/db/schema';
import { eq } from '@rinjani/db';

// =============================================================================
// Configuration
// =============================================================================

const ABUSESSL_URL = process.env.ABUSESSL_URL ||
    'https://sslbl.abuse.ch/blacklist/sslipblacklist.csv';

// =============================================================================
// Sync Functions
// =============================================================================

interface SyncResult {
    processed: number;
    failed: number;
    errors: string[];
}

export async function syncAbuseSSL(): Promise<SyncResult> {
    console.log('[Abuse.ch SSL] Starting sync...');
    console.log(`[Abuse.ch SSL] Blacklist URL: ${ABUSESSL_URL}`);

    const result: SyncResult = { processed: 0, failed: 0, errors: [] };

    try {
        const response = await fetch(ABUSESSL_URL, {
            headers: { 'Accept': 'text/csv' },
        });

        if (!response.ok) {
            throw new Error(`Abuse.ch API error: ${response.status} ${response.statusText}`);
        }

        const csvText = await response.text();
        const lines = csvText.split('\n');

        console.log(`[Abuse.ch SSL] Processing ${lines.length} lines...`);

        for (const line of lines) {
            // Skip comments and empty lines
            if (line.startsWith('#') || line.trim() === '') {
                continue;
            }

            // CSV format: Firstseen,DstIP,DstPort
            const parts = line.split(',');
            if (parts.length < 2) {
                continue;
            }

            const [firstSeen, ip, port] = parts;
            const value = port ? `${ip}:${port}` : ip;

            try {
                const existing = await db.select()
                    .from(iocs)
                    .where(eq(iocs.value, value))
                    .limit(1);

                const iocData = {
                    type: 'ip',
                    value: value,
                    source: 'abusessl',
                    threatType: 'c2', // C2 servers
                    confidence: 90,
                    severity: 'high',
                    firstSeen: firstSeen ? new Date(firstSeen) : null,
                    lastSeen: new Date(),
                    tags: ['ssl-blacklist', 'c2', 'abuse.ch'],
                };

                if (existing.length > 0) {
                    await db.update(iocs)
                        .set({ ...iocData, updatedAt: new Date() })
                        .where(eq(iocs.value, value));
                } else {
                    await db.insert(iocs).values(iocData);
                }

                result.processed++;
            } catch (iocError) {
                result.failed++;
                if (result.errors.length < 10) {
                    result.errors.push(`IP ${value}: ${iocError}`);
                }
            }
        }

    } catch (error) {
        console.error('[Abuse.ch SSL] Error fetching blacklist:', error);
        result.errors.push(`Fetch error: ${error}`);
    }

    console.log(`[Abuse.ch SSL] Sync completed: ${result.processed} IPs, ${result.failed} failed`);
    return result;
}

// Log sync results
async function logSync(result: SyncResult, startedAt: Date): Promise<void> {
    await db.insert(syncLogs).values({
        entityType: 'abusessl',
        status: result.failed === 0 ? 'success' : 'partial',
        itemsProcessed: result.processed,
        itemsFailed: result.failed,
        errorMessage: result.errors.length > 0 ? result.errors.slice(0, 5).join('\n') : null,
        startedAt,
        completedAt: new Date(),
    });
}

// Main runner
export async function runAbuseSSLSync(): Promise<void> {
    const startedAt = new Date();
    console.log('[Abuse.ch SSL] Starting full sync...');

    try {
        const result = await syncAbuseSSL();
        await logSync(result, startedAt);
        console.log('[Abuse.ch SSL] Full sync completed!');
    } catch (error) {
        console.error('[Abuse.ch SSL] Sync failed:', error);
        await logSync({ processed: 0, failed: 1, errors: [(error as Error).message] }, startedAt);
    }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
    runAbuseSSLSync()
        .then(() => process.exit(0))
        .catch((error) => {
            console.error(error);
            process.exit(1);
        });
}
