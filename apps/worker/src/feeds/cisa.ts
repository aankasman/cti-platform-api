/**
 * CISA Known Exploited Vulnerabilities (KEV) Sync Worker
 * 
 * Fetches the CISA KEV catalog of actively exploited vulnerabilities.
 * https://www.cisa.gov/known-exploited-vulnerabilities-catalog
 */

import { db } from '@rinjani/db';
import { vulnerabilities, syncLogs } from '@rinjani/db/schema';
import { eq } from '@rinjani/db';

// =============================================================================
// Configuration
// =============================================================================

const CISA_CATALOG_URL = process.env.CISA_CATALOG_URL ||
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

// =============================================================================
// Types
// =============================================================================

interface CISAVulnerability {
    cveID: string;
    vendorProject: string;
    product: string;
    vulnerabilityName: string;
    dateAdded: string;
    shortDescription: string;
    requiredAction: string;
    dueDate: string;
    knownRansomwareCampaignUse: string;
    notes: string;
}

interface CISACatalog {
    title: string;
    catalogVersion: string;
    dateReleased: string;
    count: number;
    vulnerabilities: CISAVulnerability[];
}

// =============================================================================
// Sync Functions
// =============================================================================

interface SyncResult {
    processed: number;
    failed: number;
    errors: string[];
}

function mapSeverity(ransomwareUse: string): string {
    // If used in ransomware, mark as critical
    if (ransomwareUse?.toLowerCase() === 'known') {
        return 'critical';
    }
    return 'high'; // All KEV entries are at least high severity
}

export async function syncCISA(): Promise<SyncResult> {
    console.log('[CISA KEV] Starting sync...');
    console.log(`[CISA KEV] Catalog URL: ${CISA_CATALOG_URL}`);

    const result: SyncResult = { processed: 0, failed: 0, errors: [] };

    try {
        const response = await fetch(CISA_CATALOG_URL, {
            headers: { 'Accept': 'application/json' },
        });

        if (!response.ok) {
            throw new Error(`CISA API error: ${response.status} ${response.statusText}`);
        }

        const catalog: CISACatalog = await response.json() as CISACatalog;
        console.log(`[CISA KEV] Catalog version: ${catalog.catalogVersion}, ${catalog.count} vulnerabilities`);

        for (const vuln of catalog.vulnerabilities) {
            try {
                const existing = await db.select()
                    .from(vulnerabilities)
                    .where(eq(vulnerabilities.cveId, vuln.cveID))
                    .limit(1);

                const vulnData = {
                    cveId: vuln.cveID,
                    description: vuln.shortDescription || vuln.vulnerabilityName,
                    severity: mapSeverity(vuln.knownRansomwareCampaignUse),
                    isExploited: true,
                    exploitAddedDate: vuln.dateAdded,
                    dueDate: vuln.dueDate,
                    vendorProject: vuln.vendorProject || null,
                    product: vuln.product || null,
                    rawData: vuln,
                    syncedAt: new Date(),
                };

                if (existing.length > 0) {
                    await db.update(vulnerabilities)
                        .set({ ...vulnData, updatedAt: new Date() })
                        .where(eq(vulnerabilities.cveId, vuln.cveID));
                } else {
                    await db.insert(vulnerabilities).values(vulnData);
                }

                result.processed++;
            } catch (vulnError) {
                result.failed++;
                result.errors.push(`CVE ${vuln.cveID}: ${vulnError}`);
            }
        }

    } catch (error) {
        console.error('[CISA KEV] Error fetching catalog:', error);
        result.errors.push(`Fetch error: ${error}`);
    }

    console.log(`[CISA KEV] Sync completed: ${result.processed} CVEs, ${result.failed} failed`);
    return result;
}

// Log sync results
async function logSync(result: SyncResult, startedAt: Date): Promise<void> {
    await db.insert(syncLogs).values({
        entityType: 'cisa_kev',
        status: result.failed === 0 ? 'success' : 'partial',
        itemsProcessed: result.processed,
        itemsFailed: result.failed,
        errorMessage: result.errors.length > 0 ? result.errors.slice(0, 5).join('\n') : null,
        startedAt,
        completedAt: new Date(),
    });
}

// Main runner
export async function runCISASync(): Promise<void> {
    const startedAt = new Date();
    console.log('[CISA KEV] Starting full sync...');

    try {
        const result = await syncCISA();
        await logSync(result, startedAt);
        console.log('[CISA KEV] Full sync completed!');
    } catch (error) {
        console.error('[CISA KEV] Sync failed:', error);
        await logSync({ processed: 0, failed: 1, errors: [(error as Error).message] }, startedAt);
    }
}

// Run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
    runCISASync()
        .then(() => process.exit(0))
        .catch((error) => {
            console.error(error);
            process.exit(1);
        });
}
