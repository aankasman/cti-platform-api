/**
 * CISA KEV Feed Sync
 */

import { db, inArray, sql } from '@rinjani/db';
import { vulnerabilities } from '@rinjani/db/schema';
import { createLogger } from '../../../../lib/logger';
import type { CISAVulnerability, OTXSyncOptions, SyncResult } from './types';

const log = createLogger('FeedSync:cisa');

const CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

export async function syncCISAFeed(options: OTXSyncOptions = {}): Promise<SyncResult> {
    const result: SyncResult = {
        success: true,
        pulsesProcessed: 1,
        indicatorsProcessed: 0,
        indicatorsAdded: 0,
        indicatorsUpdated: 0,
        errors: [],
    };

    try {
        log.info('Fetching Known Exploited Vulnerabilities...');
        const response = await fetch(CISA_KEV_URL);

        if (!response.ok) {
            throw new Error(`CISA API error: ${response.status}`);
        }

        const data = await response.json() as { vulnerabilities: CISAVulnerability[] };
        const totalCVEs = data.vulnerabilities?.length || 0;
        result.indicatorsProcessed = totalCVEs;

        // Delta check: which CVE IDs already exist?
        if (data.vulnerabilities && data.vulnerabilities.length > 0) {
            const cveIds = data.vulnerabilities.map(v => v.cveID);
            const BATCH_SIZE = 500;
            const existingCVEs = new Set<string>();

            for (let i = 0; i < cveIds.length; i += BATCH_SIZE) {
                const batch = cveIds.slice(i, i + BATCH_SIZE);
                try {
                    const rows = await db.select({ cveId: vulnerabilities.cveId })
                        .from(vulnerabilities)
                        .where(sql`${vulnerabilities.cveId} IN ${batch}`);
                    for (const row of rows) {
                        existingCVEs.add(row.cveId);
                    }
                } catch (err) {
                    log.warn('Delta check batch failed', { error: (err as Error).message });
                }
            }

            result.indicatorsAdded = totalCVEs - existingCVEs.size;
            result.indicatorsUpdated = existingCVEs.size;

            // PERSISTENCE: Upsert all CVEs (insert new, update existing)
            const cvesToUpsert = data.vulnerabilities.map(vuln => ({
                cveId: vuln.cveID,
                vendorProject: vuln.vendorProject,
                product: vuln.product,
                description: vuln.shortDescription,
                isExploited: true,
                exploitAddedDate: vuln.dateAdded || null,
                dueDate: vuln.dueDate || null,
                created_at: new Date(),
                updated_at: new Date(),
                raw_data: vuln,
            }));

            if (cvesToUpsert.length > 0) {
                try {
                    const BATCH_SIZE = 500;
                    for (let i = 0; i < cvesToUpsert.length; i += BATCH_SIZE) {
                        const batch = cvesToUpsert.slice(i, i + BATCH_SIZE);
                        await db.insert(vulnerabilities).values(batch)
                            .onConflictDoUpdate({
                                target: vulnerabilities.cveId,
                                set: {
                                    description: sql`excluded.description`,
                                    vendorProject: sql`excluded.vendor_project`,
                                    product: sql`excluded.product`,
                                    isExploited: sql`excluded.is_exploited`,
                                    exploitAddedDate: sql`excluded.exploit_added_date`,
                                    dueDate: sql`excluded.due_date`,
                                    rawData: sql`excluded.raw_data`,
                                    updatedAt: sql`now()`,
                                },
                            });
                    }
                } catch (dbErr) {
                    log.error('Failed to upsert CVEs', new Error((dbErr as Error).message));
                    result.errors.push(`DB Upsert failed for CISA: ${(dbErr as Error).message}`);
                }
            }
        }

        log.info('CISA sync result', { totalCVEs, newAdded: result.indicatorsAdded, existing: result.indicatorsUpdated });

    } catch (err) {
        result.success = false;
        result.errors.push(`CISA sync failed: ${(err as Error).message}`);
    }

    return result;
}
