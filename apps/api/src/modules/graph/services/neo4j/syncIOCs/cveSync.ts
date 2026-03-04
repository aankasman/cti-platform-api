/**
 * Neo4j Sync — CVE nodes
 */

import { db } from '@rinjani/db';
import { vulnerabilities } from '@rinjani/db/schema';
import { getNeo4jDriver } from '../driver';
import { createLogger } from '../../../../../lib/logger';

const log = createLogger('Neo4j');

export async function syncCVEs(maxCVEs: number = 500): Promise<number> {
    const rows = await db.select({
        id: vulnerabilities.id,
        cveId: vulnerabilities.cveId,
        severity: vulnerabilities.severity,
        cvssScore: vulnerabilities.cvssScore,
        description: vulnerabilities.description,
    }).from(vulnerabilities).limit(maxCVEs);

    if (rows.length === 0) return 0;

    const driver = getNeo4jDriver();
    const session = driver.session();
    try {
        await session.run(`
            UNWIND $batch AS row
            MERGE (c:CVE {cveId: row.cveId})
            SET c.pgId = row.id,
                c.severity = coalesce(row.severity, 'unknown'),
                c.cvssScore = row.cvssScore,
                c.description = coalesce(row.description, ''),
                c.syncedAt = datetime()
        `, {
            batch: rows.map(r => ({
                id: r.id,
                cveId: r.cveId,
                severity: r.severity || 'unknown',
                cvssScore: r.cvssScore != null ? Number(r.cvssScore) : null,
                description: (r.description || '').slice(0, 500),
            }))
        });

        log.info('CVEs synced', { count: rows.length });
        return rows.length;
    } finally {
        await session.close();
    }
}
