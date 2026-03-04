/**
 * Neo4j Sync — ALL IOCs (batch processing for large datasets)
 *
 * Reads from PostgreSQL `iocs` table first. If that table is empty,
 * falls back to OpenSearch (where IOCs may live exclusively).
 */

import { db, sql } from '@rinjani/db';
import type { RawQueryResult } from '@rinjani/db';
import { iocs } from '@rinjani/db/schema';
import { getNeo4jDriver } from '../driver';
import { createLogger } from '../../../../../lib/logger';

const log = createLogger('Neo4j');

export async function syncAllIOCs(
    batchSize: number = 5000,
    onProgress?: (pct: number, processed: number, total: number) => void,
): Promise<number> {
    log.info('Starting ALL IOCs sync');

    const countResult = await db.execute(sql`SELECT COUNT(*) as total FROM ${iocs}`) as unknown as RawQueryResult;
    const totalIOCs = Number(countResult.rows?.[0]?.total || 0);

    if (totalIOCs > 0) {
        return syncFromPostgres(totalIOCs, batchSize, onProgress);
    }

    // Fallback: try OpenSearch
    log.info('PG iocs table empty, trying OpenSearch fallback');
    return syncFromOpenSearch(batchSize, onProgress);
}

/** Sync IOCs from PostgreSQL (original path) */
async function syncFromPostgres(
    totalIOCs: number,
    batchSize: number,
    onProgress?: (pct: number, processed: number, total: number) => void,
): Promise<number> {
    log.info('Syncing IOCs from PostgreSQL', { total: totalIOCs });

    const driver = getNeo4jDriver();
    const session = driver.session();
    let synced = 0;

    try {
        for (let offset = 0; offset < totalIOCs; offset += batchSize) {
            const rows = await db.select({
                id: iocs.id,
                value: iocs.value,
                type: iocs.type,
                pulseId: iocs.pulseId,
                threatType: iocs.threatType,
                severity: iocs.severity,
            }).from(iocs)
                .limit(batchSize)
                .offset(offset);

            if (rows.length === 0) break;

            await session.run(`
                UNWIND $batch AS row
                MERGE (i:IOC {pgId: row.id})
                SET i.value = row.value,
                    i.type = row.type,
                    i.threatType = coalesce(row.threatType, 'unknown'),
                    i.severity = coalesce(row.severity, 'unknown'),
                    i.syncedAt = datetime()
            `, {
                batch: rows.map(r => ({
                    id: r.id,
                    value: r.value,
                    type: r.type,
                    threatType: r.threatType || 'unknown',
                    severity: r.severity || 'unknown',
                }))
            });

            synced += rows.length;
            const progress = Math.min(100, Math.floor((synced / totalIOCs) * 100));

            log.info('IOC sync progress', { synced, total: totalIOCs, percent: progress });
            onProgress?.(progress, synced, totalIOCs);

            if (offset + batchSize < totalIOCs) {
                await new Promise(resolve => setTimeout(resolve, 100));
            }
        }

        log.info('IOC sync complete (PG)', { synced });
        return synced;
    } finally {
        await session.close();
    }
}

/** Sync IOCs from OpenSearch when PG table is empty */
async function syncFromOpenSearch(
    batchSize: number,
    onProgress?: (pct: number, processed: number, total: number) => void,
): Promise<number> {
    const { unifiedSearch } = await import('../../opensearch');

    // First, get total count
    const probe = await unifiedSearch({
        query: '',
        filters: { entityType: ['ioc'] },
        pagination: { page: 1, limit: 1 },
        sort: { field: 'updatedAt', order: 'desc' },
        aggregations: false,
    });

    const totalIOCs = probe.total;
    if (totalIOCs === 0) {
        log.info('No IOCs found in OpenSearch either');
        return 0;
    }

    log.info('Syncing IOCs from OpenSearch', { total: totalIOCs });

    const driver = getNeo4jDriver();
    const session = driver.session();
    let synced = 0;
    const pageSize = Math.min(batchSize, 500); // OpenSearch typically caps at ~500

    try {
        for (let page = 1; synced < totalIOCs; page++) {
            const result = await unifiedSearch({
                query: '',
                filters: { entityType: ['ioc'] },
                pagination: { page, limit: pageSize },
                sort: { field: 'updatedAt', order: 'desc' },
                aggregations: false,
            });

            if (result.items.length === 0) break;

            const batch = result.items.map((item: Record<string, unknown>) => ({
                id: (item.id as string) || `os-${synced}`,
                value: (item.title as string) || (item.value as string) || '',
                type: (item.type as string) || 'unknown',
                threatType: (item.threatType as string) || 'unknown',
                severity: (item.severity as string) || 'unknown',
            }));

            await session.run(`
                UNWIND $batch AS row
                MERGE (i:IOC {pgId: row.id})
                SET i.value = row.value,
                    i.type = row.type,
                    i.threatType = coalesce(row.threatType, 'unknown'),
                    i.severity = coalesce(row.severity, 'unknown'),
                    i.source = 'opensearch',
                    i.syncedAt = datetime()
            `, { batch });

            synced += result.items.length;
            const progress = Math.min(100, Math.floor((synced / totalIOCs) * 100));

            log.info('IOC sync progress (OpenSearch)', { synced, total: totalIOCs, percent: progress });
            onProgress?.(progress, synced, totalIOCs);

            if (synced < totalIOCs) {
                await new Promise(resolve => setTimeout(resolve, 50));
            }
        }

        log.info('IOC sync complete (OpenSearch)', { synced });
        return synced;
    } finally {
        await session.close();
    }
}
