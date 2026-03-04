/**
 * Vulnerabilities Routes (CISA KEV + CVE)
 *
 * Extracted from v1.ts — list and detail endpoints for vulnerabilities.
 */

import { Hono } from 'hono';
import { db, eq, sql, rawQuery } from '@rinjani/db';
import { vulnerabilities } from '@rinjani/db/schema';
import * as opensearch from '../../../services/opensearch';
import { createLogger } from '../../../lib/logger';
import { NotFoundError } from '../../../lib/errors';
import { VulnFilterSchema } from '../../../lib/schemas';
import { paginate } from './helpers';
import { parseCursorParams, buildCursorResponse } from '../../../lib/pagination';
import { escSql } from '../../../lib/sanitize';

const log = createLogger('v1:vulnerabilities');
const router = new Hono();

// ============================================================================
// Vulnerabilities (CISA KEV + CVE)
// ============================================================================

router.get('/vulnerabilities', async (c) => {
    const { page, pageSize, q, severity, sortBy, exploited, vendor, dateFrom, dateTo, ransomware } = VulnFilterSchema.parse(c.req.query());

    // Use OpenSearch for fast search with facets
    const result = await opensearch.unifiedSearch({
        query: q || '',
        filters: {
            entityType: ['vulnerability'],
            ...(severity ? { severity: [severity] } : {}),
            ...(dateFrom ? { dateFrom } : {}),
            ...(dateTo ? { dateTo } : {}),
        },
        sort: { field: sortBy, order: 'desc' },
        pagination: { page, limit: pageSize },
        aggregations: true,
    });

    // Map OpenSearch fields to frontend-expected names for vulnerabilities
    const mappedItems = result.items.map((item: Record<string, unknown>) => ({
        ...item,
        cveId: item.value,  // Frontend expects cveId
        publishedDate: item.createdAt || item.updatedAt,
        vendorProject: item.vendorProject || '',
        product: item.product || '',
        isExploited: item.isExploited || false,
    }));

    return c.json({
        success: true,
        data: {
            items: mappedItems,
            filters: { severity, exploited, vendor, dateFrom, dateTo, ransomware, q },
            pagination: paginate(page, pageSize, result.total),
            facets: result.facets,
            took: result.took,
        },
    });
});

// ============================================================================
// Vulnerabilities — Cursor Pagination (PostgreSQL direct)
// ============================================================================

router.get('/vulnerabilities/cursor', async (c) => {
    const { cursor, limit, direction } = parseCursorParams(c.req.query());

    let whereClause = '';
    if (cursor) {
        const op = direction === 'next' ? '<' : '>';
        whereClause = `WHERE (updated_at, id::text) ${op} ('${escSql(cursor.timestamp)}', '${escSql(cursor.id)}')`;
    }

    const orderDir = direction === 'next' ? 'DESC' : 'ASC';

    const result = await rawQuery(
        `SELECT id, cve_id, description, severity, cvss_score, vendor_project, product,
                is_exploited, published_date, created_at, updated_at
         FROM vulnerabilities ${whereClause}
         ORDER BY updated_at ${orderDir} NULLS LAST, id ${orderDir}
         LIMIT ${limit + 1}`
    );

    const rows = (result.rows || []).map((row: Record<string, unknown>) => ({
        ...row,
        cveId: row.cve_id,
        cvssScore: row.cvss_score,
        vendorProject: row.vendor_project,
        isExploited: row.is_exploited,
        publishedDate: row.published_date,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
    }));

    if (direction === 'prev') rows.reverse();

    const response = buildCursorResponse(rows, limit, (row: Record<string, unknown>) => ({
        timestamp: String(row.updated_at || row.created_at || ''),
        id: String(row.id || ''),
    }));

    return c.json({ success: true, ...response });
});


router.get('/vulnerabilities/:cveId', async (c) => {
    const { cveId } = c.req.param();

    // Only uppercase CVE IDs (e.g. CVE-2018-0175), leave UUIDs as-is
    const lookupId = cveId.startsWith('CVE-') || cveId.startsWith('cve-') ? cveId.toUpperCase() : cveId;

    // Use OpenSearch getById for lookup by CVE ID or UUID
    const result = await opensearch.getById(lookupId, 'vulnerability');

    if (!result.item) {
        throw new NotFoundError('CVE', cveId);
    }

    const item = result.item;

    // Fetch additional fields from PostgreSQL if missing in OpenSearch
    let vendorProject = item.vendorProject || '';
    let product = item.product || '';

    if (!vendorProject || !product) {
        try {
            const pgResult = await db
                .select({
                    vendorProject: vulnerabilities.vendorProject,
                    product: vulnerabilities.product,
                })
                .from(vulnerabilities)
                .where(eq(vulnerabilities.cveId, String(item.value || lookupId).toUpperCase()))
                .limit(1);

            if (pgResult.length > 0) {
                vendorProject = vendorProject || pgResult[0].vendorProject || '';
                product = product || pgResult[0].product || '';
            }
        } catch (pgErr) {
            log.warn('PostgreSQL fallback failed for CVE detail', { cveId, error: (pgErr as Error)?.message });
        }
    }

    // Map OpenSearch fields to frontend-expected field names
    const mappedData = {
        ...item,
        cveId: item.value,  // Frontend expects cveId, OpenSearch has value
        publishedDate: item.createdAt || item.updatedAt,  // Use createdAt as publishedDate
        vendorProject,
        product,
        isExploited: item.isExploited || false,
    };

    return c.json({ success: true, data: mappedData, took: result.took });
});

export default router;
