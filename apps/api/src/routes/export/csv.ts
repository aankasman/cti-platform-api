/**
 * Export — CSV Routes
 */

import { Hono } from 'hono';
import { and, db, desc } from '@rinjani/db';
import { iocs, vulnerabilities } from '@rinjani/db/schema';
import { ExportRequestSchema } from '../../lib/schemas';
import { buildIOCFilters, buildVulnFilters, generateIOCCSV, generateVulnCSV, MAX_EXPORT_LIMIT } from './helpers';

const csvRoutes = new Hono();

/**
 * POST /v1/export/iocs/csv
 * Export IOCs to CSV format
 */
csvRoutes.post('/iocs/csv', async (c) => {
    const { filters, limit: rawLimit } = ExportRequestSchema.parse(await c.req.json().catch(() => ({})));
    const limit = Math.min(rawLimit, MAX_EXPORT_LIMIT);

    const conditions = buildIOCFilters(filters);

    let query = db.select().from(iocs);
    if (conditions.length > 0) {
        query = query.where(and(...conditions)) as typeof query;
    }

    const items = await query
        .orderBy(desc(iocs.lastSeen))
        .limit(limit);

    // Generate CSV
    const csv = generateIOCCSV(items);

    return c.text(csv, 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': `attachment; filename="iocs_${Date.now()}.csv"`,
    });
});

/**
 * POST /v1/export/vulnerabilities/csv
 * Export vulnerabilities to CSV format
 */
csvRoutes.post('/vulnerabilities/csv', async (c) => {
    const { filters, limit: rawLimit } = ExportRequestSchema.parse(await c.req.json().catch(() => ({})));
    const limit = Math.min(rawLimit, MAX_EXPORT_LIMIT);

    const conditions = buildVulnFilters(filters);

    let query = db.select().from(vulnerabilities);
    if (conditions.length > 0) {
        query = query.where(and(...conditions)) as typeof query;
    }

    const items = await query
        .orderBy(desc(vulnerabilities.publishedDate))
        .limit(limit);

    // Generate CSV
    const csv = generateVulnCSV(items);

    return c.text(csv, 200, {
        'Content-Type': 'text/csv',
        'Content-Disposition': `attachment; filename="vulnerabilities_${Date.now()}.csv"`,
    });
});

export default csvRoutes;
