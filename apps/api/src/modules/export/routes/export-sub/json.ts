/**
 * Export — JSON Routes
 */

import { Hono } from 'hono';
import { and, db, desc } from '@rinjani/db';
import { iocs, vulnerabilities } from '@rinjani/db/schema';
import { ExportRequestSchema } from '../../../../lib/schemas';
import { buildIOCFilters, buildVulnFilters, MAX_EXPORT_LIMIT } from './helpers';

const jsonRoutes = new Hono();

/**
 * POST /v1/export/iocs/json
 * Export IOCs to JSON format
 */
jsonRoutes.post('/iocs/json', async (c) => {
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

    return c.json({
        success: true,
        data: {
            iocs: items,
            exported_at: new Date().toISOString(),
            count: items.length,
        },
    }, 200, {
        'Content-Disposition': `attachment; filename="iocs_${Date.now()}.json"`,
    });
});

/**
 * POST /v1/export/vulnerabilities/json
 * Export vulnerabilities to JSON format
 */
jsonRoutes.post('/vulnerabilities/json', async (c) => {
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

    return c.json({
        success: true,
        data: {
            vulnerabilities: items,
            exported_at: new Date().toISOString(),
            count: items.length,
        },
    }, 200, {
        'Content-Disposition': `attachment; filename="vulnerabilities_${Date.now()}.json"`,
    });
});

export default jsonRoutes;
