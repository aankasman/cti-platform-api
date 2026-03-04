/**
 * Export — STIX 2.1 Routes
 */

import { Hono } from 'hono';
import { and, db, desc } from '@rinjani/db';
import { iocs } from '@rinjani/db/schema';
import { ExportRequestSchema } from '../../../../lib/schemas';
import { buildIOCFilters, generateSTIXBundle, MAX_STIX_LIMIT } from './helpers';

const stixRoutes = new Hono();

/**
 * POST /v1/export/iocs/stix
 * Export IOCs to STIX 2.1 format
 */
stixRoutes.post('/iocs/stix', async (c) => {
    const { filters, limit: rawLimit } = ExportRequestSchema.parse(await c.req.json().catch(() => ({})));
    const limit = Math.min(rawLimit, MAX_STIX_LIMIT);

    const conditions = buildIOCFilters(filters);

    let query = db.select().from(iocs);
    if (conditions.length > 0) {
        query = query.where(and(...conditions)) as typeof query;
    }

    const items = await query
        .orderBy(desc(iocs.lastSeen))
        .limit(limit);

    // Generate STIX bundle
    const stix = generateSTIXBundle(items);

    return c.json(stix, 200, {
        'Content-Disposition': `attachment; filename="iocs_stix_${Date.now()}.json"`,
    });
});

export default stixRoutes;
