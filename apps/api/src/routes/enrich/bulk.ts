/**
 * Bulk Enrichment Route
 */

import { Hono } from 'hono';
import { db, eq } from '@rinjani/db';
import { iocs } from '@rinjani/db/schema';
import { BulkEnrichSchema } from '../../lib/schemas';

const bulkEnrichRoutes = new Hono();

/**
 * POST /bulk
 * Bulk enrichment for multiple IOCs
 */
bulkEnrichRoutes.post('/', async (c) => {
    const { values } = BulkEnrichSchema.parse(await c.req.json().catch(() => ({})));

    const results = await Promise.all(
        values.map(async (value: string) => {
            const ioc = await db
                .select()
                .from(iocs)
                .where(eq(iocs.value, value))
                .limit(1);

            return {
                value,
                found: ioc.length > 0,
                data: ioc[0] || null,
            };
        })
    );

    return c.json({
        success: true,
        data: {
            results,
            total: results.length,
            found: results.filter(r => r.found).length,
        },
    });
});

export default bulkEnrichRoutes;
