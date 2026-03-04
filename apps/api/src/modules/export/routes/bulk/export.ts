/**
 * Bulk Export Route
 */

import { Hono } from 'hono';
import { db } from '@rinjani/db';
import { iocs } from '@rinjani/db/schema';
import { generateSTIXBundle } from '@rinjani/core/stix';
import { requireRole } from '../../../../middleware/auth';
import { LimitSchema, BulkExportQuerySchema } from '../../../../lib/schemas';

const exportRoutes = new Hono();

/**
 * GET /export/iocs
 * Export IOCs in various formats
 */
exportRoutes.get('/iocs', requireRole('admin', 'analyst'), async (c) => {
    const { format } = BulkExportQuerySchema.parse(c.req.query());
    const { limit } = LimitSchema.parse(c.req.query());

    // Build query
    const data = await db.select().from(iocs).limit(limit);

    // Format output
    switch (format.toLowerCase()) {
        case 'csv': {
            const headers = ['id', 'type', 'value', 'source', 'severity', 'firstSeen', 'lastSeen'];
            const rows = data.map(row =>
                headers.map(h => String((row as Record<string, unknown>)[h] || '')).join(',')
            );
            const csv = [headers.join(','), ...rows].join('\n');

            c.header('Content-Type', 'text/csv');
            c.header('Content-Disposition', 'attachment; filename="iocs_export.csv"');
            return c.text(csv);
        }

        case 'stix': {
            // Use the STIX bundle generator
            const bundle = await generateSTIXBundle({
                includeIOCs: true,
                includeThreatActors: false,
                includeVulnerabilities: false,
                iocLimit: limit
            });

            c.header('Content-Type', 'application/stix+json');
            return c.json(bundle);
        }

        case 'json':
        default:
            return c.json({
                success: true,
                data: {
                    items: data,
                    count: data.length,
                    format: 'json',
                },
                meta: {
                    exportedAt: new Date().toISOString(),
                },
            });
    }
});

export default exportRoutes;
