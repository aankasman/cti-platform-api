/**
 * Bulk Lookup & Stats Routes
 */

import { Hono } from 'hono';
import { db, eq } from '@rinjani/db';
import { iocs } from '@rinjani/db/schema';
import { ValidationError } from '../../../../lib/errors';

const lookupRoutes = new Hono();

/**
 * POST /lookup
 * Bulk IOC lookup
 */
lookupRoutes.post('/', async (c) => {
    const body = await c.req.json();
    const values: string[] = body.values || [];

    if (!values.length) {
        throw new ValidationError('No values provided');
    }

    if (values.length > 1000) {
        throw new ValidationError('Maximum 1,000 values per request');
    }

    // Lookup in database
    const results: Record<string, Record<string, unknown> | null> = {};

    for (const value of values) {
        // Query for matching IOC
        const matches = await db.select()
            .from(iocs)
            .where(eq(iocs.value, value))
            .limit(1);

        results[value] = matches[0] || null;
    }

    const found = Object.values(results).filter(v => v !== null).length;

    return c.json({
        success: true,
        data: {
            results,
            summary: {
                total: values.length,
                found,
                notFound: values.length - found,
            },
        },
    });
});

/**
 * GET /stats
 * Get bulk operation statistics
 */
lookupRoutes.get('/stats', async (c) => {
    const [iocCount] = await db.select({ count: iocs.id }).from(iocs).limit(1);

    return c.json({
        success: true,
        data: {
            capabilities: ['import', 'export', 'lookup'],
            formats: ['json', 'csv', 'stix'],
            limits: {
                import: 10000,
                lookup: 1000,
                export: 10000,
            },
        },
    });
});

export default lookupRoutes;
