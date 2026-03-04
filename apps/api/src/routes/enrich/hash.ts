/**
 * Hash Enrichment Route
 */

import { Hono } from 'hono';
import { db, eq } from '@rinjani/db';
import { iocs } from '@rinjani/db/schema';
import { NotFoundError } from '../../lib/errors';

const hashRoutes = new Hono();

/**
 * GET /hash/:hash
 * Enrich file hash with all available data
 */
hashRoutes.get('/:hash', async (c) => {
    const hash = c.req.param('hash');

    const relatedIOCs = await db
        .select()
        .from(iocs)
        .where(eq(iocs.value, hash.toLowerCase()))
        .limit(100);

    if (relatedIOCs.length === 0) {
        throw new NotFoundError('Hash', hash);
    }

    const sources = [...new Set(relatedIOCs.map(i => i.source))];
    const threatTypes = [...new Set(relatedIOCs.map(i => i.threatType).filter(Boolean))];
    const tags = [...new Set(relatedIOCs.flatMap(i => i.tags || []))];
    const malwareFamilies = [...new Set(
        relatedIOCs
            .map(i => (i.rawData as Record<string, unknown> | null)?.malware_family)
            .filter(Boolean)
    )];

    return c.json({
        success: true,
        data: {
            value: hash,
            type: 'hash',
            enrichment: {
                sources,
                threatTypes,
                tags,
                malwareFamilies,
                reportCount: relatedIOCs.length,
            },
            relatedIOCs: relatedIOCs.slice(0, 10),
        },
    });
});

export default hashRoutes;
