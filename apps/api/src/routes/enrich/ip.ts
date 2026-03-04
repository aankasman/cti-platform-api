/**
 * IP Enrichment Route
 */

import { Hono } from 'hono';
import { db, eq } from '@rinjani/db';
import { iocs } from '@rinjani/db/schema';
import { NotFoundError } from '../../lib/errors';

const ipRoutes = new Hono();

/**
 * GET /ip/:ip
 * Enrich IP address with all available data
 */
ipRoutes.get('/:ip', async (c) => {
    const ip = c.req.param('ip');

    // Get all IOCs for this IP
    const relatedIOCs = await db
        .select()
        .from(iocs)
        .where(eq(iocs.value, ip))
        .limit(100);

    if (relatedIOCs.length === 0) {
        throw new NotFoundError('IP', ip);
    }

    // Aggregate data
    const sources = [...new Set(relatedIOCs.map(i => i.source))];
    const threatTypes = [...new Set(relatedIOCs.map(i => i.threatType).filter(Boolean))];
    const tags = [...new Set(relatedIOCs.flatMap(i => i.tags || []))];
    const maxConfidence = Math.max(...relatedIOCs.map(i => i.confidence || 0));

    // Calculate firstSeen and lastSeen with null safety
    const validFirstSeenDates = relatedIOCs
        .map(i => i.firstSeen)
        .filter((date): date is Date => date !== null && date !== undefined)
        .map(date => new Date(date).getTime());
    const validLastSeenDates = relatedIOCs
        .map(i => i.lastSeen)
        .filter((date): date is Date => date !== null && date !== undefined)
        .map(date => new Date(date).getTime());

    const firstSeen = validFirstSeenDates.length > 0
        ? new Date(Math.min(...validFirstSeenDates))
        : null;
    const lastSeen = validLastSeenDates.length > 0
        ? new Date(Math.max(...validLastSeenDates))
        : null;

    return c.json({
        success: true,
        data: {
            value: ip,
            type: 'ip',
            enrichment: {
                sources,
                threatTypes,
                tags,
                confidence: maxConfidence,
                firstSeen,
                lastSeen,
                reportCount: relatedIOCs.length,
            },
            relatedIOCs: relatedIOCs.slice(0, 10),
        },
    });
});

export default ipRoutes;
