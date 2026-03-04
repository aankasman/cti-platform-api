/**
 * Domain Enrichment Route (with VirusTotal integration)
 */

import { Hono } from 'hono';
import { db, like } from '@rinjani/db';
import { iocs } from '@rinjani/db/schema';
import { NotFoundError } from '../../lib/errors';
import { createLogger } from '../../lib/logger';

const log = createLogger('Enrich:domain');

const domainRoutes = new Hono();

/**
 * GET /domain/:domain
 * Enrich domain with all available data
 */
domainRoutes.get('/:domain', async (c) => {
    const domain = c.req.param('domain');

    // Get all IOCs for this domain (exact match and subdomains)
    const relatedIOCs = await db
        .select()
        .from(iocs)
        .where(like(iocs.value, `%${domain}%`))
        .limit(100);

    // Aggregate internal data
    const sources = [...new Set(relatedIOCs.map(i => i.source))];
    const threatTypes = [...new Set(relatedIOCs.map(i => i.threatType).filter(Boolean))];
    const tags = [...new Set(relatedIOCs.flatMap(i => i.tags || []))];
    const maxConfidence = relatedIOCs.length > 0 ? Math.max(...relatedIOCs.map(i => i.confidence || 0)) : 0;

    // VirusTotal enrichment
    let virusTotal: Record<string, unknown> | null = null;
    const vtApiKey = process.env.VIRUSTOTAL_API_KEY;
    if (vtApiKey) {
        try {
            const vtRes = await fetch(`https://www.virustotal.com/api/v3/domains/${domain}`, {
                headers: { 'x-apikey': vtApiKey, 'Accept': 'application/json' },
            });
            if (vtRes.ok) {
                const vtData = await vtRes.json() as {
                    data?: {
                        attributes?: {
                            last_analysis_stats?: { malicious?: number; suspicious?: number; harmless?: number; undetected?: number };
                            reputation?: number;
                            registrar?: string;
                            creation_date?: number;
                            last_analysis_date?: number;
                            categories?: Record<string, string>;
                            popularity_ranks?: Record<string, { rank: number }>;
                            last_dns_records?: Array<{ type: string; value: string }>;
                        };
                    };
                };
                const attrs = vtData.data?.attributes;
                const stats = attrs?.last_analysis_stats || {};
                const malicious = stats.malicious || 0;
                const suspicious = stats.suspicious || 0;
                const total = malicious + suspicious + (stats.harmless || 0) + (stats.undetected || 0);

                virusTotal = {
                    malicious,
                    suspicious,
                    harmless: stats.harmless || 0,
                    undetected: stats.undetected || 0,
                    total,
                    reputation: attrs?.reputation,
                    registrar: attrs?.registrar,
                    creationDate: attrs?.creation_date ? new Date(attrs.creation_date * 1000).toISOString() : null,
                    lastAnalysisDate: attrs?.last_analysis_date ? new Date(attrs.last_analysis_date * 1000).toISOString() : null,
                    categories: attrs?.categories,
                    dnsRecords: attrs?.last_dns_records?.slice(0, 10),
                    verdict: malicious > 5 ? 'malicious' : malicious > 0 ? 'suspicious' : 'clean',
                    permalink: `https://www.virustotal.com/gui/domain/${domain}`,
                };
            } else if (vtRes.status !== 404) {
                log.warn('VT domain lookup failed', { domain, status: vtRes.status });
            }
        } catch (vtErr) {
            log.warn('VT domain lookup error', { domain, error: (vtErr as Error).message });
        }
    }

    // Return combined results (even if not in local DB)
    if (relatedIOCs.length === 0 && !virusTotal) {
        throw new NotFoundError('Domain', domain);
    }

    return c.json({
        success: true,
        data: {
            value: domain,
            type: 'domain',
            enrichment: {
                sources,
                threatTypes,
                tags,
                confidence: maxConfidence,
                reportCount: relatedIOCs.length,
                virusTotal,
            },
            relatedIOCs: relatedIOCs.slice(0, 10),
        },
    });
});

export default domainRoutes;
