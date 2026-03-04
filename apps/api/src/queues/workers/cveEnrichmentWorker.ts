/**
 * CVE Enrichment Worker
 *
 * Enriches vulnerabilities that are missing data:
 * 1. CVSS scores — for CISA KEV entries that arrived without them
 * 2. Published dates — for CVEs missing publishedDate
 *
 * Designed to run as a scheduled BullMQ job (daily) or triggered
 * after CISA sync completes.
 */

import { Worker, Job } from 'bullmq';
import { connection } from '../../services/redis';
import { and, db, eq, isNull } from '@rinjani/db';
import { vulnerabilities } from '@rinjani/db/schema';
import { createLogger } from '../../lib/logger';

export interface CVEEnrichmentJobData {
    type: 'cvss' | 'dates' | 'all';
    batchSize?: number;
}

const NVD_API_KEY = process.env.CVE_API_KEY || '';
const NVD_BASE_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const RATE_LIMIT_MS = NVD_API_KEY ? 700 : 6500;

// ============================================================================
// NVD API Helpers
// ============================================================================

interface NVDMetrics {
    cvssMetricV31?: Array<{ cvssData: { baseScore: number; baseSeverity: string; vectorString: string } }>;
    cvssMetricV30?: Array<{ cvssData: { baseScore: number; baseSeverity: string; vectorString: string } }>;
    cvssMetricV2?: Array<{ cvssData: { baseScore: number; vectorString: string } }>;
}

async function fetchCVEData(cveId: string): Promise<{
    cvss?: { score: number; severity: string; vector: string };
    published?: Date;
    lastModified?: Date;
} | null> {
    try {
        const url = new URL(NVD_BASE_URL);
        url.searchParams.append('cveId', cveId);

        const response = await fetch(url.toString(), {
            headers: NVD_API_KEY ? { apiKey: NVD_API_KEY } : {},
        });

        if (!response.ok) return null;

        const data = await response.json() as { vulnerabilities?: Array<{ cve: { metrics?: NVDMetrics; published?: string; lastModified?: string } }> };
        if (!data.vulnerabilities || data.vulnerabilities.length === 0) return null;

        const cve = data.vulnerabilities[0].cve;
        const metrics: NVDMetrics = cve.metrics || {};

        // Extract CVSS
        let cvss: { score: number; severity: string; vector: string } | undefined;
        if (metrics.cvssMetricV31?.[0]) {
            const d = metrics.cvssMetricV31[0].cvssData;
            cvss = { score: d.baseScore, severity: d.baseSeverity.toLowerCase(), vector: d.vectorString };
        } else if (metrics.cvssMetricV30?.[0]) {
            const d = metrics.cvssMetricV30[0].cvssData;
            cvss = { score: d.baseScore, severity: d.baseSeverity.toLowerCase(), vector: d.vectorString };
        } else if (metrics.cvssMetricV2?.[0]) {
            const d = metrics.cvssMetricV2[0].cvssData;
            const score = d.baseScore;
            const severity = score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low';
            cvss = { score, severity, vector: d.vectorString };
        }

        return {
            cvss,
            published: cve.published ? new Date(cve.published) : undefined,
            lastModified: cve.lastModified ? new Date(cve.lastModified) : undefined,
        };
    } catch {
        return null;
    }
}

// ============================================================================
// Enrichment Functions
// ============================================================================

async function enrichCVSS(log: ReturnType<typeof createLogger>, batchSize: number): Promise<number> {
    // Prioritize exploited CVEs missing CVSS
    const missing = await db.select({
        id: vulnerabilities.id,
        cveId: vulnerabilities.cveId,
    })
        .from(vulnerabilities)
        .where(and(
            eq(vulnerabilities.isExploited, true),
            isNull(vulnerabilities.cvssScore),
        ))
        .limit(batchSize);

    if (missing.length === 0) {
        // Fall back to any CVE missing CVSS
        const anyMissing = await db.select({
            id: vulnerabilities.id,
            cveId: vulnerabilities.cveId,
        })
            .from(vulnerabilities)
            .where(isNull(vulnerabilities.cvssScore))
            .limit(batchSize);

        if (anyMissing.length === 0) {
            log.info('No CVEs missing CVSS scores');
            return 0;
        }
        missing.push(...anyMissing);
    }

    log.info('Enriching CVSS scores', { count: missing.length });
    let enriched = 0;

    for (const vuln of missing) {
        const data = await fetchCVEData(vuln.cveId);
        if (data?.cvss) {
            await db.update(vulnerabilities)
                .set({
                    cvssScore: data.cvss.score.toString(),
                    severity: data.cvss.severity,
                    updatedAt: new Date(),
                })
                .where(eq(vulnerabilities.id, vuln.id));
            enriched++;
            log.debug('CVSS enriched', { cveId: vuln.cveId, score: data.cvss.score });
        }
        await new Promise(r => setTimeout(r, RATE_LIMIT_MS));
    }

    return enriched;
}

async function enrichDates(log: ReturnType<typeof createLogger>, batchSize: number): Promise<number> {
    const missing = await db.select({
        id: vulnerabilities.id,
        cveId: vulnerabilities.cveId,
    })
        .from(vulnerabilities)
        .where(isNull(vulnerabilities.publishedDate))
        .limit(batchSize);

    if (missing.length === 0) {
        log.info('No CVEs missing published dates');
        return 0;
    }

    log.info('Enriching published dates', { count: missing.length });
    let enriched = 0;

    for (const vuln of missing) {
        const data = await fetchCVEData(vuln.cveId);
        if (data?.published) {
            await db.update(vulnerabilities)
                .set({
                    publishedDate: data.published,
                    lastModified: data.lastModified || new Date(),
                    updatedAt: new Date(),
                })
                .where(eq(vulnerabilities.id, vuln.id));
            enriched++;
            log.debug('Date enriched', { cveId: vuln.cveId });
        }
        await new Promise(r => setTimeout(r, RATE_LIMIT_MS));
    }

    return enriched;
}

// ============================================================================
// BullMQ Worker
// ============================================================================

export const cveEnrichmentWorker = new Worker<CVEEnrichmentJobData>(
    'cve-enrichment',
    async (job: Job<CVEEnrichmentJobData>) => {
        const log = createLogger('CVE:Enrich');
        const { type = 'all', batchSize = 50 } = job.data;
        log.info('Processing job', { jobId: job.id, type, batchSize });

        try {
            await job.updateProgress(5);
            let cvssEnriched = 0;
            let datesEnriched = 0;

            if (type === 'cvss' || type === 'all') {
                cvssEnriched = await enrichCVSS(log, batchSize);
                await job.updateProgress(50);
            }

            if (type === 'dates' || type === 'all') {
                datesEnriched = await enrichDates(log, batchSize);
                await job.updateProgress(90);
            }

            await job.updateProgress(100);

            log.info('CVE enrichment complete', { cvssEnriched, datesEnriched });
            return {
                success: true,
                type,
                cvssEnriched,
                datesEnriched,
                completedAt: new Date().toISOString(),
            };
        } catch (error) {
            log.error('Job failed', error as Error, { jobId: job.id });
            throw error;
        }
    },
    {
        connection,
        concurrency: 1, // Only one enrichment at a time (rate limiting)
    }
);
