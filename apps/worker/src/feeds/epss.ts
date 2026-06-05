/**
 * EPSS Sync Worker — FIRST.org's Exploit Prediction Scoring System.
 *
 * Phase 1 (Vulnerability scoring upgrades). EPSS is the most decision-useful
 * signal on top of CVSS we can ship without a vendor partnership: a daily-
 * updated 0-1 score modeling probability of exploitation in the next 30
 * days, plus a corpus-rank percentile. Together with CVSS severity and
 * the CISA-KEV flag, the analyst can answer "what should I patch first?"
 * with three orthogonal signals.
 *
 * Source: https://epss.cyentia.com/epss_scores-current.csv.gz
 *   - Public, no key
 *   - Gzip-compressed CSV (~1.7 MB compressed, ~10 MB uncompressed)
 *   - First line: `#model_version:vYYYY.MM.DD,score_date:ISO8601`
 *   - Second line: `cve,epss,percentile`
 *   - Body: ~250k rows, one per CVE
 *
 * Strategy: download the whole gzipped blob, gunzip in memory, parse, and
 * bulk-UPDATE every row that matches a CVE we already have in our
 * vulnerabilities table. We do NOT INSERT new vulnerabilities from EPSS —
 * EPSS scores CVEs that exist elsewhere; if a CVE isn't in our DB yet,
 * it'll get scored on the next refresh once NVD ingests it.
 *
 * Refresh cadence: once a day. EPSS publishes daily; pulling more often
 * is wasted bandwidth.
 */

import { gunzipSync } from 'node:zlib';
import { db } from '@rinjani/db';
import { syncLogs, vulnerabilities } from '@rinjani/db/schema';
import { sql, inArray } from '@rinjani/db';
import { createLogger } from '../lib/logger';

const log = createLogger('EPSS');

const EPSS_URL = process.env.EPSS_URL || 'https://epss.cyentia.com/epss_scores-current.csv.gz';
const UPDATE_BATCH = 500;

interface SyncResult {
    processed: number;
    matched: number;
    failed: number;
    errors: string[];
}

interface EpssRow {
    cveId: string;
    epss: string;
    percentile: string;
}

async function downloadAndParse(): Promise<EpssRow[]> {
    log.info(`Fetching ${EPSS_URL}`);
    const resp = await fetch(EPSS_URL);
    if (!resp.ok) throw new Error(`EPSS fetch ${resp.status} ${resp.statusText}`);

    const gz = Buffer.from(await resp.arrayBuffer());
    const csvText = gunzipSync(gz).toString('utf8');
    const lines = csvText.split('\n');

    const rows: EpssRow[] = [];
    for (const line of lines) {
        // Skip the model_version / score_date comment header and the
        // column-name row. EPSS puts both at the very top of the file.
        if (!line || line.startsWith('#') || line.startsWith('cve,')) continue;
        // Format: cve,epss,percentile — no quoting, plain numerics.
        const [cveId, epss, percentile] = line.split(',');
        if (!cveId || !epss || !percentile) continue;
        rows.push({ cveId: cveId.trim(), epss: epss.trim(), percentile: percentile.trim() });
    }
    log.info(`Parsed EPSS rows`, { count: rows.length });
    return rows;
}

/**
 * Bulk-UPDATE in batches of `UPDATE_BATCH` CVEs using the VALUES form so
 * we hit Postgres with one statement per batch instead of N round-trips.
 * Returns count of rows actually updated (rows whose cve_id matched ours).
 */
async function applyEpssBatch(batch: EpssRow[]): Promise<number> {
    if (batch.length === 0) return 0;

    // Pre-filter to CVEs we know about — avoids constructing a 250k-row
    // VALUES clause every batch. One SELECT per batch is cheap; the
    // alternative (UPDATE against the full set) generates an enormous
    // query plan.
    const cveIds = batch.map(r => r.cveId);
    const existing = await db.select({ cveId: vulnerabilities.cveId })
        .from(vulnerabilities)
        .where(inArray(vulnerabilities.cveId, cveIds));
    const known = new Set(existing.map(r => r.cveId));
    if (known.size === 0) return 0;

    const present = batch.filter(r => known.has(r.cveId));

    // One UPDATE with FROM VALUES (...) — Postgres applies it as a single
    // pass over the matching rows.
    const valuesSql = sql.join(
        present.map(r =>
            sql`(${r.cveId}::text, ${r.epss}::numeric, ${r.percentile}::numeric)`,
        ),
        sql.raw(', '),
    );
    await db.execute(sql`
        UPDATE vulnerabilities AS v
        SET epss_score = t.score,
            epss_percentile = t.pct,
            epss_updated_at = NOW(),
            updated_at = NOW()
        FROM (VALUES ${valuesSql}) AS t(cve_id, score, pct)
        WHERE v.cve_id = t.cve_id
    `);
    return present.length;
}

export async function syncEPSS(): Promise<SyncResult> {
    const result: SyncResult = { processed: 0, matched: 0, failed: 0, errors: [] };
    try {
        const rows = await downloadAndParse();
        result.processed = rows.length;

        for (let i = 0; i < rows.length; i += UPDATE_BATCH) {
            const slice = rows.slice(i, i + UPDATE_BATCH);
            try {
                const n = await applyEpssBatch(slice);
                result.matched += n;
            } catch (e) {
                result.failed += slice.length;
                if (result.errors.length < 5) {
                    result.errors.push(`batch @${i}: ${(e as Error).message}`);
                }
            }
        }

        log.info('EPSS sync complete', {
            rowsInFeed: result.processed,
            applied: result.matched,
            failed: result.failed,
        });
    } catch (e) {
        log.error('EPSS fetch failed', e);
        result.errors.push(`Fetch error: ${(e as Error).message}`);
    }
    return result;
}

async function logSync(result: SyncResult, startedAt: Date): Promise<void> {
    await db.insert(syncLogs).values({
        entityType: 'epss',
        status: result.failed === 0 ? 'success' : 'partial',
        itemsProcessed: result.matched,
        itemsFailed: result.failed,
        errorMessage: result.errors.length > 0 ? result.errors.slice(0, 5).join('\n') : null,
        startedAt,
        completedAt: new Date(),
    });
}

export async function runEPSSSync(): Promise<void> {
    const startedAt = new Date();
    log.info('Starting EPSS sync');
    try {
        const result = await syncEPSS();
        await logSync(result, startedAt);
        log.info('EPSS sync done');
    } catch (e) {
        log.error('EPSS sync failed', e);
        await logSync({ processed: 0, matched: 0, failed: 1, errors: [(e as Error).message] }, startedAt);
    }
}

if (import.meta.url === `file://${process.argv[1]}`) {
    runEPSSSync()
        .then(() => process.exit(0))
        .catch((error) => {
            console.error(error);
            process.exit(1);
        });
}
