/**
 * Ahmia search client — Phase 5 #4.
 *
 * Queries ahmia.fi's clearnet search index for operator-pinned
 * watchterms. Crucial scope discipline:
 *
 *   - We hit ahmia.fi (clearnet) only. The platform NEVER touches
 *     the Tor network or fetches a .onion URL.
 *   - The index records titles + onion URLs + snippets for Tor
 *     hidden services that have OPTED INTO indexing. Operationally
 *     and legally this is the lightest-touch dark-web signal a
 *     single-VPS CTI platform can wire up.
 *   - Direct .onion crawling (browser, Tor proxy, etc.) is a
 *     documented non-goal — operationally messy and legally fraught
 *     in several jurisdictions.
 *
 * The pure HTML parser is exported so the test suite can pin its
 * behaviour without network. The fetch + upsert path runs in the
 * scheduled worker.
 */
import * as cheerio from 'cheerio';
import { db, eq, sql } from '@rinjani/db';
import { darkWebWatchterms, darkWebMentions } from '@rinjani/db/schema';
import { createLogger } from '../lib/logger';

const log = createLogger('AhmiaSearch');

const AHMIA_SEARCH_URL = 'https://ahmia.fi/search/';
const USER_AGENT = 'RinjaniCTI/1.0 (+https://rinjanianalytics.com)';
const FETCH_TIMEOUT_MS = 15_000;
// Cap snippet storage. Ahmia truncates well below; this is belt + braces.
const MAX_SNIPPET_LEN = 2_000;

// ============================================================================
// Parser — pure, exported for tests
// ============================================================================

export interface AhmiaResult {
    title: string;
    onionUrl: string;
    snippet: string | null;
}

/**
 * Parse Ahmia's search-results HTML into a flat list of `{title, onionUrl, snippet}`.
 *
 * Ahmia's result shape (stable for years):
 *   <li class="result"> | <ol id="ahmiaResultsPage"> with .result > h4 > a@href + cite + p
 *
 * We're conservative: take any element matching the result selectors, prefer
 * the documented structure but fall back to any `<a>` inside a `.result` if
 * the markup shifts.
 */
export function parseAhmiaResults(html: string): AhmiaResult[] {
    const $ = cheerio.load(html);
    const out: AhmiaResult[] = [];

    $('.result, li.result').each((_, el) => {
        const $el = $(el);
        // Prefer the documented title selector; fall back to any first <a>.
        const title = ($el.find('h4').first().text() || $el.find('a').first().text() || '').trim();
        // The onion URL lives in <cite> on Ahmia. Older mirrors use a@href.
        let onionUrl = $el.find('cite').first().text().trim();
        if (!onionUrl) {
            const href = $el.find('a').first().attr('href') ?? '';
            // Ahmia wraps real outbound URLs in /search/redirect?... — peel that off.
            try {
                const u = new URL(href, AHMIA_SEARCH_URL);
                const redirected = u.searchParams.get('redirect_url');
                onionUrl = (redirected ?? href).trim();
            } catch {
                onionUrl = href.trim();
            }
        }

        if (!onionUrl) return;
        // Discard anything that isn't a Tor onion URL — index sometimes shows
        // featured items, donate links, etc. that we don't want as "mentions".
        if (!/\.onion(\/|$)/i.test(onionUrl)) return;

        const snippet = $el.find('p').first().text().trim().slice(0, MAX_SNIPPET_LEN) || null;
        if (title && onionUrl) out.push({ title, onionUrl, snippet });
    });

    return out;
}

// ============================================================================
// Live fetch
// ============================================================================

export async function searchAhmia(term: string): Promise<AhmiaResult[]> {
    const url = new URL(AHMIA_SEARCH_URL);
    url.searchParams.set('q', term);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    let html: string;
    try {
        const r = await fetch(url, {
            headers: {
                'User-Agent': USER_AGENT,
                'Accept': 'text/html,application/xhtml+xml',
            },
            signal: controller.signal,
        });
        if (!r.ok) throw new Error(`Ahmia HTTP ${r.status}`);
        html = await r.text();
    } finally {
        clearTimeout(timer);
    }

    return parseAhmiaResults(html);
}

// ============================================================================
// Scheduled scan — upserts mentions per watchterm
// ============================================================================

export interface ScanSummary {
    termsScanned: number;
    resultsTotal: number;
    mentionsCreated: number;
    mentionsUpdated: number;
    errors: Array<{ term: string; error: string }>;
    durationMs: number;
}

interface WatchtermRow { id: string; term: string }

export async function scanWatchterm(watchtermId: string): Promise<{ term: string; created: number; updated: number; results: number }> {
    const [row] = await db.select({
        id: darkWebWatchterms.id,
        term: darkWebWatchterms.term,
    }).from(darkWebWatchterms).where(eq(darkWebWatchterms.id, watchtermId)).limit(1);
    if (!row) throw new Error(`watchterm ${watchtermId} not found`);
    return scanOne(row);
}

export async function scanAllWatchterms(): Promise<ScanSummary> {
    const t0 = Date.now();
    const rows = await db.select({
        id: darkWebWatchterms.id,
        term: darkWebWatchterms.term,
    }).from(darkWebWatchterms).where(eq(darkWebWatchterms.enabled, true));

    const summary: ScanSummary = {
        termsScanned: 0,
        resultsTotal: 0,
        mentionsCreated: 0,
        mentionsUpdated: 0,
        errors: [],
        durationMs: 0,
    };

    for (const row of rows) {
        try {
            const r = await scanOne(row);
            summary.termsScanned++;
            summary.resultsTotal += r.results;
            summary.mentionsCreated += r.created;
            summary.mentionsUpdated += r.updated;
        } catch (err) {
            summary.errors.push({ term: row.term, error: (err as Error).message });
        }
    }

    summary.durationMs = Date.now() - t0;
    log.info('Ahmia scan complete', summary as unknown as Record<string, unknown>);
    return summary;
}

async function scanOne(row: WatchtermRow): Promise<{ term: string; created: number; updated: number; results: number }> {
    const results = await searchAhmia(row.term);
    const now = new Date();
    let created = 0, updated = 0;

    for (const r of results) {
        const ret = await db.insert(darkWebMentions).values({
            watchtermId: row.id,
            source: 'ahmia',
            title: r.title.slice(0, 4000),
            onionUrl: r.onionUrl,
            snippet: r.snippet,
            firstSeenAt: now,
            lastSeenAt: now,
        }).onConflictDoUpdate({
            target: [darkWebMentions.watchtermId, darkWebMentions.source, darkWebMentions.onionUrl],
            set: {
                title: r.title.slice(0, 4000),
                snippet: r.snippet,
                lastSeenAt: now,
                updatedAt: now,
            },
        }).returning({ createdAt: darkWebMentions.createdAt });

        const ts = ret[0]?.createdAt?.getTime?.();
        if (ts && Math.abs(ts - now.getTime()) < 2_000) created++;
        else updated++;
    }

    await db.update(darkWebWatchterms)
        .set({ lastSearchedAt: now, updatedAt: now })
        .where(eq(darkWebWatchterms.id, row.id));

    return { term: row.term, results: results.length, created, updated };
}

// Silence unused-import warning until follow-on uses it.
export const _reserved = { sql };
