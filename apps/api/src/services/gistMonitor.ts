/**
 * Paste-site monitor — GitHub Gist firehose. Phase 5 #5.
 *
 * Polls `GET /gists/public` for recently-created public gists and
 * matches each against the operator's `paste_watchterms`. A match
 * fires when a watchterm substring appears (case-insensitively) in:
 *   - the gist description
 *   - any filename in the gist
 *
 * We intentionally do NOT fetch raw gist content (yet) — it would
 * double the rate-limit cost per poll and most useful CTI signal
 * (brand names, project names, leaked-cred indicators) already
 * shows up in filenames / descriptions. Content-grep can be a
 * follow-on with a per-watchterm strictness toggle.
 *
 * Auth: GitHub's `/gists/public` is anonymous-readable at 60 req/h.
 * If `GITHUB_TICKETING_TOKEN` is set (already in .env from PR #72),
 * we send it as Bearer auth → 5000 req/h. The token has no special
 * scope requirement for this endpoint.
 *
 * Scope discipline for this PR:
 *   - YES: GitHub Gist firehose
 *   - NO:  Telegram channels (needs bot token + per-channel
 *          subscription; different operational shape)
 *   - NO:  Pastebin (free `/scrape` endpoint deprecated, paid
 *          firehose intentionally out of scope)
 */
import { db, eq } from '@rinjani/db';
import { pasteWatchterms, pasteMentions } from '@rinjani/db/schema';
import { createLogger } from '../lib/logger';

const log = createLogger('GistMonitor');

const GITHUB_API = 'https://api.github.com';
const USER_AGENT = 'RinjaniCTI/1.0 (+https://rinjanianalytics.com)';
const FETCH_TIMEOUT_MS = 15_000;
// How many `/gists/public` pages we walk per run. 3 pages × 30/page = 90
// gists per run; with a 30-min cron that's 4320/day, well above the typical
// public-gist creation rate.
const MAX_PAGES = 3;
const PER_PAGE = 30;
const MAX_SNIPPET_LEN = 1_000;

// ============================================================================
// Types
// ============================================================================

interface GistAPIRow {
    id: string;
    html_url: string;
    description: string | null;
    created_at: string;
    updated_at: string;
    owner?: { login?: string } | null;
    files?: Record<string, { filename?: string; type?: string; language?: string }>;
}

export interface NormalisedGist {
    id: string;
    htmlUrl: string;
    owner: string | null;
    description: string;
    /** Filenames joined by ' | ' — used both for matching and display. */
    filenames: string[];
    /** Combined searchable text: description + filenames, all lower-cased. */
    searchable: string;
}

// ============================================================================
// Pure helpers — exported for tests
// ============================================================================

export function normaliseGist(g: GistAPIRow): NormalisedGist {
    const files = g.files ?? {};
    const filenames = Object.keys(files).map(k => (files[k]?.filename ?? k));
    const description = g.description ?? '';
    return {
        id: g.id,
        htmlUrl: g.html_url,
        owner: g.owner?.login ?? null,
        description,
        filenames,
        searchable: `${description} ${filenames.join(' ')}`.toLowerCase(),
    };
}

export interface GistMatch {
    watchtermId: string;
    term: string;
    gist: NormalisedGist;
    matchedFilename: string | null;
}

/**
 * For each enabled watchterm, find every gist whose searchable text
 * contains the term (case-insensitively). One gist can match multiple
 * watchterms — emit one row per (watchterm, gist) pair.
 */
export function findMatches(
    watchterms: Array<{ id: string; term: string }>,
    gists: NormalisedGist[],
): GistMatch[] {
    const out: GistMatch[] = [];
    for (const wt of watchterms) {
        const needle = wt.term.toLowerCase();
        if (needle.length === 0) continue;
        for (const g of gists) {
            if (!g.searchable.includes(needle)) continue;
            const filename = g.filenames.find(f => f.toLowerCase().includes(needle)) ?? null;
            out.push({ watchtermId: wt.id, term: wt.term, gist: g, matchedFilename: filename });
        }
    }
    return out;
}

// ============================================================================
// GitHub fetch
// ============================================================================

function authHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
        'User-Agent': USER_AGENT,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
    };
    const token = process.env.GITHUB_TICKETING_TOKEN?.trim();
    if (token) headers['Authorization'] = `Bearer ${token}`;
    return headers;
}

async function fetchGistPage(page: number): Promise<GistAPIRow[]> {
    const url = new URL(`${GITHUB_API}/gists/public`);
    url.searchParams.set('per_page', String(PER_PAGE));
    url.searchParams.set('page', String(page));
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
    try {
        const r = await fetch(url, { headers: authHeaders(), signal: controller.signal });
        if (!r.ok) throw new Error(`GitHub /gists/public HTTP ${r.status}`);
        return await r.json() as GistAPIRow[];
    } finally {
        clearTimeout(timer);
    }
}

// ============================================================================
// Scheduled scan
// ============================================================================

export interface ScanSummary {
    pagesFetched: number;
    gistsScanned: number;
    watchtermsActive: number;
    matchesCreated: number;
    matchesUpdated: number;
    durationMs: number;
    error?: string;
}

export async function runGistScan(): Promise<ScanSummary> {
    const t0 = Date.now();

    const watchterms = await db.select({
        id: pasteWatchterms.id,
        term: pasteWatchterms.term,
    }).from(pasteWatchterms).where(eq(pasteWatchterms.enabled, true));

    if (watchterms.length === 0) {
        log.info('No enabled watchterms — skipping gist scan');
        return {
            pagesFetched: 0, gistsScanned: 0, watchtermsActive: 0,
            matchesCreated: 0, matchesUpdated: 0,
            durationMs: Date.now() - t0,
        };
    }

    const gists: NormalisedGist[] = [];
    let pagesFetched = 0;
    let fetchError: string | undefined;
    try {
        for (let page = 1; page <= MAX_PAGES; page++) {
            const rows = await fetchGistPage(page);
            pagesFetched++;
            if (rows.length === 0) break;
            for (const row of rows) gists.push(normaliseGist(row));
            if (rows.length < PER_PAGE) break; // last page
        }
    } catch (err) {
        fetchError = (err as Error).message;
        log.warn('Gist firehose fetch failed', { error: fetchError, pagesFetched });
    }

    const matches = findMatches(watchterms, gists);

    let created = 0, updated = 0;
    const now = new Date();
    for (const m of matches) {
        try {
            const snippet = buildSnippet(m).slice(0, MAX_SNIPPET_LEN);
            const ret = await db.insert(pasteMentions).values({
                watchtermId: m.watchtermId,
                source: 'github_gist',
                author: m.gist.owner,
                filename: m.matchedFilename ?? m.gist.filenames[0] ?? null,
                title: m.gist.description || null,
                externalUrl: m.gist.htmlUrl,
                externalId: m.gist.id,
                snippet,
                firstSeenAt: now,
                lastSeenAt: now,
            }).onConflictDoUpdate({
                target: [pasteMentions.watchtermId, pasteMentions.source, pasteMentions.externalId],
                set: {
                    title: m.gist.description || null,
                    snippet,
                    lastSeenAt: now,
                    updatedAt: now,
                },
            }).returning({ createdAt: pasteMentions.createdAt });
            const ts = ret[0]?.createdAt?.getTime?.();
            if (ts && Math.abs(ts - now.getTime()) < 2_000) created++;
            else updated++;
        } catch (err) {
            log.warn('Paste mention upsert failed', {
                watchtermId: m.watchtermId, externalId: m.gist.id, error: (err as Error).message,
            });
        }
    }

    // Bump last_searched_at on every watchterm we ran so the UI can render
    // "last checked X ago" even when the term has no recent hits.
    if (watchterms.length > 0) {
        await db.update(pasteWatchterms)
            .set({ lastSearchedAt: now, updatedAt: now })
            .where(eq(pasteWatchterms.enabled, true));
    }

    const summary: ScanSummary = {
        pagesFetched,
        gistsScanned: gists.length,
        watchtermsActive: watchterms.length,
        matchesCreated: created,
        matchesUpdated: updated,
        durationMs: Date.now() - t0,
        ...(fetchError ? { error: fetchError } : {}),
    };
    log.info('Gist scan complete', summary as unknown as Record<string, unknown>);
    return summary;
}

function buildSnippet(m: GistMatch): string {
    const head = m.gist.description ? `desc="${m.gist.description}"` : '';
    const files = m.gist.filenames.length > 0 ? `files=${m.gist.filenames.slice(0, 5).join(', ')}` : '';
    return [head, files].filter(Boolean).join(' | ');
}
