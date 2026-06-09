/**
 * GitHub Issues client. Phase 4 #6 — first ticketing vendor wired.
 *
 * API: https://docs.github.com/en/rest/issues
 *   POST /repos/{owner}/{repo}/issues                  → create
 *   GET  /repos/{owner}/{repo}/issues/{issue_number}   → fetch one
 *   POST /repos/{owner}/{repo}/issues/{issue_number}/comments → add comment
 *
 * Auth: `Authorization: Bearer <GITHUB_TICKETING_TOKEN>`. A separate env
 * var from the existing OAuth tokens — operators typically want a
 * fine-grained PAT scoped to "issues:write" on a single repo for this.
 *
 * Behaviour without a token:
 *   - Every call returns { ok: false, error: 'not configured' } so the
 *     route layer responds 503 rather than crashing.
 */
import { createLogger } from '../../lib/logger';
import type { TicketStatus } from '@rinjani/db/schema';

const log = createLogger('GitHubIssues');

const GH_API = (process.env.GITHUB_API_BASE_URL || 'https://api.github.com').replace(/\/+$/, '');
const GH_API_VERSION = '2022-11-28';

function getApiToken(): string | null {
    return process.env.GITHUB_TICKETING_TOKEN?.trim() || null;
}

function authHeaders(token: string): Record<string, string> {
    return {
        'Authorization': `Bearer ${token}`,
        'X-GitHub-Api-Version': GH_API_VERSION,
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'RinjaniCTI/1.0 (+https://rinjanianalytics.com)',
    };
}

/**
 * Split `owner/repo` and reject anything else. GitHub's API will 404
 * on bad shapes anyway but failing fast gives a clearer error.
 */
function parseRepo(repo: string): { owner: string; name: string } | null {
    const m = repo.trim().match(/^([^/\s]+)\/([^/\s]+)$/);
    if (!m) return null;
    return { owner: m[1], name: m[2] };
}

// ============================================================================
// Public API
// ============================================================================

export interface GhCreateInput {
    repo: string;             // "owner/repo"
    title: string;
    body?: string;
    labels?: string[];
}
export interface GhCreateResult {
    ok: boolean;
    issueNumber?: number;
    issueUrl?: string;
    error?: string;
}

export async function ghCreateIssue(input: GhCreateInput): Promise<GhCreateResult> {
    const token = getApiToken();
    if (!token) return { ok: false, error: 'GITHUB_TICKETING_TOKEN not configured' };

    const repo = parseRepo(input.repo);
    if (!repo) return { ok: false, error: `invalid repo "${input.repo}" — expected "owner/repo"` };

    const payload: Record<string, unknown> = {
        title: input.title.slice(0, 256), // GitHub caps at 256
        body: input.body ?? '',
    };
    if (input.labels && input.labels.length > 0) payload.labels = input.labels;

    try {
        const r = await fetch(`${GH_API}/repos/${repo.owner}/${repo.name}/issues`, {
            method: 'POST',
            headers: { ...authHeaders(token), 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (!r.ok) {
            const body = await r.text().catch(() => '');
            return { ok: false, error: `GitHub create HTTP ${r.status}: ${body.slice(0, 200)}` };
        }
        const body = await r.json() as { number?: number; html_url?: string };
        if (!body.number || !body.html_url) {
            return { ok: false, error: `GitHub create returned no number/url: ${JSON.stringify(body).slice(0, 200)}` };
        }
        return { ok: true, issueNumber: body.number, issueUrl: body.html_url };
    } catch (err) {
        return { ok: false, error: (err as Error).message };
    }
}

export interface GhGetInput {
    repo: string;
    issueNumber: number | string;
}
export interface GhGetResult {
    ok: boolean;
    status?: TicketStatus;
    title?: string;
    labels?: string[];
    issueUrl?: string;
    raw?: Record<string, unknown>;
    error?: string;
}

export async function ghGetIssue(input: GhGetInput): Promise<GhGetResult> {
    const token = getApiToken();
    if (!token) return { ok: false, error: 'GITHUB_TICKETING_TOKEN not configured' };

    const repo = parseRepo(input.repo);
    if (!repo) return { ok: false, error: `invalid repo "${input.repo}"` };

    try {
        const r = await fetch(
            `${GH_API}/repos/${repo.owner}/${repo.name}/issues/${encodeURIComponent(String(input.issueNumber))}`,
            { method: 'GET', headers: authHeaders(token) },
        );
        if (!r.ok) {
            const body = await r.text().catch(() => '');
            return { ok: false, error: `GitHub fetch HTTP ${r.status}: ${body.slice(0, 200)}` };
        }
        const body = await r.json() as Record<string, unknown>;
        const mapped = mapGhIssue(body);
        return { ...mapped, ok: true, raw: body, issueUrl: (body.html_url as string | undefined) };
    } catch (err) {
        return { ok: false, error: (err as Error).message };
    }
}

export interface GhCommentInput {
    repo: string;
    issueNumber: number | string;
    body: string;
}
export interface GhCommentResult { ok: boolean; commentUrl?: string; error?: string }

export async function ghAddComment(input: GhCommentInput): Promise<GhCommentResult> {
    const token = getApiToken();
    if (!token) return { ok: false, error: 'GITHUB_TICKETING_TOKEN not configured' };

    const repo = parseRepo(input.repo);
    if (!repo) return { ok: false, error: `invalid repo "${input.repo}"` };
    if (!input.body || input.body.trim().length === 0) return { ok: false, error: 'comment body required' };

    try {
        const r = await fetch(
            `${GH_API}/repos/${repo.owner}/${repo.name}/issues/${encodeURIComponent(String(input.issueNumber))}/comments`,
            {
                method: 'POST',
                headers: { ...authHeaders(token), 'Content-Type': 'application/json' },
                body: JSON.stringify({ body: input.body.slice(0, 65536) }),
            },
        );
        if (!r.ok) {
            const body = await r.text().catch(() => '');
            return { ok: false, error: `GitHub comment HTTP ${r.status}: ${body.slice(0, 200)}` };
        }
        const body = await r.json() as { html_url?: string };
        return { ok: true, commentUrl: body.html_url };
    } catch (err) {
        return { ok: false, error: (err as Error).message };
    }
}

// ============================================================================
// Pure mapper — vendor shape → our normalised shape.
// ============================================================================

/**
 * Map a GitHub issue payload to our normalised fields. Pure function,
 * no I/O — covered by the unit tests so a vendor shape change shows up
 * loudly in CI.
 *
 * GitHub's REST returns `state: "open" | "closed"`, plus a labels array
 * of objects with a `name` field.
 */
export function mapGhIssue(payload: Record<string, unknown>): {
    status: TicketStatus;
    title: string;
    labels: string[];
} {
    const stateRaw = (payload.state as string | undefined)?.toLowerCase();
    const status: TicketStatus = stateRaw === 'open' || stateRaw === 'closed' ? (stateRaw as TicketStatus) : 'unknown';
    const title = (payload.title as string | undefined) ?? '';
    const labelsArr = Array.isArray(payload.labels) ? payload.labels : [];
    const labels = labelsArr
        .map(l => (typeof l === 'string' ? l : (l as { name?: string })?.name))
        .filter((n): n is string => typeof n === 'string');

    if (status === 'closed') log.debug('GitHub issue mapped to closed', { title });
    return { status, title, labels };
}
