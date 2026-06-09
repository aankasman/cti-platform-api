/**
 * JIRA Cloud client. Phase 4 #6 follow-on — second ticketing vendor.
 *
 * API: https://developer.atlassian.com/cloud/jira/platform/rest/v3/
 *   POST /rest/api/3/issue                       → create (returns key like "RIN-42")
 *   GET  /rest/api/3/issue/{issueIdOrKey}        → fetch one
 *   POST /rest/api/3/issue/{issueIdOrKey}/comment → add comment
 *
 * Auth: Basic <base64(email:api_token)>. API tokens come from
 * id.atlassian.com (the per-user PAT analogue). JIRA Server / Data
 * Center installs that still use the v2 endpoints would need a
 * separate adapter; this client targets Cloud (v3).
 *
 * The description + comment bodies use Atlassian Document Format
 * (ADF) — a nested JSON shape. For our MVP we wrap plain text in
 * the minimal ADF envelope; rich content can come later.
 *
 * Behaviour without credentials:
 *   - All three calls return { ok: false, error: 'not configured' }.
 *     The route layer responds 502.
 */
import { createLogger } from '../../lib/logger';
import type { TicketStatus } from '@rinjani/db/schema';

const log = createLogger('JIRA');

function getConfig(): { baseUrl: string; email: string; token: string } | null {
    const baseUrl = process.env.JIRA_BASE_URL?.trim();
    const email = process.env.JIRA_EMAIL?.trim();
    const token = process.env.JIRA_API_TOKEN?.trim();
    if (!baseUrl || !email || !token) return null;
    return { baseUrl: baseUrl.replace(/\/+$/, ''), email, token };
}

function authHeaders(cfg: { email: string; token: string }): Record<string, string> {
    const basic = Buffer.from(`${cfg.email}:${cfg.token}`).toString('base64');
    return {
        'Authorization': `Basic ${basic}`,
        'Accept': 'application/json',
        'User-Agent': 'RinjaniCTI/1.0 (+https://rinjanianalytics.com)',
    };
}

/** Wrap a plain string in the minimal ADF envelope JIRA expects. */
function adfParagraph(text: string): Record<string, unknown> {
    return {
        type: 'doc',
        version: 1,
        content: [{
            type: 'paragraph',
            content: [{ type: 'text', text }],
        }],
    };
}

// ============================================================================
// Public API
// ============================================================================

export interface JiraCreateInput {
    repo: string;             // JIRA project key (e.g., "RIN")
    title: string;
    body?: string;
    labels?: string[];
    issueType?: string;       // default 'Task'
}
export interface JiraCreateResult {
    ok: boolean;
    issueKey?: string;        // e.g., "RIN-42"
    issueUrl?: string;
    error?: string;
}

export async function jiraCreateIssue(input: JiraCreateInput): Promise<JiraCreateResult> {
    const cfg = getConfig();
    if (!cfg) return { ok: false, error: 'JIRA credentials not configured (need JIRA_BASE_URL + JIRA_EMAIL + JIRA_API_TOKEN)' };

    if (!input.repo || !input.repo.trim()) {
        return { ok: false, error: 'JIRA project key required' };
    }

    const payload: Record<string, unknown> = {
        fields: {
            project: { key: input.repo.trim() },
            summary: input.title.slice(0, 255), // JIRA caps summary at 255
            issuetype: { name: input.issueType ?? 'Task' },
            ...(input.body && input.body.length > 0
                ? { description: adfParagraph(input.body) }
                : {}),
            ...(input.labels && input.labels.length > 0
                ? { labels: input.labels.slice(0, 50) }
                : {}),
        },
    };

    try {
        const r = await fetch(`${cfg.baseUrl}/rest/api/3/issue`, {
            method: 'POST',
            headers: { ...authHeaders(cfg), 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        if (!r.ok) {
            const body = await r.text().catch(() => '');
            return { ok: false, error: `JIRA create HTTP ${r.status}: ${body.slice(0, 200)}` };
        }
        const body = await r.json() as { key?: string; id?: string; self?: string };
        if (!body.key) {
            return { ok: false, error: `JIRA create returned no key: ${JSON.stringify(body).slice(0, 200)}` };
        }
        return {
            ok: true,
            issueKey: body.key,
            // JIRA's `self` field points at the REST URL, not the browser one.
            // Construct the human-facing URL from base + key.
            issueUrl: `${cfg.baseUrl}/browse/${body.key}`,
        };
    } catch (err) {
        return { ok: false, error: (err as Error).message };
    }
}

export interface JiraGetInput {
    repo: string;             // unused — JIRA issue keys are globally unique within a tenant, repo is informational only
    issueNumber: number | string;
}
export interface JiraGetResult {
    ok: boolean;
    status?: TicketStatus;
    title?: string;
    labels?: string[];
    issueUrl?: string;
    raw?: Record<string, unknown>;
    error?: string;
}

export async function jiraGetIssue(input: JiraGetInput): Promise<JiraGetResult> {
    const cfg = getConfig();
    if (!cfg) return { ok: false, error: 'JIRA credentials not configured' };

    try {
        const r = await fetch(
            `${cfg.baseUrl}/rest/api/3/issue/${encodeURIComponent(String(input.issueNumber))}`,
            { method: 'GET', headers: authHeaders(cfg) },
        );
        if (!r.ok) {
            const body = await r.text().catch(() => '');
            return { ok: false, error: `JIRA fetch HTTP ${r.status}: ${body.slice(0, 200)}` };
        }
        const body = await r.json() as Record<string, unknown>;
        const mapped = mapJiraIssue(body);
        return {
            ...mapped,
            ok: true,
            raw: body,
            issueUrl: `${cfg.baseUrl}/browse/${input.issueNumber}`,
        };
    } catch (err) {
        return { ok: false, error: (err as Error).message };
    }
}

export interface JiraCommentInput {
    repo: string;
    issueNumber: number | string;
    body: string;
}
export interface JiraCommentResult { ok: boolean; commentUrl?: string; error?: string }

export async function jiraAddComment(input: JiraCommentInput): Promise<JiraCommentResult> {
    const cfg = getConfig();
    if (!cfg) return { ok: false, error: 'JIRA credentials not configured' };
    if (!input.body || input.body.trim().length === 0) return { ok: false, error: 'comment body required' };

    try {
        const r = await fetch(
            `${cfg.baseUrl}/rest/api/3/issue/${encodeURIComponent(String(input.issueNumber))}/comment`,
            {
                method: 'POST',
                headers: { ...authHeaders(cfg), 'Content-Type': 'application/json' },
                body: JSON.stringify({ body: adfParagraph(input.body.slice(0, 32_000)) }),
            },
        );
        if (!r.ok) {
            const body = await r.text().catch(() => '');
            return { ok: false, error: `JIRA comment HTTP ${r.status}: ${body.slice(0, 200)}` };
        }
        const body = await r.json() as { id?: string; self?: string };
        return {
            ok: true,
            // JIRA's `self` is the REST URL; the human-facing URL is the issue + #fragment.
            commentUrl: `${cfg.baseUrl}/browse/${input.issueNumber}${body.id ? `?focusedCommentId=${body.id}` : ''}`,
        };
    } catch (err) {
        return { ok: false, error: (err as Error).message };
    }
}

// ============================================================================
// Pure mapper — vendor shape → our normalised shape.
// ============================================================================

/**
 * JIRA's status names are workflow-defined per project but the
 * `statusCategory.key` is a fixed three-value enum: "new" | "indeterminate"
 * | "done". We use that for the open/closed mapping so it's resilient to
 * custom workflow names like "Triaged" or "Awaiting QA".
 *
 * Labels are a top-level string array on `fields.labels`.
 */
export function mapJiraIssue(payload: Record<string, unknown>): {
    status: TicketStatus;
    title: string;
    labels: string[];
} {
    const fields = (payload.fields as Record<string, unknown> | undefined) ?? {};
    const statusObj = fields.status as { statusCategory?: { key?: string } } | undefined;
    const categoryKey = statusObj?.statusCategory?.key?.toLowerCase();
    const status: TicketStatus = ((): TicketStatus => {
        switch (categoryKey) {
            case 'done': return 'closed';
            case 'new':
            case 'indeterminate': return 'open';
            default: return 'unknown';
        }
    })();

    const title = (fields.summary as string | undefined) ?? '';
    const labelsRaw = fields.labels;
    const labels = Array.isArray(labelsRaw)
        ? labelsRaw.filter((l): l is string => typeof l === 'string')
        : [];

    if (status === 'closed') log.debug('JIRA issue mapped to closed', { title });
    return { status, title, labels };
}
