/**
 * Joe Sandbox client. Phase 4 #5 follow-on.
 *
 * API: https://jbxcloud.joesecurity.org/userguide?sphinx=1
 *   POST /api/v2/submission/new          → submit (returns submission_id + webids)
 *   GET  /api/v2/submission/info         → status + analyses
 *   GET  /api/v2/analysis/info           → per-analysis report detail
 *
 * Joe Sandbox auth is *form-encoded* — the API key is sent as the
 * `apikey` form field on every request rather than via a header.
 */
import { createLogger } from '../../lib/logger';
import type { SandboxSubmissionType } from '@rinjani/db/schema';

const log = createLogger('JoeSandbox');

const JOE_BASE = (process.env.JOESANDBOX_BASE_URL || 'https://jbxcloud.joesecurity.org').replace(/\/+$/, '');

export interface JoeSubmitInput {
    value: string;
    type: SandboxSubmissionType;
    options?: Record<string, unknown>;
}
export interface JoeSubmitResult { ok: boolean; taskId?: string; reportUrl?: string; error?: string }
export interface JoeReportResult {
    ok: boolean;
    status?: 'queued' | 'running' | 'completed' | 'failed' | 'timeout';
    verdict?: 'malicious' | 'suspicious' | 'benign' | 'unknown';
    score?: number;
    reportUrl?: string;
    raw?: Record<string, unknown>;
    error?: string;
}

function getApiKey(): string | null {
    return process.env.JOESANDBOX_API_KEY?.trim() || null;
}

export async function joeSubmit(input: JoeSubmitInput): Promise<JoeSubmitResult> {
    const key = getApiKey();
    if (!key) return { ok: false, error: 'JOESANDBOX_API_KEY not configured' };

    if (input.type !== 'url' && input.type !== 'hash') {
        // File upload requires multipart streaming; deferred.
        return { ok: false, error: `submission type "${input.type}" not yet supported by the Joe Sandbox client` };
    }

    const form = new FormData();
    form.append('apikey', key);
    form.append('accept-tac', '1');
    if (input.type === 'url') {
        form.append('url', input.value);
    } else {
        // Hash lookup is a separate endpoint in Joe Sandbox; absent a hash
        // submission API in the free tier, surface a clear error.
        return { ok: false, error: 'Joe Sandbox hash lookup endpoint not wired yet' };
    }
    for (const [k, v] of Object.entries(input.options ?? {})) {
        if (v != null) form.append(k, String(v));
    }

    try {
        const r = await fetch(`${JOE_BASE}/api/v2/submission/new`, { method: 'POST', body: form });
        if (!r.ok) {
            const body = await r.text().catch(() => '');
            return { ok: false, error: `Joe Sandbox submit HTTP ${r.status}: ${body.slice(0, 200)}` };
        }
        const body = await r.json() as { data?: { submission_id?: number | string; webids?: Array<string | number> } };
        const id = body?.data?.submission_id ?? body?.data?.webids?.[0];
        if (id == null) return { ok: false, error: `Joe Sandbox submit returned no id: ${JSON.stringify(body).slice(0, 200)}` };
        const taskId = String(id);
        return { ok: true, taskId, reportUrl: `${JOE_BASE}/analysis/${taskId}` };
    } catch (err) {
        return { ok: false, error: (err as Error).message };
    }
}

export async function joeGetReport(taskId: string): Promise<JoeReportResult> {
    const key = getApiKey();
    if (!key) return { ok: false, error: 'JOESANDBOX_API_KEY not configured' };

    const form = new FormData();
    form.append('apikey', key);
    form.append('submission_id', taskId);
    try {
        const r = await fetch(`${JOE_BASE}/api/v2/submission/info`, { method: 'POST', body: form });
        if (!r.ok) {
            const body = await r.text().catch(() => '');
            return { ok: false, error: `Joe Sandbox report HTTP ${r.status}: ${body.slice(0, 200)}` };
        }
        const body = await r.json() as Record<string, unknown>;
        const mapped = mapJoeReport(body);
        return { ...mapped, ok: true, raw: body, reportUrl: `${JOE_BASE}/analysis/${taskId}` };
    } catch (err) {
        return { ok: false, error: (err as Error).message };
    }
}

/**
 * Map Joe Sandbox's response shape into our normalised fields.
 *
 * `data.status` is one of "submitted | running | finished | error";
 * `data.analyses[0].detection` is "malicious | suspicious | clean |
 * unknown"; `data.analyses[0].score` is 0-100.
 */
export function mapJoeReport(payload: Record<string, unknown>): {
    status?: JoeReportResult['status'];
    verdict?: JoeReportResult['verdict'];
    score?: number;
} {
    const data = (payload as { data?: Record<string, unknown> }).data ?? payload;
    const statusRaw = (data as { status?: string }).status?.toLowerCase();
    const status = ((): JoeReportResult['status'] | undefined => {
        switch (statusRaw) {
            case 'submitted': case 'queued': return 'queued';
            case 'running': case 'processing': return 'running';
            case 'finished': case 'done': case 'completed': return 'completed';
            case 'error': case 'failed': return 'failed';
            case 'timeout': case 'timed_out': return 'timeout';
            default: return undefined;
        }
    })();

    const first = ((data as { analyses?: Array<Record<string, unknown>> }).analyses ?? [])[0];
    const detectionRaw = (first as { detection?: string } | undefined)?.detection?.toLowerCase();
    const verdict = ((): JoeReportResult['verdict'] | undefined => {
        switch (detectionRaw) {
            case 'malicious': return 'malicious';
            case 'suspicious': return 'suspicious';
            case 'clean': case 'benign': return 'benign';
            case 'unknown': return 'unknown';
            default: return undefined;
        }
    })();

    const rawScore = (first as { score?: number } | undefined)?.score;
    const score = typeof rawScore === 'number' ? Math.max(0, Math.min(100, rawScore)) : undefined;

    if (status === 'completed') log.debug('Joe Sandbox report mapped', { status, verdict, score });
    return { status, verdict, score };
}
