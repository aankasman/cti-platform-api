/**
 * ANY.RUN sandbox client. Phase 4 #5 — first sandbox vendor wired.
 *
 * API: https://any.run/api-documentation/
 *   POST https://api.any.run/v1/analysis      → submit (returns task uuid)
 *   GET  https://api.any.run/v1/analysis/{id} → get status + report
 *
 * Auth: Authorization: API-Key <ANYRUN_API_KEY>
 *
 * Behaviour without a key:
 *   - Both calls return { ok: false, error: 'not configured' } so callers
 *     can surface the configuration gap without blowing up. The route
 *     layer responds 503 in that case.
 */
import { createLogger } from '../../lib/logger';
import type { SandboxSubmissionType } from '@rinjani/db/schema';

const log = createLogger('AnyRun');

const ANYRUN_BASE = 'https://api.any.run/v1';

export interface AnyRunSubmitInput {
    /** What to submit. URL for type=url; file hash (sha256) for type=hash. */
    value: string;
    type: SandboxSubmissionType;
    /** Per-submission options the caller wants to forward to the vendor (env, locale, …). */
    options?: Record<string, unknown>;
}

export interface AnyRunSubmitResult {
    ok: boolean;
    taskId?: string;
    reportUrl?: string;
    error?: string;
}

export interface AnyRunReportResult {
    ok: boolean;
    /** Normalised lifecycle status. */
    status?: 'queued' | 'running' | 'completed' | 'failed' | 'timeout';
    /** Normalised verdict — only present once `status === 'completed'`. */
    verdict?: 'malicious' | 'suspicious' | 'benign' | 'unknown';
    /** Normalised 0-100 risk score. */
    score?: number;
    reportUrl?: string;
    raw?: Record<string, unknown>;
    error?: string;
}

function getApiKey(): string | null {
    return process.env.ANYRUN_API_KEY?.trim() || null;
}

/** Submit a URL or hash to ANY.RUN for detonation. */
export async function anyRunSubmit(input: AnyRunSubmitInput): Promise<AnyRunSubmitResult> {
    const key = getApiKey();
    if (!key) return { ok: false, error: 'ANYRUN_API_KEY not configured' };

    if (input.type !== 'url' && input.type !== 'hash') {
        // Other submission types (file upload) need multipart streaming
        // which the scaffold defers until we wire the upload route.
        return { ok: false, error: `submission type "${input.type}" not yet supported by the ANY.RUN client` };
    }

    const form = new FormData();
    form.append('obj_type', input.type === 'url' ? 'url' : 'hash');
    if (input.type === 'url') form.append('obj_url', input.value);
    else form.append('obj_hash', input.value);
    for (const [k, v] of Object.entries(input.options ?? {})) {
        if (v != null) form.append(k, String(v));
    }

    try {
        const r = await fetch(`${ANYRUN_BASE}/analysis`, {
            method: 'POST',
            headers: { Authorization: `API-Key ${key}` },
            body: form,
        });
        if (!r.ok) {
            const body = await r.text().catch(() => '');
            return { ok: false, error: `ANY.RUN submit HTTP ${r.status}: ${body.slice(0, 200)}` };
        }
        const body = await r.json() as { data?: { taskid?: string } };
        const taskId = body?.data?.taskid;
        if (!taskId) return { ok: false, error: `ANY.RUN submit returned no task id: ${JSON.stringify(body).slice(0, 200)}` };
        return {
            ok: true,
            taskId,
            reportUrl: `https://app.any.run/tasks/${taskId}/`,
        };
    } catch (err) {
        return { ok: false, error: (err as Error).message };
    }
}

/** Fetch the latest status/report for a previously-submitted task. */
export async function anyRunGetReport(taskId: string): Promise<AnyRunReportResult> {
    const key = getApiKey();
    if (!key) return { ok: false, error: 'ANYRUN_API_KEY not configured' };

    try {
        const r = await fetch(`${ANYRUN_BASE}/analysis/${encodeURIComponent(taskId)}`, {
            method: 'GET',
            headers: { Authorization: `API-Key ${key}` },
        });
        if (!r.ok) {
            const body = await r.text().catch(() => '');
            return { ok: false, error: `ANY.RUN report HTTP ${r.status}: ${body.slice(0, 200)}` };
        }
        const body = await r.json() as Record<string, unknown>;
        const mapped = mapAnyRunReport(body);
        return { ...mapped, ok: true, raw: body, reportUrl: `https://app.any.run/tasks/${taskId}/` };
    } catch (err) {
        return { ok: false, error: (err as Error).message };
    }
}

/**
 * Map ANY.RUN's report shape into our normalised fields.
 * Pure function — no I/O. Tested independently of the HTTP layer.
 *
 * ANY.RUN's `analysis.scores.verdict` block is the canonical source of
 * truth: `verdict.threat_level` is a 0-3 enum (0=undetected, 1=info,
 * 2=suspicious, 3=malicious); `verdict.score` is 0-100. Status is
 * carried separately at `analysis.status`.
 */
export function mapAnyRunReport(payload: Record<string, unknown>): {
    status?: AnyRunReportResult['status'];
    verdict?: AnyRunReportResult['verdict'];
    score?: number;
} {
    const analysis = (payload as { analysis?: Record<string, unknown> }).analysis ?? payload;
    const statusRaw = (analysis as { status?: string }).status?.toLowerCase();
    const status = ((): AnyRunReportResult['status'] | undefined => {
        switch (statusRaw) {
            case 'preparing': case 'queued': case 'pending': return 'queued';
            case 'running': case 'processing': return 'running';
            case 'done': case 'completed': return 'completed';
            case 'failed': case 'error': return 'failed';
            case 'timeout': case 'timed_out': return 'timeout';
            default: return undefined;
        }
    })();

    const scores = (analysis as { scores?: { verdict?: { threat_level?: number; score?: number } } }).scores;
    const tl = scores?.verdict?.threat_level;
    const verdict = ((): AnyRunReportResult['verdict'] | undefined => {
        if (tl == null) return undefined;
        if (tl >= 3) return 'malicious';
        if (tl === 2) return 'suspicious';
        if (tl <= 0) return 'benign';
        return 'unknown';
    })();

    const score = typeof scores?.verdict?.score === 'number'
        ? Math.max(0, Math.min(100, scores.verdict.score))
        : undefined;

    if (status === 'completed') log.debug('ANY.RUN report mapped', { status, verdict, score });
    return { status, verdict, score };
}
