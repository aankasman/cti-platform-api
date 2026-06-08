/**
 * TAXII 2.1 outbound push client.
 *
 * Posts a STIX bundle (built by `@rinjani/core/stix`) to a remote
 * TAXII server's `<api_root>/collections/<id>/objects/` endpoint.
 *
 * Spec: https://docs.oasis-open.org/cti/taxii/v2.1/taxii-v2.1.html §5.4
 *
 * Per-target config lives in `taxii_remote_targets`. The bearer token
 * is resolved from `config_api_keys.id == target.apiKeyRef`, falling
 * back to the `TAXII_PUSH_API_KEY` env var when apiKeyRef is NULL —
 * that single-target shortcut keeps `docker compose up` working without
 * a config UI for self-hosted operators.
 */
import { db, eq, rawQuery } from '@rinjani/db';
import { taxiiRemoteTargets } from '@rinjani/db/schema';
import { generateSTIXBundle, type STIXExportOptions } from '@rinjani/core/stix';
import { createLogger } from '../lib/logger';

const log = createLogger('TAXIIPush');

const TAXII_CONTENT_TYPE = 'application/taxii+json;version=2.1';

export interface PushResult {
    targetId: string;
    targetName: string;
    httpStatus: number;
    objectsPushed: number;
    success: boolean;
    error?: string;
    /** TAXII status resource id, if the server returned one (status URL polling future work). */
    statusId?: string;
    durationMs: number;
}

/**
 * Resolve the bearer token to use for a target.
 * Priority:
 *   1. target.apiKeyRef → config_api_keys.key_value
 *   2. process.env.TAXII_PUSH_API_KEY
 *   3. throw (operator misconfiguration)
 */
async function resolveBearerToken(apiKeyRef: string | null): Promise<string> {
    if (apiKeyRef) {
        const r = await rawQuery<{ key_value: string }>(
            `SELECT key_value FROM config_api_keys WHERE id = '${apiKeyRef.replace(/'/g, "''")}' AND is_active = true LIMIT 1`
        );
        const tok = r.rows?.[0]?.key_value;
        if (tok) return tok;
    }
    const envTok = process.env.TAXII_PUSH_API_KEY;
    if (envTok) return envTok;
    throw new Error('No TAXII bearer token configured (set target.apiKeyRef or TAXII_PUSH_API_KEY)');
}

/** Build the POST URL for adding STIX objects to a collection. */
export function buildPushUrl(apiRoot: string, collectionId: string): string {
    // TAXII spec requires trailing slashes — be tolerant to operator config.
    const root = apiRoot.endsWith('/') ? apiRoot.slice(0, -1) : apiRoot;
    return `${root}/collections/${encodeURIComponent(collectionId)}/objects/`;
}

/**
 * Push to a single target by id. Updates the target's last_push_* columns
 * with the outcome so the UI can show "last pushed 10 min ago · 503 / 247
 * objects".
 *
 * Returns the result regardless of HTTP outcome — caller decides whether
 * a non-2xx is a failure for their flow.
 */
export async function pushToTarget(targetId: string, options?: STIXExportOptions): Promise<PushResult> {
    const t0 = Date.now();
    const [target] = await db.select().from(taxiiRemoteTargets).where(eq(taxiiRemoteTargets.id, targetId)).limit(1);
    if (!target) throw new Error(`taxii target not found: ${targetId}`);
    if (!target.enabled) throw new Error(`taxii target disabled: ${target.name}`);

    const filter: STIXExportOptions = { ...(target.pushFilter as STIXExportOptions), ...(options ?? {}) };
    const bundle = await generateSTIXBundle(filter);

    let httpStatus = 0;
    let success = false;
    let error: string | undefined;
    let statusId: string | undefined;

    try {
        const bearer = await resolveBearerToken(target.apiKeyRef);
        const url = buildPushUrl(target.apiRoot, target.collectionId);
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 60_000);
        const resp = await fetch(url, {
            method: 'POST',
            headers: {
                'Accept': TAXII_CONTENT_TYPE,
                'Content-Type': TAXII_CONTENT_TYPE,
                'Authorization': `Bearer ${bearer}`,
            },
            body: JSON.stringify(bundle),
            signal: controller.signal,
        });
        clearTimeout(timeout);

        httpStatus = resp.status;
        success = resp.ok;
        if (!success) {
            const body = await resp.text().catch(() => '');
            error = `HTTP ${resp.status} ${resp.statusText}: ${body.slice(0, 500)}`;
        } else {
            // TAXII servers respond with a status resource on 2xx
            const body = await resp.json().catch(() => null) as { id?: string } | null;
            statusId = body?.id;
        }
    } catch (err) {
        error = (err as Error).message;
    }

    // Persist push-history bookkeeping (best-effort — don't fail the push if this errors)
    try {
        await db.update(taxiiRemoteTargets)
            .set({
                lastPushAt: new Date(),
                lastPushStatus: success ? 'success' : 'error',
                lastPushError: error ?? null,
                lastPushObjects: bundle.objects.length,
                updatedAt: new Date(),
            })
            .where(eq(taxiiRemoteTargets.id, targetId));
    } catch (e) {
        log.warn('Failed to update taxii_remote_targets bookkeeping', { error: (e as Error).message });
    }

    const result: PushResult = {
        targetId,
        targetName: target.name,
        httpStatus,
        objectsPushed: bundle.objects.length,
        success,
        error,
        statusId,
        durationMs: Date.now() - t0,
    };
    log.info('TAXII push complete', { ...result });
    return result;
}

/**
 * Push to every enabled target. Used by the scheduled job (added later)
 * and the admin "push all now" button. Continues past per-target failures.
 */
export async function pushToAllEnabledTargets(options?: STIXExportOptions): Promise<PushResult[]> {
    const targets = await db.select({ id: taxiiRemoteTargets.id })
        .from(taxiiRemoteTargets)
        .where(eq(taxiiRemoteTargets.enabled, true));
    const results: PushResult[] = [];
    for (const t of targets) {
        try {
            results.push(await pushToTarget(t.id, options));
        } catch (err) {
            results.push({
                targetId: t.id,
                targetName: 'unknown',
                httpStatus: 0,
                objectsPushed: 0,
                success: false,
                error: (err as Error).message,
                durationMs: 0,
            });
        }
    }
    return results;
}
