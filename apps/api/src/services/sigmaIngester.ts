/**
 * Sigma rule ingester.
 *
 * Upserts parsed Sigma rules into the `detection_rules` table with
 * `rule_type = 'sigma'`. The MISP-Galaxy sync also writes to this table
 * with only metadata; this path stores the full detection logic so the
 * UI can show "show me the YAML" and downstream converters (Splunk,
 * Elastic, OpenSearch) have something to transform.
 *
 * Source of `source` column:
 *   - 'user-upload' — single YAML POSTed via API
 *   - 'url:<host>'  — POST /sigma/import/url, host of the source URL
 *   - 'sigmahq'     — bulk bundle ingest from the upstream library
 *
 * Idempotent on Sigma `id` (stored as `detection_rules.uuid`).
 */
import { db, eq } from '@rinjani/db';
import { detectionRules } from '@rinjani/db/schema';
import { parseSigmaYaml, parseSigmaBundle, type ParsedSigmaRule } from '@rinjani/core/sigma';
import { createLogger } from '../lib/logger';

const log = createLogger('SigmaIngester');

export interface IngestStats {
    inserted: number;
    updated: number;
    skipped: number;
    errors: Array<{ index: number; uuid?: string; message: string }>;
}

function emptyStats(): IngestStats {
    return { inserted: 0, updated: 0, skipped: 0, errors: [] };
}

/** Upsert a single parsed rule. Returns 'inserted' | 'updated'. */
async function upsertRule(rule: ParsedSigmaRule, source: string): Promise<'inserted' | 'updated'> {
    const existing = await db.select({ id: detectionRules.id })
        .from(detectionRules)
        .where(eq(detectionRules.uuid, rule.uuid))
        .limit(1);

    const enrichedMeta = {
        ...rule.meta,
        mitre_techniques: rule.mitreTechniques,
        mitre_tactics: rule.mitreTactics,
    };

    if (existing.length > 0) {
        await db.update(detectionRules)
            .set({
                ruleType: 'sigma',
                name: rule.name,
                description: rule.description,
                severity: rule.severity,
                status: rule.status,
                tags: rule.tags,
                detection: rule.detection,
                meta: enrichedMeta,
                externalReferences: rule.externalReferences,
                source,
                syncedAt: new Date(),
                updatedAt: new Date(),
            })
            .where(eq(detectionRules.uuid, rule.uuid));
        return 'updated';
    }

    await db.insert(detectionRules).values({
        ruleType: 'sigma',
        uuid: rule.uuid,
        name: rule.name,
        description: rule.description,
        severity: rule.severity,
        status: rule.status,
        tags: rule.tags,
        detection: rule.detection,
        meta: enrichedMeta,
        externalReferences: rule.externalReferences,
        source,
        syncedAt: new Date(),
    });
    return 'inserted';
}

/** Parse + upsert a single YAML rule. */
export async function ingestSigmaYaml(yamlText: string, source = 'user-upload'): Promise<IngestStats> {
    const stats = emptyStats();
    try {
        const rule = parseSigmaYaml(yamlText);
        const result = await upsertRule(rule, source);
        stats[result]++;
    } catch (err) {
        stats.errors.push({ index: 0, message: (err as Error).message });
    }
    return stats;
}

/** Parse + upsert a multi-document YAML bundle (concatenated rules). */
export async function ingestSigmaBundle(yamlText: string, source = 'user-upload'): Promise<IngestStats> {
    const stats = emptyStats();
    const { rules, errors } = parseSigmaBundle(yamlText);
    for (const e of errors) stats.errors.push(e);

    for (const rule of rules) {
        try {
            const result = await upsertRule(rule, source);
            stats[result]++;
        } catch (err) {
            stats.errors.push({ index: -1, uuid: rule.uuid, message: (err as Error).message });
        }
    }
    log.info('Sigma bundle ingested', { ...stats, errorCount: stats.errors.length });
    return stats;
}

/**
 * Fetch a YAML document from a URL and ingest it. Single-rule or bundle —
 * we always try the bundle path because it's a strict superset.
 * Caps the response body at 5 MiB to refuse pathological inputs.
 */
export async function ingestSigmaFromUrl(url: string): Promise<IngestStats> {
    const stats = emptyStats();
    const u = new URL(url);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') {
        stats.errors.push({ index: 0, message: `unsupported protocol: ${u.protocol}` });
        return stats;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30_000);
    let resp: Response;
    try {
        resp = await fetch(url, {
            signal: controller.signal,
            headers: { 'Accept': 'application/yaml, text/yaml, text/plain' },
        });
    } catch (err) {
        clearTimeout(timeout);
        stats.errors.push({ index: 0, message: `fetch failed: ${(err as Error).message}` });
        return stats;
    }
    clearTimeout(timeout);

    if (!resp.ok) {
        stats.errors.push({ index: 0, message: `fetch returned ${resp.status} ${resp.statusText}` });
        return stats;
    }

    const text = await resp.text();
    if (text.length > 5 * 1024 * 1024) {
        stats.errors.push({ index: 0, message: 'response exceeds 5 MiB limit' });
        return stats;
    }

    const source = `url:${u.host}`;
    return ingestSigmaBundle(text, source);
}
