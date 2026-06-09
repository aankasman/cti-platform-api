/**
 * Report ingestion service — Phase 3 #1 scaffold.
 *
 * Takes free-form report text (operator-pasted today; PDF + URL fetch
 * follow in later PRs) and returns a structured **draft** for review:
 *
 *   - Deterministic IOCs from the regex extractor in
 *     `@rinjani/core/iocExtractor` (always runs, no network needed).
 *
 *   - Fuzzy entities (threat-actor names, malware families, campaigns,
 *     vulnerabilities, MITRE techniques, target sectors, countries)
 *     from the existing `extractEntities()` LLM helper in
 *     `services/aiMiddleware/helpers`.
 *
 * The response is purely read-only — operator decides which IOCs and
 * entities to import. Persistence + STIX entity creation come in the
 * follow-on PR; this scaffold is the extraction surface so the
 * marketing site's "PLANNED · PHASE 3" tag for report ingestion can
 * flip to "shipped".
 *
 * Honest degradation: if no LLM provider is configured (no Gemini /
 * OpenRouter key, no Ollama reachable), IOC extraction still works
 * and the entity block returns empty with an `llmError` populated.
 * The operator sees what we *could* extract deterministically and
 * knows the LLM piece needs configuration.
 */
import {
    extractIocs, groupExtracted,
    type ExtractedIoc, type GroupedIocs,
} from '@rinjani/core/iocExtractor';
import { extractEntities, type ExtractedEntities } from './aiMiddleware/helpers';
import { createLogger } from '../lib/logger';
import type { LLMProvider } from './aiMiddleware/types';
import { db } from '@rinjani/db';
import { extractedReports, type ReportSourceKind } from '@rinjani/db/schema';

const log = createLogger('ReportIngestion');

/** Hard ceiling on input text size — protects the regex + LLM calls from runaway memory. */
const MAX_TEXT_LEN = 200_000;

export interface ReportIngestionInput {
    text: string;
    /** Free-form attribution — operator-provided URL, PDF filename, "pasted from Slack", etc. */
    source?: string;
    /** Where the text came from — drives the persisted `source_kind` column. Defaults to 'text'. */
    sourceKind?: ReportSourceKind;
    /** Vendor metadata for the persisted row (URL fields, PDF page count, etc.). */
    sourceMeta?: Record<string, unknown>;
    /** Override the LLM provider. Defaults to the auto-selected one. */
    provider?: LLMProvider;
    /** Skip the LLM enrichment entirely (useful for tests + offline mode). */
    skipLlm?: boolean;
    /** Persist the draft to `extracted_reports`. Defaults to true. Pass false for stateless mode. */
    persist?: boolean;
    /** Audit attribution. Falls back to 'unknown' when persist is true and this is missing. */
    createdBy?: string;
}

export interface ReportIngestionDraft {
    /** Persisted draft id. Undefined when persist=false. */
    reportId?: string;
    source?: string;
    /** ISO timestamp the extraction ran. */
    extractedAt: string;
    /** Input text length (after the MAX_TEXT_LEN truncation). */
    textLength: number;

    iocs: {
        items: ExtractedIoc[];
        grouped: GroupedIocs;
    };
    entities: ExtractedEntities;

    /** Populated when the LLM call fails. IOC extraction is unaffected. */
    llmError?: string;
    /** LLM call metadata, omitted if `skipLlm` or the call failed before producing one. */
    llmMeta?: {
        provider: LLMProvider;
        latencyMs: number;
    };
}

export async function ingestReportText(input: ReportIngestionInput): Promise<ReportIngestionDraft> {
    const text = input.text.slice(0, MAX_TEXT_LEN);
    const iocs = extractIocs(text);
    const grouped = groupExtracted(iocs);

    log.info('IOC extraction complete', {
        textLength: text.length,
        iocsExtracted: grouped.total,
        source: input.source,
    });

    const draft: ReportIngestionDraft = {
        source: input.source,
        extractedAt: new Date().toISOString(),
        textLength: text.length,
        iocs: { items: iocs, grouped },
        entities: {},
    };

    if (!input.skipLlm) {
        // Best-effort LLM enrichment. A failure here doesn't poison the response —
        // operator still sees the deterministic IOCs.
        const t0 = Date.now();
        try {
            const entities = await extractEntities(text, {
                provider: input.provider,
                temperature: 0.1,
                maxTokens: 1024,
            });
            draft.entities = entities;
            draft.llmMeta = {
                provider: input.provider ?? 'gemini', // best-effort label; selectProvider doesn't surface back
                latencyMs: Date.now() - t0,
            };
        } catch (err) {
            const msg = (err as Error).message;
            log.warn('LLM entity extraction failed; returning IOCs only', { error: msg });
            draft.llmError = msg;
        }
    }

    // Persist the draft unless explicitly opted out. Errors here don't poison
    // the response — operator still gets the extracted draft, just unpersisted.
    if (input.persist !== false) {
        try {
            const [row] = await db.insert(extractedReports).values({
                source: input.source ?? null,
                sourceKind: input.sourceKind ?? 'text',
                sourceMeta: input.sourceMeta ?? {},
                textLength: draft.textLength,
                iocs: { items: draft.iocs.items, grouped: draft.iocs.grouped } as unknown as Record<string, unknown>,
                entities: draft.entities as unknown as Record<string, unknown>,
                llmProvider: draft.llmMeta?.provider ?? null,
                llmError: draft.llmError ?? null,
                createdBy: input.createdBy ?? 'unknown',
            }).returning({ id: extractedReports.id });
            draft.reportId = row.id;
        } catch (err) {
            log.warn('Draft persistence failed; returning unpersisted draft', { error: (err as Error).message });
        }
    }

    return draft;
}
