/**
 * Threat-actor activity summarisation.
 *
 * Wraps the existing LLM router (services/aiMiddleware) with a focused
 * RAG context: the actor's row + its recent relationships, malware
 * usage, campaigns, and IOC activity in a configurable lookback
 * window. Returns markdown the dashboard can render directly.
 *
 * Phase 3 #2.
 */
import { db, sql, eq } from '@rinjani/db';
import { threatActors, mitreRelationships } from '@rinjani/db/schema';
import { callLLM } from './aiMiddleware';
import { createLogger } from '../lib/logger';

const log = createLogger('ActorSummary');

export interface ActorSummaryOptions {
    /** Lookback window in days. Default 30. Capped at 365. */
    days?: number;
    /** Optional context hint passed into the prompt — e.g. "for tomorrow's executive briefing". */
    context?: string;
    /** Force a different LLM provider for this call (default = router). */
    provider?: 'gemini' | 'openrouter' | 'ollama';
}

export interface ActorSummaryResult {
    actorId: string;
    actorName: string;
    windowDays: number;
    /** The actor row itself, for the UI to render alongside the summary. */
    actor: typeof threatActors.$inferSelect;
    /** Activity counts that fed the LLM — surfaced so the UI can show "based on X IOCs + Y campaigns…". */
    activity: {
        totalRelationships: number;
        recentRelationships: number;
        outgoingByType: Array<{ targetType: string; relationshipType: string; count: number }>;
        recentIOCs: Array<{ value: string; type: string; severity: string | null; lastSeen: string | null }>;
        topMalware: string[];
        recentCampaigns: string[];
    };
    summary: string;
    /** Diagnostics — useful for the UI to surface provider + cost. */
    meta: {
        provider: string;
        model: string;
        tokensUsed?: number;
        latencyMs: number;
    };
}

const MAX_DAYS = 365;
const MAX_LOOKBACK_IOCS = 20;
const MAX_MALWARE = 10;
const MAX_CAMPAIGNS = 10;

/**
 * Gather the context block — pure data, no LLM call. Exposed so tests
 * can lock the SQL queries without burning tokens.
 */
async function gatherActorActivity(
    actor: typeof threatActors.$inferSelect,
    windowDays: number,
): Promise<ActorSummaryResult['activity']> {
    const cutoff = new Date(Date.now() - windowDays * 86400 * 1000);

    // Total + recent relationships
    const totalRow = await db.execute(sql`
        SELECT COUNT(*)::int AS c FROM relationships
        WHERE (source_type = 'threat_actor' AND source_id = ${actor.id})
           OR (target_type = 'threat_actor' AND target_id = ${actor.id})
    `) as unknown as Array<{ c: number }>;
    const recentRow = await db.execute(sql`
        SELECT COUNT(*)::int AS c FROM relationships
        WHERE ((source_type = 'threat_actor' AND source_id = ${actor.id})
            OR (target_type = 'threat_actor' AND target_id = ${actor.id}))
          AND (last_seen >= ${cutoff} OR first_seen >= ${cutoff} OR created_at >= ${cutoff})
    `) as unknown as Array<{ c: number }>;

    // Outgoing relationship distribution
    const outRows = await db.execute(sql`
        SELECT target_type, relationship_type, COUNT(*)::int AS count
        FROM relationships
        WHERE source_type = 'threat_actor' AND source_id = ${actor.id}
        GROUP BY target_type, relationship_type
        ORDER BY count DESC
        LIMIT 20
    `) as unknown as Array<{ target_type: string; relationship_type: string; count: number }>;

    // Top malware used by this actor (USES → malware), with names
    const malwareRows = await db.execute(sql`
        SELECT COALESCE(m.name, r.target_id) AS name
        FROM relationships r
        LEFT JOIN malware m ON m.stix_id = r.target_id
        WHERE r.source_type = 'threat_actor' AND r.source_id = ${actor.id}
          AND r.target_type IN ('malware', 'tool')
        ORDER BY r.last_seen DESC NULLS LAST, r.created_at DESC
        LIMIT ${MAX_MALWARE}
    `) as unknown as Array<{ name: string }>;

    // Recent campaigns this actor is attributed to or runs
    const campaignRows = await db.execute(sql`
        SELECT c.name
        FROM relationships r
        JOIN campaigns c ON c.stix_id = r.target_id OR c.stix_id = r.source_id
        WHERE (r.source_type = 'threat_actor' AND r.source_id = ${actor.id}
               AND r.target_type = 'campaign')
           OR (r.target_type = 'threat_actor' AND r.target_id = ${actor.id}
               AND r.source_type = 'campaign')
        ORDER BY r.last_seen DESC NULLS LAST, r.created_at DESC
        LIMIT ${MAX_CAMPAIGNS}
    `).catch(() => []) as unknown as Array<{ name: string }>;

    // Recent IOCs linked to this actor (relationships → iocs in the window)
    const iocRows = await db.execute(sql`
        SELECT i.value, i.type, i.severity, i.last_seen
        FROM relationships r
        JOIN iocs i ON i.id::text = r.target_id
        WHERE r.source_type = 'threat_actor' AND r.source_id = ${actor.id}
          AND r.target_type = 'ioc'
          AND (i.last_seen >= ${cutoff} OR i.first_seen >= ${cutoff})
        ORDER BY i.last_seen DESC NULLS LAST
        LIMIT ${MAX_LOOKBACK_IOCS}
    `).catch(() => []) as unknown as Array<{ value: string; type: string; severity: string | null; last_seen: string | null }>;

    return {
        totalRelationships: totalRow[0]?.c ?? 0,
        recentRelationships: recentRow[0]?.c ?? 0,
        outgoingByType: outRows.map(r => ({
            targetType: r.target_type,
            relationshipType: r.relationship_type,
            count: r.count,
        })),
        recentIOCs: iocRows.map(r => ({
            value: r.value,
            type: r.type,
            severity: r.severity,
            lastSeen: r.last_seen,
        })),
        topMalware: malwareRows.map(r => r.name).filter(Boolean),
        recentCampaigns: campaignRows.map(r => r.name).filter(Boolean),
    };
}

/** Build the LLM prompt — pure function, no IO. Exposed for prompt-eval tests. */
export function buildActorSummaryPrompt(
    actor: typeof threatActors.$inferSelect,
    activity: ActorSummaryResult['activity'],
    windowDays: number,
    context = '30-day activity briefing',
): string {
    const aliases = (actor.aliases ?? []).join(', ') || '—';
    const motivations = [actor.primaryMotivation, ...(actor.secondaryMotivations ?? [])].filter(Boolean).join(', ') || '—';

    const outDist = activity.outgoingByType.length > 0
        ? activity.outgoingByType.map(o => `  - ${o.relationshipType} → ${o.targetType}: ${o.count}`).join('\n')
        : '  (none)';
    const malware = activity.topMalware.length > 0
        ? activity.topMalware.map(n => `  - ${n}`).join('\n')
        : '  (none recorded)';
    const campaigns = activity.recentCampaigns.length > 0
        ? activity.recentCampaigns.map(n => `  - ${n}`).join('\n')
        : '  (none recorded)';
    const iocs = activity.recentIOCs.length > 0
        ? activity.recentIOCs.map(i => `  - [${i.severity ?? 'n/a'}] ${i.type}: ${i.value}${i.lastSeen ? ` (last seen ${i.lastSeen})` : ''}`).join('\n')
        : '  (no recent IOCs in window)';

    return `You are a senior CTI analyst writing a ${context} on a specific threat actor.

## Actor
- Name: ${actor.name}
- Aliases: ${aliases}
- Description: ${actor.description ?? '—'}
- Sophistication: ${actor.sophistication ?? '—'}
- Resource level: ${actor.resourceLevel ?? '—'}
- Motivation: ${motivations}

## Activity window
- Last ${windowDays} days
- Total relationships in our graph: ${activity.totalRelationships}
- Relationships touched in window: ${activity.recentRelationships}

## Outgoing relationship distribution (top 20)
${outDist}

## Top malware / tools the actor uses
${malware}

## Recent campaigns
${campaigns}

## Recent IOCs in window (max ${MAX_LOOKBACK_IOCS})
${iocs}

Write a markdown briefing with these sections:

### Operational summary
Two sentences. What this actor has been doing in the last ${windowDays} days, grounded in the data above. If activity is sparse, say so explicitly — don't invent.

### Notable patterns
3-5 bullets, each backed by a specific count or name from the data. No vague statements.

### Recommendations
2-3 bullets. Defensive actions justified by what's above. Skip generic security advice.

Stay under 300 words total. Do NOT hallucinate IOCs, campaign names, or malware that aren't in the data above.`;
}

/** End-to-end: fetch actor, gather activity, prompt the LLM, return everything. */
export async function summariseActor(
    actorId: string,
    opts: ActorSummaryOptions = {},
): Promise<ActorSummaryResult | null> {
    const days = Math.min(MAX_DAYS, Math.max(1, opts.days ?? 30));

    const [actor] = await db.select().from(threatActors).where(eq(threatActors.id, actorId)).limit(1);
    if (!actor) return null;

    const activity = await gatherActorActivity(actor, days);
    const prompt = buildActorSummaryPrompt(actor, activity, days, opts.context);

    const t0 = Date.now();
    const llm = await callLLM(prompt, { temperature: 0.2, maxTokens: 800, provider: opts.provider });
    log.info('actor summary generated', {
        actorId, days,
        provider: llm.provider,
        tokensUsed: llm.tokensUsed,
        latencyMs: Date.now() - t0,
    });

    return {
        actorId,
        actorName: actor.name,
        windowDays: days,
        actor,
        activity,
        summary: llm.text,
        meta: {
            provider: llm.provider,
            model: llm.model,
            tokensUsed: llm.tokensUsed,
            latencyMs: llm.latencyMs,
        },
    };
}

/** Inadvertently exported for tests — DO NOT call from production code. */
export const __testing = { gatherActorActivity };
