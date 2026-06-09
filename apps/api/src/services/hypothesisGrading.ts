/**
 * LLM grading for hypothesis tracking — Phase 3 #5.
 *
 * The grader takes a claim + the analyst's evidence list and outputs a
 * single confidence score (0..100) + one paragraph of reasoning. The
 * prompt is deliberately narrow: count supports vs refutes, weight by
 * the analyst-provided weight, surface specific contradictions, never
 * invent facts not in the evidence list.
 *
 * Same provider abstraction as actorSummary / nlCypher / reportIngestion
 * (Gemini / OpenRouter / Ollama via `callLLM`). No-LLM fallback returns
 * a deterministic weighted average so the route still works in offline
 * dev — see `deterministicGrade()`.
 */
import { callLLM } from './aiMiddleware/callLLM';
import type { LLMProvider } from './aiMiddleware/types';
import type { Hypothesis, HypothesisEvidence } from '@rinjani/db/schema';
import { createLogger } from '../lib/logger';

const log = createLogger('HypothesisGrading');

export interface GradingResult {
    confidence: number;            // 0..100
    reasoning: string;
    provider: LLMProvider;
    /** True if the LLM call failed / wasn't configured and we fell back to deterministic. */
    fallback: boolean;
}

// ============================================================================
// Prompt builder — exported so the test suite can pin its shape
// ============================================================================

export function buildGradingPrompt(hypothesis: Hypothesis, evidence: HypothesisEvidence[]): string {
    const supports = evidence.filter(e => e.kind === 'supports');
    const refutes = evidence.filter(e => e.kind === 'refutes');

    // Cap evidence list to avoid blowing the prompt budget. Sort by weight
    // descending so the strongest signals always make the cut.
    const renderItems = (items: HypothesisEvidence[], cap = 25) =>
        items
            .slice()
            .sort((a, b) => b.weight - a.weight)
            .slice(0, cap)
            .map((e, i) => {
                const entityRef = e.entityId ? `${e.evidenceType}=${e.entityId}` : `${e.evidenceType}=freeform`;
                const note = (e.note ?? '').replace(/\s+/g, ' ').trim().slice(0, 500) || '(no note)';
                return `  ${i + 1}. [${entityRef}, weight=${e.weight}] ${note}`;
            })
            .join('\n') || '  (none)';

    return [
        'You are grading a threat-intelligence hypothesis against evidence the analyst has collected.',
        '',
        'Output a JSON object: {"confidence": <integer 0..100>, "reasoning": "<one paragraph>"}.',
        'No prose outside the JSON. No code fence. Do NOT invent IOCs, actors, or sources not in the evidence list.',
        '',
        `HYPOTHESIS TITLE: ${hypothesis.title}`,
        `CLAIM: ${hypothesis.claim.slice(0, 2000)}`,
        hypothesis.subjectType && hypothesis.subjectId
            ? `SUBJECT: ${hypothesis.subjectType}=${hypothesis.subjectId}`
            : 'SUBJECT: (none)',
        '',
        `EVIDENCE SUPPORTING (${supports.length} item${supports.length === 1 ? '' : 's'}):`,
        renderItems(supports),
        '',
        `EVIDENCE REFUTING (${refutes.length} item${refutes.length === 1 ? '' : 's'}):`,
        renderItems(refutes),
        '',
        'GRADING GUIDELINES:',
        '- 0..20:   strong refutation; multiple independent refuting items',
        '- 21..40:  weak refutation; some refuting evidence but not conclusive',
        '- 41..59:  ambiguous / insufficient evidence',
        '- 60..79:  weak support; some supporting evidence with gaps',
        '- 80..100: strong support; multiple independent supporting items',
        'When evidence is contradictory, weight by the analyst-provided weights and by item count.',
        'In the reasoning, name the strongest 1–2 supporting items and the strongest 1–2 refuting items by index.',
    ].join('\n');
}

// ============================================================================
// Parser — separate so the test suite can exercise without LLM
// ============================================================================

export function parseGradingResponse(text: string): { confidence: number; reasoning: string } | null {
    // Pull the first JSON object out of the response — the LLM occasionally
    // wraps in prose despite instructions.
    const match = text.match(/\{[\s\S]*?\}/);
    if (!match) return null;
    try {
        const parsed = JSON.parse(match[0]) as { confidence?: unknown; reasoning?: unknown };
        const c = typeof parsed.confidence === 'number'
            ? parsed.confidence
            : typeof parsed.confidence === 'string' ? parseInt(parsed.confidence, 10) : NaN;
        if (!Number.isFinite(c) || c < 0 || c > 100) return null;
        const reasoning = typeof parsed.reasoning === 'string' ? parsed.reasoning.slice(0, 4000) : '';
        return { confidence: Math.round(c), reasoning };
    } catch {
        return null;
    }
}

// ============================================================================
// Deterministic fallback — weighted average so the route still works without LLM
// ============================================================================

export function deterministicGrade(evidence: HypothesisEvidence[]): { confidence: number; reasoning: string } {
    if (evidence.length === 0) {
        return { confidence: 50, reasoning: 'No evidence yet; defaulting to neutral 50.' };
    }
    let supportSum = 0, refuteSum = 0;
    for (const e of evidence) {
        if (e.kind === 'supports') supportSum += e.weight;
        else refuteSum += e.weight;
    }
    const total = supportSum + refuteSum;
    if (total === 0) {
        return { confidence: 50, reasoning: 'All evidence has zero weight; defaulting to neutral 50.' };
    }
    const confidence = Math.round((supportSum / total) * 100);
    return {
        confidence,
        reasoning:
            `Deterministic weighted score (no LLM): supporting weight=${supportSum}, refuting weight=${refuteSum} ` +
            `across ${evidence.length} item${evidence.length === 1 ? '' : 's'}.`,
    };
}

// ============================================================================
// Public API
// ============================================================================

export async function gradeHypothesis(
    hypothesis: Hypothesis,
    evidence: HypothesisEvidence[],
    opts: { provider?: LLMProvider; skipLlm?: boolean } = {},
): Promise<GradingResult> {
    if (opts.skipLlm) {
        const det = deterministicGrade(evidence);
        return { ...det, provider: opts.provider ?? 'gemini', fallback: true };
    }

    const prompt = buildGradingPrompt(hypothesis, evidence);
    try {
        const llm = await callLLM(prompt, {
            provider: opts.provider,
            temperature: 0.1,
            maxTokens: 512,
            jsonMode: true,
        });
        const parsed = parseGradingResponse(llm.text);
        if (!parsed) {
            log.warn('LLM grading parse failed; falling back to deterministic', {
                provider: llm.provider, snippet: llm.text.slice(0, 200),
            });
            const det = deterministicGrade(evidence);
            return { ...det, provider: llm.provider, fallback: true };
        }
        return { ...parsed, provider: llm.provider, fallback: false };
    } catch (err) {
        log.warn('LLM grading call failed; falling back to deterministic', {
            error: (err as Error).message,
        });
        const det = deterministicGrade(evidence);
        return { ...det, provider: opts.provider ?? 'gemini', fallback: true };
    }
}
