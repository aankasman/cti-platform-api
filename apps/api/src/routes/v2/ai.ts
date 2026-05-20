/**
 * V2 AI Routes — Analysis, Summarization (RAG), and NL Query (RAG)
 *
 * Both /summarize and /query pull real data from OpenSearch to enrich the LLM
 * prompt with platform-specific context (RAG = Retrieval-Augmented Generation).
 */

import { Hono } from 'hono';
import { analyzeEntity, EntityType } from '../../services/aiAnalysis';
import { AIAnalyzeSchema } from '../../lib/schemas';
import { callLLM } from '../../services/aiMiddleware';
import { createLogger } from '../../lib/logger';
import { getCounts, getBatchedStats, getDateHistogram } from '../../services/opensearch/aggregations';
import { unifiedSearch } from '../../services/opensearch/search';

const log = createLogger('AI:Routes');
const aiRoutes = new Hono();

// ============================================================================
// Helper: Gather RAG context from OpenSearch
// ============================================================================

async function gatherPlatformContext(): Promise<string> {
    const sections: string[] = [];

    try {
        // 1. Entity counts
        const counts = await getCounts();
        sections.push(`## Platform Data Overview
- Total IOCs: ${counts.iocs.toLocaleString()}
- Total Vulnerabilities: ${counts.vulnerabilities.toLocaleString()}
- Total Threat Actors: ${counts.actors.toLocaleString()}
- Total Entities: ${counts.total.toLocaleString()}`);
    } catch { /* non-critical */ }

    try {
        // 2. IOC distribution + source breakdown + heatmap
        const stats = await getBatchedStats();
        if (stats.distribution.length > 0) {
            const distText = stats.distribution.slice(0, 8)
                .map(d => `  - ${d.name}: ${d.value.toLocaleString()}`).join('\n');
            sections.push(`## IOC Distribution by Type\n${distText}`);
        }
        if (stats.sourceBreakdown.length > 0) {
            const srcText = stats.sourceBreakdown.slice(0, 8)
                .map(s => `  - ${s.source}: ${s.count.toLocaleString()}`).join('\n');
            sections.push(`## Top Intel Sources\n${srcText}`);
        }
        if (stats.heatmap.length > 0) {
            const critHeat = stats.heatmap
                .filter(h => h.severity === 'critical' || h.severity === 'high')
                .slice(0, 6)
                .map(h => `  - ${h.type} (${h.severity}): ${h.count}`).join('\n');
            if (critHeat) sections.push(`## Critical/High Severity by Type\n${critHeat}`);
        }
    } catch { /* non-critical */ }

    try {
        // 3. Recent critical IOCs (last 7 days)
        const recentCritical = await unifiedSearch({
            query: '',
            filters: {
                entityType: ['ioc'],
                severity: ['critical', 'high'],
                dateFrom: new Date(Date.now() - 7 * 86400000).toISOString(),
            },
            pagination: { page: 1, limit: 10 },
            sort: { field: 'updatedAt', order: 'desc' },
            aggregations: false,
        });
        if (recentCritical.items.length > 0) {
            const iocList = recentCritical.items.map((item: Record<string, unknown>) =>
                `  - [${item.severity}] ${item.value || item.title} (${item.type || 'unknown'}, source: ${item.source || 'N/A'})`
            ).join('\n');
            sections.push(`## Recent Critical/High IOCs (Last 7 Days, ${recentCritical.total} total)\n${iocList}`);
        }
    } catch { /* non-critical */ }

    try {
        // 4. Severity trend (last 7 days)
        const trend = await getDateHistogram(7);
        if (trend.length > 0) {
            const trendText = trend.map(d =>
                `  - ${d.date}: critical=${d.critical}, high=${d.high}, medium=${d.medium}, low=${d.low}`
            ).join('\n');
            sections.push(`## Severity Trends (Last 7 Days)\n${trendText}`);
        }
    } catch { /* non-critical */ }

    return sections.join('\n\n');
}

async function searchForQuery(query: string): Promise<string> {
    try {
        const results = await unifiedSearch({
            query,
            pagination: { page: 1, limit: 10 },
            sort: { field: '_score', order: 'desc' },
            aggregations: true,
        });
        if (results.items.length === 0) return '';

        const items = results.items.map((item: Record<string, unknown>) => {
            const parts = [`Type: ${item.entityType}`, `Value: ${item.value || item.title}`];
            if (item.severity) parts.push(`Severity: ${item.severity}`);
            if (item.source) parts.push(`Source: ${item.source}`);
            if (item.description) parts.push(`Desc: ${String(item.description).slice(0, 150)}`);
            return `  - ${parts.join(' | ')}`;
        }).join('\n');

        let facetsSummary = '';
        if (results.facets) {
            const facetParts: string[] = [];
            if (Object.keys(results.facets.entityType).length > 0) {
                facetParts.push(`Entity types: ${Object.entries(results.facets.entityType).map(([k, v]) => `${k}(${v})`).join(', ')}`);
            }
            if (Object.keys(results.facets.severity).length > 0) {
                facetParts.push(`Severities: ${Object.entries(results.facets.severity).map(([k, v]) => `${k}(${v})`).join(', ')}`);
            }
            if (facetParts.length) facetsSummary = `\nFacets: ${facetParts.join('; ')}`;
        }

        return `## Search Results for "${query}" (${results.total} matches)${facetsSummary}\n${items}`;
    } catch {
        return '';
    }
}

// ============================================================================
// POST /ai/analyze — Entity-specific analysis
// ============================================================================

aiRoutes.post('/analyze', async (c) => {
    const startTime = Date.now();
    const body = await c.req.json();
    const { entityType, entityId, entityData, forceRefresh } = AIAnalyzeSchema.parse(body);

    const result = await analyzeEntity({
        entityId,
        entityType: entityType as EntityType,
        entityData,
        forceRefresh,
    });

    return c.json({
        success: result.success,
        data: result,
        meta: {
            requestId: crypto.randomUUID(),
            took: Date.now() - startTime,
            cached: result.cached ?? false,
        },
    });
});

// ============================================================================
// POST /ai/summarize — RAG-enhanced threat briefing
// ============================================================================

aiRoutes.post('/summarize', async (c) => {
    const startTime = Date.now();
    const body = await c.req.json().catch(() => ({}));
    const context = (body as { context?: string }).context || 'daily briefing';

    try {
        // Gather real platform data for RAG context
        const platformContext = await gatherPlatformContext();

        const prompt = `You are a senior cyber threat intelligence analyst providing a ${context} to the security team.

Below is REAL DATA from our threat intelligence platform. Use this data to create a grounded, specific briefing.

${platformContext || '(No platform data available — provide general threat landscape analysis.)'}

Based on the above data, provide a concise threat briefing covering:

1. **Platform Status**: Summarize what our platform currently tracks (IOC counts, vulnerabilities, sources)
2. **Key Findings**: Highlight the most notable critical/high severity indicators and patterns from the data
3. **Recommendations**: Based on the data patterns, suggest 2-3 actionable steps

Keep the response concise (3-4 paragraphs). Reference specific numbers from the data. Use markdown formatting (bold, lists, headers).`;

        const result = await callLLM(prompt, { temperature: 0.3, maxTokens: 1500 });

        return c.json({
            success: true,
            data: { summary: result.text },
            meta: {
                requestId: crypto.randomUUID(),
                took: Date.now() - startTime,
                provider: result.provider,
                tokensUsed: result.tokensUsed,
            },
        });
    } catch (err) {
        log.error('AI summarize failed', { error: (err as Error).message });
        return c.json({
            success: false,
            error: { message: 'AI summarization failed. Check LLM provider configuration.' },
        }, 500);
    }
});

// ============================================================================
// POST /ai/query — RAG-enhanced natural language query
// ============================================================================

aiRoutes.post('/query', async (c) => {
    const startTime = Date.now();
    const body = await c.req.json();
    const query = (body as { query?: string }).query;

    if (!query || typeof query !== 'string' || !query.trim()) {
        return c.json({ success: false, error: { message: 'Missing or empty query' } }, 400);
    }

    try {
        // Search platform data for relevant context (RAG)
        const [searchContext, platformContext] = await Promise.all([
            searchForQuery(query.trim()),
            gatherPlatformContext(),
        ]);

        const prompt = `You are a cyber threat intelligence analyst assistant. A security analyst has asked:

"${query.trim()}"

Below is REAL DATA from our threat intelligence platform that may be relevant to their question.

${platformContext || ''}

${searchContext || '(No matching records found in platform.)'}

Based on the above real data, provide a clear, specific, and actionable answer. Reference actual data from the platform (specific IOCs, counts, sources) when available. If the platform data doesn't contain enough information to fully answer the question, acknowledge what data IS available and supplement with general guidance.

Use markdown formatting (bold, lists, headers) for readability.`;

        const result = await callLLM(prompt, { temperature: 0.3, maxTokens: 1500 });

        return c.json({
            success: true,
            data: {
                answer: result.text,
                sources: [],
            },
            meta: {
                requestId: crypto.randomUUID(),
                took: Date.now() - startTime,
                provider: result.provider,
                tokensUsed: result.tokensUsed,
            },
        });
    } catch (err) {
        log.error('AI query failed', { error: (err as Error).message });
        return c.json({
            success: false,
            error: { message: 'AI query failed. Check LLM provider configuration.' },
        }, 500);
    }
});

export default aiRoutes;
