/**
 * AI Analysis — Core Analysis Functions & Caching
 */

import { createHash } from 'crypto';
import { createLogger } from '../../../../lib/logger';
import { db, sql } from '@rinjani/db';
import { ANALYSIS_PROMPTS } from './prompts';
import { getActiveProvider, callGemini, callOpenAI, callAnthropic, callOllama } from './providers';
import type {
    EntityType, AnalysisType, AnalysisRequest, EntityAnalysisRequest,
    AnalysisResult, EntityAnalysisResult,
    ThreatAssessment, MalwareClassification, RiskScoreResult, CVEAnalysis, ActorProfile,
} from './types';

const log = createLogger('AIAnalysis');

// ============================================================================
// IOC Analysis
// ============================================================================

/**
 * Run AI analysis on an IOC
 */
export async function analyzeIOC(request: AnalysisRequest): Promise<AnalysisResult> {
    const provider = getActiveProvider();
    const prompt = ANALYSIS_PROMPTS[request.analysisType](request.iocValue, request.iocType);

    log.info('Running analysis', { analysisType: request.analysisType, iocValue: request.iocValue, provider: provider.name });

    try {
        let response: string;
        let tokensUsed = 0;

        switch (provider.name) {
            case 'Gemini':
                ({ response, tokensUsed } = await callGemini(provider, prompt));
                break;
            case 'OpenAI':
                ({ response, tokensUsed } = await callOpenAI(provider, prompt));
                break;
            case 'Anthropic':
                ({ response, tokensUsed } = await callAnthropic(provider, prompt));
                break;
            default:
                ({ response } = await callOllama(provider, prompt));
        }

        // Parse response
        const data = parseAnalysisResponse(response, request.analysisType);

        return {
            success: true,
            analysisType: request.analysisType,
            iocId: request.iocId,
            iocValue: request.iocValue,
            analyzedAt: new Date().toISOString(),
            data,
            provider: provider.name,
            tokensUsed,
        };
    } catch (err) {
        log.error('Analysis error', new Error((err as Error).message));
        return {
            success: false,
            analysisType: request.analysisType,
            iocId: request.iocId,
            iocValue: request.iocValue,
            analyzedAt: new Date().toISOString(),
            error: (err as Error).message,
            provider: provider.name,
        };
    }
}

// ============================================================================
// Caching Helpers
// ============================================================================

/**
 * Generate a hash of entity data for cache invalidation
 */
function hashEntityData(entityData: Record<string, unknown>): string {
    const dataStr = JSON.stringify(entityData, Object.keys(entityData).sort());
    return createHash('sha256').update(dataStr).digest('hex').substring(0, 32);
}

/**
 * Get cached analysis from database
 */
async function getCachedAnalysis(entityType: EntityType, entityId: string): Promise<EntityAnalysisResult | null> {
    try {
        const result = await db.execute(sql`
            SELECT entity_type, entity_id, analysis_data, provider, tokens_used, analyzed_at
            FROM ai_analysis_cache
            WHERE entity_type = ${entityType}::ai_entity_type AND entity_id = ${entityId}::uuid
            LIMIT 1
        `) as unknown as Record<string, unknown>[];

        if (result && result.length > 0) {
            const cache = result[0] as Record<string, unknown>;
            log.info('Cache HIT', { entityType, entityId });
            return {
                success: true,
                entityType: cache.entity_type as EntityType,
                entityId: String(cache.entity_id),
                analyzedAt: new Date(cache.analyzed_at as string).toISOString(),
                data: cache.analysis_data as ThreatAssessment | MalwareClassification | RiskScoreResult | CVEAnalysis | ActorProfile | string,
                provider: String(cache.provider),
                tokensUsed: cache.tokens_used ? parseInt(String(cache.tokens_used)) : undefined,
                cached: true,
            };
        }
    } catch (err) {
        log.error('Cache lookup error', new Error((err as Error).message));
    }
    return null;
}


/**
 * Save analysis to cache
 */
async function saveToCache(
    entityType: EntityType,
    entityId: string,
    entityDataHash: string,
    analysisData: unknown,
    provider: string,
    tokensUsed?: number
): Promise<void> {
    try {
        // First, try to delete any existing cache for this entity
        await db.execute(sql`
            DELETE FROM ai_analysis_cache
            WHERE entity_type = ${entityType}::ai_entity_type AND entity_id = ${entityId}::uuid
        `);

        // Insert new cache entry
        const analysisJson = JSON.stringify(analysisData);
        const tokensStr = tokensUsed?.toString() || null;
        const nowStr = new Date().toISOString();

        await db.execute(sql`
            INSERT INTO ai_analysis_cache 
            (entity_type, entity_id, analysis_data, provider, tokens_used, entity_data_hash, analyzed_at, created_at, updated_at)
            VALUES (
                ${entityType}::ai_entity_type, 
                ${entityId}::uuid, 
                ${analysisJson}::jsonb, 
                ${provider}, 
                ${tokensStr}, 
                ${entityDataHash}, 
                ${nowStr}::timestamptz, 
                ${nowStr}::timestamptz, 
                ${nowStr}::timestamptz
            )
        `);
        log.info('Cached analysis', { entityType, entityId });
    } catch (err) {
        log.error('Cache save error', new Error((err as Error).message));
    }

}

// ============================================================================
// Entity Analysis
// ============================================================================

/**
 * Run AI analysis on any entity type (IOC, CVE, or Threat Actor)
 * Results are cached in the database for instant retrieval.
 * Use forceRefresh to bypass cache and regenerate analysis.
 */
export async function analyzeEntity(request: EntityAnalysisRequest): Promise<EntityAnalysisResult> {
    const provider = getActiveProvider();
    const entityDataHash = hashEntityData(request.entityData);

    // Check cache first (unless forceRefresh is true)
    if (!request.forceRefresh) {
        const cachedResult = await getCachedAnalysis(request.entityType, request.entityId);
        if (cachedResult) {
            return cachedResult;
        }
        log.info('Cache MISS', { entityType: request.entityType, entityId: request.entityId });
    } else {
        log.info('Force refresh requested', { entityType: request.entityType, entityId: request.entityId });
    }

    // Build context-rich prompt based on entity type
    let prompt: string;
    let analysisType: AnalysisType;

    switch (request.entityType) {
        case 'ioc':
            analysisType = 'threat-assessment';
            const iocData = request.entityData;
            prompt = ANALYSIS_PROMPTS['threat-assessment'](
                String(iocData.value || ''),
                String(iocData.type || 'unknown')
            );
            break;

        case 'cve':
            analysisType = 'cve-analysis';
            const cveData = request.entityData;
            const cveContext = `
CVE ID: ${cveData.cveId || cveData.id || 'Unknown'}
Description: ${cveData.description || 'No description available'}
CVSS Score: ${cveData.cvssScore || 'Not available'}
Severity: ${cveData.severity || 'Unknown'}
Vendor/Product: ${cveData.vendorProject || 'Unknown'} / ${cveData.product || 'Unknown'}
Published Date: ${cveData.publishedDate || 'Unknown'}
Is Known Exploited: ${cveData.isExploited ? 'Yes - CISA KEV' : 'Not in CISA KEV'}
${cveData.cvssVector ? `CVSS Vector: ${cveData.cvssVector}` : ''}
            `.trim();
            prompt = ANALYSIS_PROMPTS['cve-analysis'](cveContext);
            break;

        case 'actor':
            analysisType = 'actor-profile';
            const actorData = request.entityData;
            const actorContext = `
Threat Actor Name: ${actorData.name || 'Unknown'}
Aliases: ${Array.isArray(actorData.aliases) ? actorData.aliases.join(', ') : 'None known'}
Description: ${actorData.description || 'No description available'}
Sophistication Level: ${actorData.sophistication || 'Unknown'}
Resource Level: ${actorData.resourceLevel || 'Unknown'}
Primary Motivation: ${actorData.primaryMotivation || 'Unknown'}
Secondary Motivations: ${Array.isArray(actorData.secondaryMotivations) ? actorData.secondaryMotivations.join(', ') : 'None'}
Goals: ${Array.isArray(actorData.goals) ? actorData.goals.join(', ') : 'Unknown'}
            `.trim();
            prompt = ANALYSIS_PROMPTS['actor-profile'](actorContext);
            break;

        default:
            return {
                success: false,
                entityType: request.entityType,
                entityId: request.entityId,
                analyzedAt: new Date().toISOString(),
                error: `Unsupported entity type: ${request.entityType}`,
                provider: provider.name,
            };
    }

    log.info('Running analysis', { analysisType, entityType: request.entityType, entityId: request.entityId, provider: provider.name });

    try {
        let response: string;
        let tokensUsed = 0;

        switch (provider.name) {
            case 'Gemini':
                ({ response, tokensUsed } = await callGemini(provider, prompt));
                break;
            case 'OpenAI':
                ({ response, tokensUsed } = await callOpenAI(provider, prompt));
                break;
            case 'Anthropic':
                ({ response, tokensUsed } = await callAnthropic(provider, prompt));
                break;
            default:
                ({ response } = await callOllama(provider, prompt));
        }

        // Parse response
        const data = parseAnalysisResponse(response, analysisType);

        // Save to cache
        await saveToCache(
            request.entityType,
            request.entityId,
            entityDataHash,
            data,
            provider.name,
            tokensUsed
        );

        return {
            success: true,
            entityType: request.entityType,
            entityId: request.entityId,
            analyzedAt: new Date().toISOString(),
            data,
            provider: provider.name,
            tokensUsed,
            cached: false,
        };
    } catch (err) {
        log.error('Analysis error', new Error((err as Error).message));
        return {
            success: false,
            entityType: request.entityType,
            entityId: request.entityId,
            analyzedAt: new Date().toISOString(),
            error: (err as Error).message,
            provider: provider.name,
        };
    }
}

// ============================================================================
// Response Parsing
// ============================================================================

/**
 * Parse AI response into structured data
 */
export function parseAnalysisResponse(response: string, analysisType: AnalysisType): ThreatAssessment | MalwareClassification | RiskScoreResult | CVEAnalysis | ActorProfile | string {
    if (analysisType === 'summarization') {
        return response;
    }

    try {
        // Extract JSON from response (may be wrapped in markdown code blocks)
        const jsonMatch = response.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
            return JSON.parse(jsonMatch[0]);
        }
    } catch {
        log.warn('Failed to parse JSON response, returning raw text');
    }

    return response;
}
