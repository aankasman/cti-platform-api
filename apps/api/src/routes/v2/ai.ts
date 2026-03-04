/**
 * V2 AI Analysis Route
 */

import { Hono } from 'hono';
import { analyzeEntity, EntityType } from '../../services/aiAnalysis';
import { AIAnalyzeSchema } from '../../lib/schemas';

const aiRoutes = new Hono();

/**
 * POST /ai/analyze
 * AI-powered analysis for any entity type (IOC, CVE, or Threat Actor)
 * Results are cached - subsequent requests return cached data instantly.
 *
 * Request body:
 * {
 *   entityType: 'ioc' | 'cve' | 'actor',
 *   entityId: string,
 *   entityData: { ... entity fields ... },
 *   forceRefresh?: boolean  // Set to true to regenerate analysis
 * }
 */
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

export default aiRoutes;
