/**
 * Nexus Providers & Utility Routes
 *
 * Health check, provider listing, and IOC extraction utility.
 */

import { Hono } from 'hono';
import type { Context } from 'hono';
import * as exa from '../../../../services/exa';
import * as searxng from '../../../../services/searxng';
import * as aiMW from '../../../../services/aiMiddleware';
import { extractIOCs } from '../../../../services/iocExtractor';
import { ValidationError } from '../../../../lib/errors';
import { ExtractIOCsSchema } from './schemas';

const router = new Hono();

/** GET /providers - List available search and AI providers */
router.get('/providers', async (c: Context) => {
    const [searxngHealth, aiStatus] = await Promise.all([
        searxng.checkHealth(),
        Promise.resolve(aiMW.getProviderStatus()),
    ]);

    return c.json({
        success: true,
        data: {
            search: {
                searxng: { available: searxngHealth.available, url: searxngHealth.url },
                exa: { available: !!process.env.EXA_API_KEY, note: 'Paid API — costs per query' },
            },
            ai: aiStatus,
        },
    });
});

/** GET /health - Intelligence service health check */
router.get('/health', async (c: Context) => {
    const health = await exa.checkHealth();
    return c.json({ success: true, data: health });
});

/** POST /extract-iocs - Extract IOCs from arbitrary text */
router.post('/extract-iocs', async (c: Context) => {
    const body = await c.req.json();
    const parsed = ExtractIOCsSchema.safeParse(body);
    if (!parsed.success) {
        throw new ValidationError(
            parsed.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; '),
        );
    }

    const result = extractIOCs(parsed.data.text);
    return c.json({ success: true, data: result });
});

export default router;
