/**
 * Stream Subscription & Status Management
 */

import { Hono } from 'hono';
import type { Context } from 'hono';
import { wsManager } from '../../../../websocket';
import { StreamSubscribeSchema } from '../../../../lib/schemas';

const managementRoutes = new Hono();

/**
 * POST /subscribe - Create a filtered subscription
 *
 * Allows clients to subscribe to specific channels or keyword filters.
 * Returns a clientId for use with the SSE or polling endpoints.
 */
managementRoutes.post('/subscribe', async (c: Context) => {
    const { channels, keywords } = StreamSubscribeSchema.parse(await c.req.json().catch(() => ({})));

    const clientId = wsManager.registerClient();

    for (const channel of channels) {
        wsManager.subscribe(clientId, channel);
    }

    return c.json({
        success: true,
        data: {
            clientId,
            channels,
            keywords,
            message: 'Subscription created. Use GET /stream/intel with this clientId or poll /ws/poll/:clientId',
            pollUrl: `/ws/poll/${clientId}`,
        },
    });
});

/**
 * GET /status - Stream health info
 */
managementRoutes.get('/status', (c: Context) => {
    const stats = wsManager.getStats();
    return c.json({
        success: true,
        data: {
            ...stats,
            availableStreams: [
                { path: '/v2/stream/intel', description: 'All web intelligence events' },
                { path: '/v2/stream/social', description: 'Social media intelligence (SOCMINT)' },
                { path: '/v2/stream/campaign', description: 'Campaign activity updates' },
            ],
        },
    });
});

export default managementRoutes;
