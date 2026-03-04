/**
 * SSE Streaming Routes — Real-Time CTI Intelligence
 *
 * Server-Sent Events endpoint for push-based intelligence updates.
 * Replaces polling for real-time SOC dashboards.
 *
 * Usage:
 *   GET /v2/events?channels=ioc,alert,feed
 *   GET /v2/events (all channels)
 */

import { Hono } from 'hono';
import { eventBus, type EventChannel } from '../services/eventBus';
import { SSEPublishSchema } from '../lib/schemas';
import { createLogger } from '../lib/logger';

const log = createLogger('SSE');

const sseRouter = new Hono();

const VALID_CHANNELS: EventChannel[] = ['ioc', 'alert', 'feed', 'enrichment', 'system'];

/**
 * SSE endpoint — streams real-time CTI events
 */
sseRouter.get('/events', (c) => {
    const channelsParam = c.req.query('channels');
    const channels: EventChannel[] = channelsParam
        ? channelsParam.split(',').filter((ch): ch is EventChannel => VALID_CHANNELS.includes(ch as EventChannel))
        : VALID_CHANNELS;

    log.info('SSE client connected', { channels });

    const stream = eventBus.createSSEStream(channels);

    return new Response(stream, {
        headers: {
            'Content-Type': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'X-Accel-Buffering': 'no', // Disable Nginx/Traefik buffering
        },
    });
});

/**
 * Publish an event (admin/internal use)
 */
sseRouter.post('/events/publish', async (c) => {
    const body = await c.req.json();
    const { channel, type, data, source } = SSEPublishSchema.parse(body);

    await eventBus.publish(channel as EventChannel, type, data, source);
    return c.json({ success: true, message: 'Event published' });
});

/**
 * List available channels
 */
sseRouter.get('/events/channels', (c) => {
    return c.json({
        success: true,
        data: {
            channels: VALID_CHANNELS.map(ch => ({
                name: ch,
                description: getChannelDescription(ch),
            })),
        },
    });
});

function getChannelDescription(channel: EventChannel): string {
    const descriptions: Record<EventChannel, string> = {
        ioc: 'New or updated Indicators of Compromise',
        alert: 'Critical security alerts and notifications',
        feed: 'Feed health and status changes',
        enrichment: 'Enrichment job completions',
        system: 'System health and operational events',
    };
    return descriptions[channel];
}

export default sseRouter;
