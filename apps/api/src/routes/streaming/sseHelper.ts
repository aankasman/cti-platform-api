/**
 * SSE Stream Helper — DRY factory for SSE streaming endpoints
 *
 * Encapsulates the common pattern: register client, subscribe to channels,
 * poll messages, send heartbeats, and clean up on disconnect.
 */

import type { Context } from 'hono';
import { streamSSE } from 'hono/streaming';
import { wsManager } from '../../websocket';
import { createLogger } from '../../lib/logger';

const log = createLogger('streaming');

/**
 * Creates an SSE streaming response for the given channels.
 *
 * @param c       - Hono context
 * @param channels - Channel names to subscribe to
 * @param label    - Human-readable label for log messages
 * @param eventType - Default event type for messages (defaults to first channel name)
 */
export function createSSEStream(
    c: Context,
    channels: string[],
    label: string,
    eventType?: string,
) {
    const defaultEvent = eventType || channels[0] || 'data';

    return streamSSE(c, async (stream) => {
        const clientId = wsManager.registerClient();

        for (const ch of channels) {
            wsManager.subscribe(clientId, ch);
        }

        // Send initial connection event
        await stream.writeSSE({
            event: 'connected',
            data: JSON.stringify({
                clientId,
                channels,
                message: `Connected to ${label}`,
            }),
        });

        // Poll for messages and stream them
        const interval = setInterval(async () => {
            try {
                const messages = wsManager.getMessages(clientId);
                for (const msg of messages) {
                    await stream.writeSSE({
                        event: msg.type || defaultEvent,
                        data: JSON.stringify(msg),
                    });
                }
            } catch {
                clearInterval(interval);
            }
        }, 1000);

        // Heartbeat every 30s
        const heartbeat = setInterval(async () => {
            try {
                await stream.writeSSE({
                    event: 'heartbeat',
                    data: JSON.stringify({ ts: new Date().toISOString() }),
                });
            } catch {
                clearInterval(heartbeat);
            }
        }, 30000);

        // Cleanup on disconnect
        stream.onAbort(() => {
            clearInterval(interval);
            clearInterval(heartbeat);
            wsManager.unregisterClient(clientId);
            log.info(`${label} client disconnected`, { clientId });
        });

        // Keep the stream alive
        while (true) {
            await new Promise((resolve) => setTimeout(resolve, 1000));
        }
    });
}
