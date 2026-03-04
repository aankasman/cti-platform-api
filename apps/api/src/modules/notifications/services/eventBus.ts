/**
 * Server-Sent Events (SSE) Event Bus
 *
 * Redis Pub/Sub backed event bus for real-time CTI intelligence streaming.
 * Broadcasts events to all connected SSE clients.
 *
 * Channels:
 *   rjn:events:ioc       — new/updated IOCs
 *   rjn:events:alert     — critical alerts
 *   rjn:events:feed      — feed status changes
 *   rjn:events:enrichment — enrichment completions
 *   rjn:events:system    — system health events
 */

import { Redis } from 'ioredis';
import { createLogger } from '../../../lib/logger';

const log = createLogger('EventBus');

// ============================================================================
// Types
// ============================================================================

export type EventChannel = 'ioc' | 'alert' | 'feed' | 'enrichment' | 'system';

export interface CTIEvent {
    channel: EventChannel;
    type: string;
    data: Record<string, unknown>;
    timestamp: string;
    source?: string;
}

type EventListener = (event: CTIEvent) => void;

// ============================================================================
// Event Bus (Singleton)
// ============================================================================

const CHANNEL_PREFIX = 'rjn:events:';
const ALL_CHANNELS: EventChannel[] = ['ioc', 'alert', 'feed', 'enrichment', 'system'];

class EventBus {
    private publisher: Redis | null = null;
    private subscriber: Redis | null = null;
    private listeners = new Map<string, Set<EventListener>>();
    private isRunning = false;

    /**
     * Initialize connections (call once at startup)
     */
    async start(): Promise<void> {
        if (this.isRunning) return;

        const cacheUrl = process.env.REDIS_CACHE_URL
            || process.env.REDIS_URL
            || 'redis://localhost:6379';

        // Pub/Sub uses the cache Redis (volatile, low-latency)
        this.publisher = new Redis(cacheUrl, { lazyConnect: true });
        this.subscriber = new Redis(cacheUrl, { lazyConnect: true });

        await Promise.all([
            this.publisher.connect(),
            this.subscriber.connect(),
        ]);

        // Subscribe to all channels
        const channels = ALL_CHANNELS.map(c => `${CHANNEL_PREFIX}${c}`);
        await this.subscriber.subscribe(...channels);

        this.subscriber.on('message', (_channel: string, message: string) => {
            try {
                const event = JSON.parse(message) as CTIEvent;
                this.dispatch(event);
            } catch (err) {
                log.warn('Failed to parse event', { error: (err as Error).message });
            }
        });

        this.isRunning = true;
        log.info('EventBus started', { channels: ALL_CHANNELS });
    }

    /**
     * Publish an event to a channel
     */
    async publish(channel: EventChannel, type: string, data: Record<string, unknown>, source?: string): Promise<void> {
        if (!this.publisher) {
            log.warn('EventBus not started, dropping event', { channel, type });
            return;
        }

        const event: CTIEvent = {
            channel,
            type,
            data,
            timestamp: new Date().toISOString(),
            source,
        };

        await this.publisher.publish(
            `${CHANNEL_PREFIX}${channel}`,
            JSON.stringify(event),
        );
    }

    /**
     * Subscribe to events on specific channels
     */
    on(channel: EventChannel | '*', listener: EventListener): () => void {
        const key = channel;
        if (!this.listeners.has(key)) {
            this.listeners.set(key, new Set());
        }
        this.listeners.get(key)!.add(listener);

        // Return unsubscribe function
        return () => {
            this.listeners.get(key)?.delete(listener);
        };
    }

    /**
     * Create an SSE-compatible ReadableStream for a client
     */
    createSSEStream(channels: EventChannel[] = ALL_CHANNELS): ReadableStream {
        const listeners: Array<() => void> = [];

        return new ReadableStream({
            start: (controller) => {
                // Send initial heartbeat
                controller.enqueue(': connected\n\n');

                // Subscribe to requested channels
                for (const channel of channels) {
                    const unsub = this.on(channel, (event) => {
                        const sseData = `event: ${event.channel}\ndata: ${JSON.stringify(event)}\n\n`;
                        try {
                            controller.enqueue(sseData);
                        } catch {
                            // Stream closed
                        }
                    });
                    listeners.push(unsub);
                }

                // Also subscribe to wildcard listeners
                const unsubAll = this.on('*', (event) => {
                    if (channels.includes(event.channel)) {
                        const sseData = `event: ${event.channel}\ndata: ${JSON.stringify(event)}\n\n`;
                        try {
                            controller.enqueue(sseData);
                        } catch { /* closed */ }
                    }
                });
                listeners.push(unsubAll);

                // Heartbeat every 30s to keep connection alive
                const heartbeat = setInterval(() => {
                    try {
                        controller.enqueue(': heartbeat\n\n');
                    } catch {
                        clearInterval(heartbeat);
                    }
                }, 30_000);

                listeners.push(() => clearInterval(heartbeat));
            },
            cancel: () => {
                listeners.forEach(unsub => unsub());
            },
        });
    }

    private dispatch(event: CTIEvent): void {
        // Notify channel-specific listeners
        const channelListeners = this.listeners.get(event.channel);
        if (channelListeners) {
            for (const listener of channelListeners) {
                try { listener(event); } catch { /* ignore */ }
            }
        }

        // Notify wildcard listeners
        const wildcardListeners = this.listeners.get('*');
        if (wildcardListeners) {
            for (const listener of wildcardListeners) {
                try { listener(event); } catch { /* ignore */ }
            }
        }
    }

    /**
     * Graceful shutdown
     */
    async shutdown(): Promise<void> {
        this.isRunning = false;
        await Promise.allSettled([
            this.subscriber?.quit(),
            this.publisher?.quit(),
        ]);
        this.listeners.clear();
        log.info('EventBus shut down');
    }
}

// Singleton instance
export const eventBus = new EventBus();
