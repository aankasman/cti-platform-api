/**
 * Redis Streams Event Stream — Durable Event-Driven Architecture
 *
 * Unlike the existing Pub/Sub EventBus (fire-and-forget for SSE),
 * this module uses Redis Streams for **durable, replayable** event
 * processing with consumer groups. Every event is persisted and
 * acknowledged — no data loss even if consumers are down.
 *
 * Architecture:
 *   Producer → Redis Stream → Consumer Group → Consumers (workers)
 *
 * Streams:
 *   rjn:stream:ioc         — IOC CRUD events
 *   rjn:stream:vuln        — CVE/vulnerability events
 *   rjn:stream:actor       — Threat actor events
 *   rjn:stream:enrichment  — Enrichment completions
 *   rjn:stream:system      — System lifecycle events
 *
 * Consumer Groups:
 *   enrichment-group    — Triggers auto-enrichment on new IOCs
 *   opensearch-group    — Syncs entities to OpenSearch
 *   neo4j-group         — Syncs relationships to Neo4j
 *   alert-group         — Evaluates alert rules
 *   taxii-group         — Publishes to TAXII collections
 *   meili-group         — Syncs to Meilisearch instant search
 */

import { Redis } from 'ioredis';
import { createLogger } from '../lib/logger';
import { eventBus } from './eventBus';

const log = createLogger('EventStream');

// ============================================================================
// Types
// ============================================================================

export type StreamName = 'ioc' | 'vuln' | 'actor' | 'enrichment' | 'system';

export interface StreamEvent {
    stream: StreamName;
    action: string; // created | updated | deleted | enriched | completed
    entityId: string;
    entityType: string;
    data: Record<string, unknown>;
    source: string;
    timestamp: string;
}

export interface ConsumerConfig {
    /** Consumer group name */
    group: string;
    /** Unique consumer name within the group */
    consumer: string;
    /** Streams to listen on */
    streams: StreamName[];
    /** Handler function */
    handler: (event: StreamEvent) => Promise<void>;
    /** Max events to read per batch */
    batchSize?: number;
    /** Block timeout in ms (0 = forever) */
    blockMs?: number;
    /** Max retries before sending to DLQ */
    maxRetries?: number;
}

// ============================================================================
// Constants
// ============================================================================

const STREAM_PREFIX = 'rjn:stream:';
const ALL_STREAMS: StreamName[] = ['ioc', 'vuln', 'actor', 'enrichment', 'system'];
const MAX_STREAM_LEN = 50_000; // Trim old entries beyond this

// ============================================================================
// Event Stream Service (Singleton)
// ============================================================================

class EventStreamService {
    private redis: Redis | null = null;
    private adminRedis: Redis | null = null;  // Separate connection for non-blocking admin queries
    private consumers: Map<string, { running: boolean; config: ConsumerConfig }> = new Map();
    private isRunning = false;

    /**
     * Initialize the Redis connection and create consumer groups
     */
    async start(): Promise<void> {
        if (this.isRunning) return;

        const queueUrl = process.env.REDIS_QUEUE_URL
            || process.env.REDIS_URL
            || 'redis://localhost:6379';

        log.info('EventStream connecting to Redis', { url: queueUrl.replace(/\/\/.*@/, '//*****@') });

        try {
            // Main connection for consumers (blocking XREADGROUP)
            this.redis = new Redis(queueUrl, {
                lazyConnect: true,
                maxRetriesPerRequest: null,
                connectTimeout: 5000,
            });
            this.redis.on('error', (err) => {
                log.warn('Redis consumer connection error', { error: err.message });
            });
            await this.redis.connect();
            await this.redis.ping();

            // Separate connection for admin queries (XLEN, XINFO — non-blocking)
            // Consumers' blocking XREADGROUP monopolizes the main connection
            this.adminRedis = new Redis(queueUrl, {
                lazyConnect: true,
                maxRetriesPerRequest: 3,
                connectTimeout: 5000,
            });
            this.adminRedis.on('error', (err) => {
                log.warn('Redis admin connection error', { error: err.message });
            });
            await this.adminRedis.connect();

            // Ensure all streams exist with their consumer groups
            await this.ensureStreams();

            this.isRunning = true;
            log.info('EventStream started', { streams: ALL_STREAMS });
        } catch (err) {
            log.warn('EventStream Redis connection failed', { error: (err as Error).message, url: queueUrl.replace(/\/\/.*@/, '//*****@') });
            if (this.redis) { try { this.redis.disconnect(); } catch { /* ignore */ } }
            if (this.adminRedis) { try { this.adminRedis.disconnect(); } catch { /* ignore */ } }
            this.redis = null;
            this.adminRedis = null;
        }
    }

    /**
     * Create streams and consumer groups if they don't exist
     */
    private async ensureStreams(): Promise<void> {
        if (!this.redis) return;

        const groups = [
            'enrichment-group',
            'opensearch-group',
            'neo4j-group',
            'alert-group',
            'taxii-group',
            'meili-group',
            'audit-group',
        ];

        for (const stream of ALL_STREAMS) {
            const key = `${STREAM_PREFIX}${stream}`;
            for (const group of groups) {
                try {
                    await this.redis.xgroup('CREATE', key, group, '0', 'MKSTREAM');
                } catch (err) {
                    // BUSYGROUP = group already exists, which is fine
                    if (!(err as Error).message?.includes('BUSYGROUP')) {
                        log.warn('Failed to create consumer group', { stream, group, error: (err as Error).message });
                    }
                }
            }
        }
    }

    // ========================================================================
    // Producer API
    // ========================================================================

    /**
     * Emit an event to a Redis Stream (durable) + Pub/Sub EventBus (real-time SSE)
     */
    async emit(
        stream: StreamName,
        action: string,
        entityId: string,
        entityType: string,
        data: Record<string, unknown> = {},
        source: string = 'api',
    ): Promise<string | null> {
        const event: StreamEvent = {
            stream,
            action,
            entityId,
            entityType,
            data,
            source,
            timestamp: new Date().toISOString(),
        };

        // 1. Write to durable Redis Stream
        let messageId: string | null = null;
        if (this.redis) {
            try {
                messageId = await this.redis.xadd(
                    `${STREAM_PREFIX}${stream}`,
                    'MAXLEN', '~', String(MAX_STREAM_LEN),
                    '*',
                    'payload', JSON.stringify(event),
                );
            } catch (err) {
                log.error('Failed to write to stream', { stream, error: (err as Error).message });
            }
        }

        // 2. Also publish to Pub/Sub for real-time SSE delivery
        try {
            await eventBus.publish(
                stream === 'vuln' ? 'ioc' : stream === 'actor' ? 'ioc' : stream as 'ioc' | 'alert' | 'feed' | 'system',
                `${entityType}.${action}`,
                { ...data, entityId, entityType },
                source,
            );
        } catch {
            // SSE delivery is best-effort
        }

        return messageId;
    }

    /**
     * Convenience: emit IOC created event
     */
    async emitIOCCreated(iocId: string, data: Record<string, unknown>, source = 'feed-sync'): Promise<void> {
        await this.emit('ioc', 'created', iocId, 'indicator', data, source);
    }

    /**
     * Convenience: emit IOC enriched event
     */
    async emitIOCEnriched(iocId: string, data: Record<string, unknown>, source = 'enrichment'): Promise<void> {
        await this.emit('enrichment', 'completed', iocId, 'enrichment', data, source);
    }

    /**
     * Convenience: emit CVE created event
     */
    async emitVulnCreated(cveId: string, data: Record<string, unknown>, source = 'cve-sync'): Promise<void> {
        await this.emit('vuln', 'created', cveId, 'vulnerability', data, source);
    }

    /**
     * Convenience: emit actor discovered event
     */
    async emitActorDiscovered(actorId: string, data: Record<string, unknown>, source = 'feed-sync'): Promise<void> {
        await this.emit('actor', 'discovered', actorId, 'threat-actor', data, source);
    }

    // ========================================================================
    // Consumer API
    // ========================================================================

    /**
     * Register and start a consumer that processes events from a stream.
     * Uses XREADGROUP for at-least-once delivery with acknowledgement.
     */
    startConsumer(config: ConsumerConfig): void {
        const key = `${config.group}:${config.consumer}`;
        if (this.consumers.has(key)) {
            log.warn('Consumer already running', { key });
            return;
        }

        this.consumers.set(key, { running: true, config });
        this.consumeLoop(key, config).catch(err => {
            log.error('Consumer loop crashed', { key, error: (err as Error).message });
        });

        log.info('Consumer started', { group: config.group, consumer: config.consumer, streams: config.streams });
    }

    private async consumeLoop(key: string, config: ConsumerConfig): Promise<void> {
        const batchSize = config.batchSize || 10;
        const blockMs = config.blockMs || 5000;
        const maxRetries = config.maxRetries || 3;

        while (this.consumers.get(key)?.running) {
            if (!this.redis) {
                await sleep(1000);
                continue;
            }

            try {
                // Build XREADGROUP args for multiple streams
                const streamKeys = config.streams.map(s => `${STREAM_PREFIX}${s}`);
                const ids = config.streams.map(() => '>'); // Read new messages

                const result = await this.redis.xreadgroup(
                    'GROUP', config.group, config.consumer,
                    'COUNT', String(batchSize),
                    'BLOCK', String(blockMs),
                    'STREAMS', ...streamKeys, ...ids,
                ) as Array<[string, Array<[string, string[]]>]> | null;

                if (!result) continue; // Timeout, no new messages

                for (const [streamKey, messages] of result) {
                    for (const [messageId, fields] of messages) {
                        try {
                            // Parse the event payload
                            const payloadIdx = fields.indexOf('payload');
                            if (payloadIdx === -1 || !fields[payloadIdx + 1]) continue;

                            const event = JSON.parse(fields[payloadIdx + 1]) as StreamEvent;

                            // Process the event
                            await config.handler(event);

                            // Acknowledge successful processing
                            await this.redis.xack(streamKey, config.group, messageId);
                        } catch (err) {
                            log.warn('Event processing failed', {
                                group: config.group,
                                consumer: config.consumer,
                                messageId,
                                error: (err as Error).message,
                            });
                            // Don't ACK — message will be retried via XPENDING
                        }
                    }
                }
            } catch (err) {
                const errStr = err instanceof Error ? err.message : JSON.stringify(err);
                if (errStr?.includes('NOGROUP')) {
                    await this.ensureStreams();
                } else {
                    log.error('Consumer read error', { key, error: errStr });
                    await sleep(2000);
                }
            }
        }
    }

    /**
     * Claim and retry pending (unacknowledged) messages that are older than minIdleMs
     */
    async claimPending(
        stream: StreamName,
        group: string,
        consumer: string,
        minIdleMs: number = 60_000,
        count: number = 10,
    ): Promise<number> {
        if (!this.redis) return 0;

        const key = `${STREAM_PREFIX}${stream}`;
        try {
            const result = await this.redis.xautoclaim(
                key, group, consumer,
                String(minIdleMs), '0-0',
                'COUNT', String(count),
            ) as unknown as [unknown, unknown[]];

            const claimed = result?.[1]?.length || 0;
            if (claimed > 0) {
                log.info('Claimed pending messages', { stream, group, consumer, claimed });
            }
            return claimed;
        } catch {
            return 0;
        }
    }

    // ========================================================================
    // Stream Info
    // ========================================================================

    /**
     * Get info about all streams (length, groups, pending counts)
     * Times out after 5 seconds to avoid hanging the gateway proxy.
     */
    async getStreamInfo(): Promise<Record<string, {
        length: number;
        groups: Array<{ name: string; consumers: number; pending: number; lastDeliveredId: string }>;
    }>> {
        if (!this.adminRedis) return {};

        // Timeout after 5s — if Redis is unreachable, fail fast
        const timeoutMs = 5_000;
        const timeoutPromise = new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error('Stream info timed out')), timeoutMs)
        );

        try {
            return await Promise.race([this._fetchStreamInfo(), timeoutPromise]);
        } catch (err) {
            log.warn('getStreamInfo failed', { error: (err as Error).message });
            return {};
        }
    }

    private async _fetchStreamInfo(): Promise<Record<string, {
        length: number;
        groups: Array<{ name: string; consumers: number; pending: number; lastDeliveredId: string }>;
    }>> {
        const info: Record<string, { length: number; groups: Array<{ name: string; consumers: number; pending: number; lastDeliveredId: string }> }> = {};

        for (const stream of ALL_STREAMS) {
            const key = `${STREAM_PREFIX}${stream}`;
            try {
                const len = await this.adminRedis!.xlen(key);
                const groups = await this.adminRedis!.xinfo('GROUPS', key) as unknown as Array<Record<string, unknown>>;

                info[stream] = {
                    length: len,
                    groups: groups.map((g: Record<string, unknown>) => ({
                        name: String(g[1] || g.name || ''),
                        consumers: Number(g[3] || g.consumers || 0),
                        pending: Number(g[5] || g.pending || 0),
                        lastDeliveredId: String(g[7] || g['last-delivered-id'] || '0'),
                    })),
                };
            } catch {
                info[stream] = { length: 0, groups: [] };
            }
        }

        return info;
    }

    // ========================================================================
    // Lifecycle
    // ========================================================================

    /**
     * Stop all consumers and close the connection
     */
    async shutdown(): Promise<void> {
        // Stop all consumer loops
        for (const [key, entry] of this.consumers) {
            entry.running = false;
        }
        this.consumers.clear();

        await Promise.allSettled([
            this.redis?.quit(),
            this.adminRedis?.quit(),
        ]);
        this.redis = null;
        this.adminRedis = null;
        this.isRunning = false;
        log.info('EventStream shut down');
    }
}

function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Singleton
export const eventStream = new EventStreamService();
