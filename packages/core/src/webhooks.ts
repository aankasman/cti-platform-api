/**
 * Webhook Delivery Service
 * 
 * Handles webhook event processing and HTTP delivery with retry logic.
 */

import { createHmac } from 'crypto';

// ============================================================================
// Types
// ============================================================================

export interface WebhookEvent {
    id: string;
    type: string;
    timestamp: string;
    data: Record<string, unknown>;
}

export interface WebhookDeliveryResult {
    success: boolean;
    statusCode?: number;
    responseTime?: number;
    error?: string;
}

interface WebhookTarget {
    id: string;
    url: string;
    secret?: string | null;
    headers?: Record<string, string>;
    events: string[];
    filters?: {
        severity?: string[];
        type?: string[];
        source?: string[];
    };
}

// ============================================================================
// In-Memory Subscription Store (for demo - replace with DB in production)
// ============================================================================

const subscriptions = new Map<string, WebhookTarget>();
const deliveryQueue: Array<{ subscription: WebhookTarget; event: WebhookEvent }> = [];

// ============================================================================
// Event Listeners (for playbook integration)
// ============================================================================

type EventListener = (event: string, data: Record<string, unknown>) => Promise<void> | void;
const eventListeners: EventListener[] = [];

/**
 * Register a listener that will be called for every webhook event.
 * Used by the playbooks service to evaluate automation rules.
 */
export function addWebhookEventListener(listener: EventListener): void {
    eventListeners.push(listener);
}

export function removeWebhookEventListener(listener: EventListener): void {
    const idx = eventListeners.indexOf(listener);
    if (idx >= 0) eventListeners.splice(idx, 1);
}

// ============================================================================
// Signature Generation
// ============================================================================

export function generateSignature(payload: string, secret: string): string {
    return createHmac('sha256', secret).update(payload).digest('hex');
}

export function generateWebhookHeaders(
    event: WebhookEvent,
    payload: string,
    secret?: string | null
): Record<string, string> {
    const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'X-Webhook-Event': event.type,
        'X-Webhook-Timestamp': event.timestamp,
        'X-Webhook-ID': event.id,
    };

    if (secret) {
        headers['X-Webhook-Signature'] = `sha256=${generateSignature(payload, secret)}`;
    }

    return headers;
}

// ============================================================================
// Delivery Logic
// ============================================================================

export async function deliverWebhook(
    subscription: WebhookTarget,
    event: WebhookEvent
): Promise<WebhookDeliveryResult> {
    const payload = JSON.stringify(event);
    const headers = {
        ...generateWebhookHeaders(event, payload, subscription.secret),
        ...subscription.headers,
    };

    const startTime = Date.now();

    try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 30000); // 30s timeout

        const response = await fetch(subscription.url, {
            method: 'POST',
            headers,
            body: payload,
            signal: controller.signal,
        });

        clearTimeout(timeout);

        const responseTime = Date.now() - startTime;

        if (response.ok) {
            return {
                success: true,
                statusCode: response.status,
                responseTime,
            };
        }

        return {
            success: false,
            statusCode: response.status,
            responseTime,
            error: `HTTP ${response.status}: ${response.statusText}`,
        };
    } catch (error) {
        return {
            success: false,
            responseTime: Date.now() - startTime,
            error: error instanceof Error ? error.message : (error as Error).message,
        };
    }
}

// ============================================================================
// Event Filtering
// ============================================================================

function matchesFilters(event: WebhookEvent, filters?: WebhookTarget['filters']): boolean {
    if (!filters) return true;

    const data = event.data as Record<string, unknown>;

    // Check severity filter
    if (filters.severity && filters.severity.length > 0) {
        const itemSeverity = data.severity as string;
        if (itemSeverity && !filters.severity.includes(itemSeverity)) {
            return false;
        }
    }

    // Check type filter
    if (filters.type && filters.type.length > 0) {
        const itemType = data.type as string;
        if (itemType && !filters.type.includes(itemType)) {
            return false;
        }
    }

    // Check source filter
    if (filters.source && filters.source.length > 0) {
        const itemSource = data.source as string;
        if (itemSource && !filters.source.includes(itemSource)) {
            return false;
        }
    }

    return true;
}

function matchesEventType(subscription: WebhookTarget, eventType: string): boolean {
    if (subscription.events.includes('*')) return true;
    if (subscription.events.includes(eventType)) return true;

    // Check wildcard patterns (e.g., ioc.* matches ioc.created)
    const [category] = eventType.split('.');
    return subscription.events.includes(`${category}.*`);
}

// ============================================================================
// Public API
// ============================================================================

/**
 * Emit a webhook event to all matching subscriptions
 */
export async function emitWebhookEvent(
    type: string,
    data: Record<string, unknown>
): Promise<{ delivered: number; failed: number }> {
    const event: WebhookEvent = {
        id: crypto.randomUUID(),
        type,
        timestamp: new Date().toISOString(),
        data,
    };

    let delivered = 0;
    let failed = 0;

    for (const subscription of subscriptions.values()) {
        if (!matchesEventType(subscription, type)) continue;
        if (!matchesFilters(event, subscription.filters)) continue;

        const result = await deliverWebhook(subscription, event);
        if (result.success) {
            delivered++;
        } else {
            failed++;
            console.error(`Webhook delivery failed to ${subscription.url}:`, result.error);
        }
    }

    // Notify event listeners (playbooks, analytics, etc.)
    for (const listener of eventListeners) {
        try {
            await listener(type, data);
        } catch (err) {
            console.error('Event listener error:', err);
        }
    }

    return { delivered, failed };
}

/**
 * Register a webhook subscription
 */
export function registerSubscription(subscription: WebhookTarget): void {
    subscriptions.set(subscription.id, subscription);
}

/**
 * Unregister a webhook subscription
 */
export function unregisterSubscription(id: string): boolean {
    return subscriptions.delete(id);
}

/**
 * Get all subscriptions
 */
export function getSubscriptions(): WebhookTarget[] {
    return Array.from(subscriptions.values());
}

/**
 * Get subscription by ID
 */
export function getSubscription(id: string): WebhookTarget | undefined {
    return subscriptions.get(id);
}

// ============================================================================
// Event Types
// ============================================================================

export const WEBHOOK_EVENTS = {
    IOC_CREATED: 'ioc.created',
    IOC_UPDATED: 'ioc.updated',
    IOC_DELETED: 'ioc.deleted',
    VULNERABILITY_CREATED: 'vulnerability.created',
    VULNERABILITY_UPDATED: 'vulnerability.updated',
    THREAT_ACTOR_CREATED: 'threat_actor.created',
    THREAT_ACTOR_UPDATED: 'threat_actor.updated',
    FEED_SYNC_STARTED: 'feed.sync_started',
    FEED_SYNC_COMPLETED: 'feed.sync_completed',
    FEED_SYNC_FAILED: 'feed.sync_failed',
    ALERT_HIGH_SEVERITY: 'alert.high_severity',
    ALERT_CRITICAL: 'alert.critical',
    // Sightings
    SIGHTING_CREATED: 'sighting.created',
    // Correlation
    CORRELATION_COMPLETED: 'correlation.completed',
    // Playbooks
    PLAYBOOK_EXECUTED: 'playbook.executed',
    PLAYBOOK_NOTIFICATION: 'playbook.notification',
} as const;
