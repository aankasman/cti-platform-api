/**
 * Webhook Database Schema
 * 
 * Tables for webhook subscriptions and delivery logs.
 */

import { pgTable, uuid, varchar, text, timestamp, jsonb, boolean, integer, index } from 'drizzle-orm/pg-core';

// =============================================================================
// Webhook Subscriptions
// =============================================================================

export const webhookSubscriptions = pgTable('webhook_subscriptions', {
    id: uuid('id').primaryKey().defaultRandom(),

    // Subscriber info
    name: varchar('name', { length: 255 }).notNull(),
    url: text('url').notNull(),
    secret: varchar('secret', { length: 255 }), // For HMAC signature verification

    // What to subscribe to
    events: jsonb('events').$type<string[]>().default(['*']),
    // Events: ioc.created, ioc.updated, vulnerability.created, threat_actor.created, feed.completed, alert.high_severity

    // Filters
    filters: jsonb('filters').$type<{
        severity?: string[];
        type?: string[];
        source?: string[];
    }>().default({}),

    // Status
    isActive: boolean('is_active').default(true),
    lastDeliveryAt: timestamp('last_delivery_at', { withTimezone: true }),
    lastDeliveryStatus: varchar('last_delivery_status', { length: 20 }), // success, failed
    failureCount: integer('failure_count').default(0),

    // Metadata
    headers: jsonb('headers').$type<Record<string, string>>().default({}),
    createdBy: varchar('created_by', { length: 255 }),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
    urlIdx: index('webhook_subscriptions_url_idx').on(table.url),
    isActiveIdx: index('webhook_subscriptions_is_active_idx').on(table.isActive),
}));

// =============================================================================
// Webhook Delivery Logs
// =============================================================================

export const webhookDeliveryLogs = pgTable('webhook_delivery_logs', {
    id: uuid('id').primaryKey().defaultRandom(),

    subscriptionId: uuid('subscription_id').notNull().references(() => webhookSubscriptions.id),

    // Event details
    eventType: varchar('event_type', { length: 100 }).notNull(),
    payload: jsonb('payload').notNull(),

    // Delivery attempt
    attemptNumber: integer('attempt_number').default(1),
    requestHeaders: jsonb('request_headers').$type<Record<string, string>>(),
    requestBody: text('request_body'),

    // Response
    responseStatus: integer('response_status'),
    responseBody: text('response_body'),
    responseTimeMs: integer('response_time_ms'),

    // Status
    status: varchar('status', { length: 20 }).notNull(), // pending, success, failed, retrying
    errorMessage: text('error_message'),

    // Timestamps
    deliveredAt: timestamp('delivered_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
    subscriptionIdx: index('webhook_delivery_logs_subscription_idx').on(table.subscriptionId),
    eventTypeIdx: index('webhook_delivery_logs_event_type_idx').on(table.eventType),
    statusIdx: index('webhook_delivery_logs_status_idx').on(table.status),
}));

// Type exports
export type WebhookSubscription = typeof webhookSubscriptions.$inferSelect;
export type NewWebhookSubscription = typeof webhookSubscriptions.$inferInsert;
export type WebhookDeliveryLog = typeof webhookDeliveryLogs.$inferSelect;
export type NewWebhookDeliveryLog = typeof webhookDeliveryLogs.$inferInsert;
