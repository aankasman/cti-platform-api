/**
 * Opengate Subscription Schema
 * 
 * Tables for managing API consumers (partners/customers):
 * - api_consumers: Partner/customer accounts with tier and quotas
 * - api_keys: Generated API keys for authentication
 * - api_usage: Request tracking for analytics and quota enforcement
 */

import { pgTable, uuid, varchar, text, integer, boolean, timestamp, jsonb, index, pgEnum } from 'drizzle-orm/pg-core';

// ============================================================================
// Enums
// ============================================================================

export const tierEnum = pgEnum('subscription_tier', ['free', 'pro', 'enterprise']);
export const keyStatusEnum = pgEnum('key_status', ['active', 'revoked', 'expired']);

// ============================================================================
// API Consumers (Partners/Customers)
// ============================================================================

export const apiConsumers = pgTable('api_consumers', {
    id: uuid('id').defaultRandom().primaryKey(),
    name: varchar('name', { length: 256 }).notNull(),
    email: varchar('email', { length: 256 }).notNull().unique(),
    organization: varchar('organization', { length: 256 }),

    // Subscription tier
    tier: tierEnum('tier').default('free').notNull(),

    // Quota settings (monthly requests)
    quotaMonthly: integer('quota_monthly').default(1000).notNull(),    // Free: 1000
    quotaUsed: integer('quota_used').default(0).notNull(),
    quotaResetDate: timestamp('quota_reset_date'),

    // Rate limiting (requests per minute)
    rateLimitRpm: integer('rate_limit_rpm').default(60).notNull(),     // Free: 60 RPM

    // Feature flags
    features: jsonb('features').$type<{
        graphql?: boolean;
        webhooks?: boolean;
        bulkExport?: boolean;
        realtime?: boolean;
    }>().default({}),

    // Status
    isActive: boolean('is_active').default(true).notNull(),
    verifiedAt: timestamp('verified_at'),

    // Metadata
    metadata: jsonb('metadata'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
}, (table) => ({
    emailIdx: index('consumers_email_idx').on(table.email),
    tierIdx: index('consumers_tier_idx').on(table.tier),
}));

// ============================================================================
// API Keys
// ============================================================================

export const consumerApiKeys = pgTable('consumer_api_keys', {
    id: uuid('id').defaultRandom().primaryKey(),
    consumerId: uuid('consumer_id').notNull().references(() => apiConsumers.id),

    // Key details
    keyHash: varchar('key_hash', { length: 128 }).notNull().unique(),  // SHA-256 hash
    keyPrefix: varchar('key_prefix', { length: 12 }).notNull(),        // First 8 chars for display
    name: varchar('name', { length: 128 }),                            // e.g., "Production Key"

    // Status
    status: keyStatusEnum('status').default('active').notNull(),

    // Permissions (subset of consumer features)
    permissions: jsonb('permissions').$type<string[]>().default([]),   // e.g., ['read:threats', 'read:iocs']

    // Usage tracking
    lastUsedAt: timestamp('last_used_at'),
    usageCount: integer('usage_count').default(0).notNull(),

    // Expiration
    expiresAt: timestamp('expires_at'),

    // Metadata
    createdAt: timestamp('created_at').defaultNow().notNull(),
    revokedAt: timestamp('revoked_at'),
}, (table) => ({
    consumerIdx: index('keys_consumer_idx').on(table.consumerId),
    keyHashIdx: index('keys_hash_idx').on(table.keyHash),
    prefixIdx: index('keys_prefix_idx').on(table.keyPrefix),
}));

// ============================================================================
// API Usage Logs
// ============================================================================

export const apiUsage = pgTable('api_usage', {
    id: uuid('id').defaultRandom().primaryKey(),
    consumerId: uuid('consumer_id').references(() => apiConsumers.id),
    keyId: uuid('key_id').references(() => consumerApiKeys.id),

    // Request details
    endpoint: varchar('endpoint', { length: 256 }).notNull(),
    method: varchar('method', { length: 10 }).notNull(),

    // Response
    statusCode: integer('status_code').notNull(),
    latencyMs: integer('latency_ms'),
    responseSize: integer('response_size'),

    // Client info
    ipAddress: varchar('ip_address', { length: 45 }),
    userAgent: varchar('user_agent', { length: 512 }),

    // Timestamp
    timestamp: timestamp('timestamp').defaultNow().notNull(),
}, (table) => ({
    consumerIdx: index('usage_consumer_idx').on(table.consumerId),
    timestampIdx: index('usage_timestamp_idx').on(table.timestamp),
    endpointIdx: index('usage_endpoint_idx').on(table.endpoint),
}));

// ============================================================================
// Webhooks (for event notifications)
// ============================================================================

export const consumerWebhooks = pgTable('consumer_webhooks', {
    id: uuid('id').defaultRandom().primaryKey(),
    consumerId: uuid('consumer_id').notNull().references(() => apiConsumers.id),

    url: varchar('url', { length: 512 }).notNull(),
    secret: varchar('secret', { length: 128 }),                        // HMAC signing secret

    // Event types to subscribe
    events: jsonb('events').$type<string[]>().default([]),             // e.g., ['threat.new', 'ioc.new']

    // Status
    isActive: boolean('is_active').default(true).notNull(),
    lastTriggeredAt: timestamp('last_triggered_at'),
    failureCount: integer('failure_count').default(0).notNull(),

    createdAt: timestamp('created_at').defaultNow().notNull(),
});

// ============================================================================
// Tier Configurations (reference)
// ============================================================================

export const TIER_LIMITS = {
    free: {
        quotaMonthly: 1000,
        rateLimitRpm: 60,
        features: { graphql: false, webhooks: false, bulkExport: false, realtime: false },
    },
    pro: {
        quotaMonthly: 50000,
        rateLimitRpm: 300,
        features: { graphql: true, webhooks: true, bulkExport: false, realtime: false },
    },
    enterprise: {
        quotaMonthly: -1, // Unlimited
        rateLimitRpm: 1000,
        features: { graphql: true, webhooks: true, bulkExport: true, realtime: true },
    },
} as const;

// Type exports
export type ApiConsumer = typeof apiConsumers.$inferSelect;
export type NewApiConsumer = typeof apiConsumers.$inferInsert;
export type ConsumerApiKey = typeof consumerApiKeys.$inferSelect;
export type ApiUsageLog = typeof apiUsage.$inferSelect;
