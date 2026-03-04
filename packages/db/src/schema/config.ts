/**
 * Database Schema - Configuration Tables
 *
 * Stores feed configs, API key slot definitions, and service connection
 * definitions in PostgreSQL instead of hardcoded arrays + Redis.
 * Supports runtime CRUD via admin API.
 */

import { pgTable, varchar, text, timestamp, boolean, jsonb } from 'drizzle-orm/pg-core';

// ============================================================================
// Feeds Configuration
// ============================================================================

export const feedsConfig = pgTable('feeds_config', {
    id: varchar('id', { length: 100 }).primaryKey(),
    name: varchar('name', { length: 255 }).notNull(),
    source: varchar('source', { length: 100 }).notNull(),
    description: text('description').notNull().default(''),
    cron: varchar('cron', { length: 50 }).notNull().default('0 * * * *'),
    enabled: boolean('enabled').default(true).notNull(),
    category: varchar('category', { length: 50 }).notNull().default('custom-api'),
    requiresApiKey: varchar('requires_api_key', { length: 100 }),
    isCustom: boolean('is_custom').default(false).notNull(),
    url: text('url'),
    authHeader: varchar('auth_header', { length: 100 }),
    authKeyRef: varchar('auth_key_ref', { length: 100 }),
    format: varchar('format', { length: 20 }),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
});

// ============================================================================
// API Key Slot Definitions
// ============================================================================

export const apiKeySlots = pgTable('api_key_slots', {
    id: varchar('id', { length: 100 }).primaryKey(),
    name: varchar('name', { length: 255 }).notNull(),
    provider: varchar('provider', { length: 100 }).notNull(),
    envVar: varchar('env_var', { length: 100 }).notNull(),
    testEndpoint: text('test_endpoint'),
    authHeaderName: varchar('auth_header_name', { length: 100 }),
    isCustom: boolean('is_custom').default(false).notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
});

// ============================================================================
// Service Connection Definitions
// ============================================================================

export interface ServiceEnvVar {
    key: string;
    label: string;
    secret?: boolean;
    placeholder?: string;
}

export const servicesConfig = pgTable('services_config', {
    id: varchar('id', { length: 100 }).primaryKey(),
    name: varchar('name', { length: 255 }).notNull(),
    envVars: jsonb('env_vars').$type<ServiceEnvVar[]>().default([]).notNull(),
    isCustom: boolean('is_custom').default(false).notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
});

// Type exports
export type FeedConfigRecord = typeof feedsConfig.$inferSelect;
export type NewFeedConfig = typeof feedsConfig.$inferInsert;
export type ApiKeySlotRecord = typeof apiKeySlots.$inferSelect;
export type NewApiKeySlot = typeof apiKeySlots.$inferInsert;
export type ServiceConfigRecord = typeof servicesConfig.$inferSelect;
export type NewServiceConfig = typeof servicesConfig.$inferInsert;
