/**
 * Database Schema - Web Intelligence (Exa Integration)
 *
 * Tables for Exa Websets, web intelligence items, and extracted mentions.
 */

import { pgTable, uuid, varchar, text, timestamp, jsonb, index, integer, boolean } from 'drizzle-orm/pg-core';

// ============================================================================
// Exa Websets (tracked Webset IDs and metadata)
// ============================================================================

export const exaWebsets = pgTable('exa_websets', {
    id: uuid('id').primaryKey().defaultRandom(),
    exaWebsetId: varchar('exa_webset_id', { length: 255 }).notNull().unique(),
    category: varchar('category', { length: 50 }).notNull(), // malware-c2, zero-day-cve, apt-actors, socmint
    title: varchar('title', { length: 500 }).notNull(),
    status: varchar('status', { length: 20 }).notNull().default('active'),
    exaMonitorId: varchar('exa_monitor_id', { length: 255 }),
    itemCount: integer('item_count').default(0),
    lastSyncAt: timestamp('last_sync_at', { withTimezone: true }),
    config: jsonb('config').$type<Record<string, unknown>>().default({}),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
    categoryIdx: index('exa_websets_category_idx').on(table.category),
    statusIdx: index('exa_websets_status_idx').on(table.status),
    exaWebsetIdIdx: index('exa_websets_exa_id_idx').on(table.exaWebsetId),
}));

// ============================================================================
// Web Intelligence Items (individual items from Exa Websets)
// ============================================================================

export const webIntelItems = pgTable('web_intel_items', {
    id: uuid('id').primaryKey().defaultRandom(),
    exaItemId: varchar('exa_item_id', { length: 255 }).unique(), // nullable for non-Exa sources
    websetId: uuid('webset_id').references(() => exaWebsets.id),
    category: varchar('category', { length: 50 }).notNull(),

    // Source content
    title: varchar('title', { length: 2000 }),
    url: text('url'),
    sourceUrl: text('source_url'),
    author: varchar('author', { length: 500 }),
    publishedAt: timestamp('published_at', { withTimezone: true }),

    // Extracted text
    textContent: text('text_content'),
    summary: text('summary'),
    highlights: jsonb('highlights').$type<string[]>().default([]),

    // AI analysis results (from AI middleware)
    aiSummary: text('ai_summary'),
    extractedEntities: jsonb('extracted_entities').$type<Record<string, string[]>>().default({}),

    // Exa enrichments (structured)
    enrichments: jsonb('enrichments').$type<Record<string, unknown>>().default({}),

    // Processing status
    iocExtracted: boolean('ioc_extracted').default(false),
    embeddingGenerated: boolean('embedding_generated').default(false),
    neo4jSynced: boolean('neo4j_synced').default(false),

    // Metadata
    sourceProvider: varchar('source_provider', { length: 20 }).default('exa'), // exa, searxng, manual
    platform: varchar('platform', { length: 50 }), // twitter, reddit, blog, forum
    severity: varchar('severity', { length: 20 }),   // critical, high, medium, low
    confidence: integer('confidence'),                // 0-100

    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
    categoryIdx: index('web_intel_items_category_idx').on(table.category),
    websetIdIdx: index('web_intel_items_webset_id_idx').on(table.websetId),
    publishedAtIdx: index('web_intel_items_published_at_idx').on(table.publishedAt),
    severityIdx: index('web_intel_items_severity_idx').on(table.severity),
    platformIdx: index('web_intel_items_platform_idx').on(table.platform),
    exaItemIdIdx: index('web_intel_items_exa_item_id_idx').on(table.exaItemId),
    sourceProviderIdx: index('web_intel_items_source_provider_idx').on(table.sourceProvider),
}));

// ============================================================================
// Web Intelligence Mentions (IOCs/CVEs/Actors extracted from items)
// ============================================================================

export const webIntelMentions = pgTable('web_intel_mentions', {
    id: uuid('id').primaryKey().defaultRandom(),
    itemId: uuid('item_id').references(() => webIntelItems.id).notNull(),
    type: varchar('type', { length: 30 }).notNull(), // ipv4, domain, hash-sha256, cve, etc.
    value: varchar('value', { length: 2000 }).notNull(),
    canonicalId: varchar('canonical_id', { length: 128 }).notNull(),
    confidence: integer('confidence').default(0),
    context: text('context'), // surrounding text snippet
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
    itemIdIdx: index('web_intel_mentions_item_id_idx').on(table.itemId),
    typeIdx: index('web_intel_mentions_type_idx').on(table.type),
    valueIdx: index('web_intel_mentions_value_idx').on(table.value),
    canonicalIdIdx: index('web_intel_mentions_canonical_id_idx').on(table.canonicalId),
}));

// ============================================================================
// Campaigns (clustered intelligence activity)
// ============================================================================

export const campaigns = pgTable('campaigns', {
    id: uuid('id').primaryKey().defaultRandom(),
    name: varchar('name', { length: 500 }).notNull(),
    description: text('description'),
    status: varchar('status', { length: 20 }).notNull().default('active'), // active, resolved, investigating
    severity: varchar('severity', { length: 20 }),
    firstSeen: timestamp('first_seen', { withTimezone: true }),
    lastSeen: timestamp('last_seen', { withTimezone: true }),
    indicatorCount: integer('indicator_count').default(0),
    metadata: jsonb('metadata').$type<Record<string, unknown>>().default({}),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
    statusIdx: index('campaigns_status_idx').on(table.status),
    severityIdx: index('campaigns_severity_idx').on(table.severity),
}));

// ============================================================================
// Campaign Indicators (IOCs/items linked to a campaign)
// ============================================================================

export const campaignIndicators = pgTable('campaign_indicators', {
    id: uuid('id').primaryKey().defaultRandom(),
    campaignId: uuid('campaign_id').references(() => campaigns.id).notNull(),
    mentionId: uuid('mention_id').references(() => webIntelMentions.id),
    itemId: uuid('item_id').references(() => webIntelItems.id),
    addedAt: timestamp('added_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
    campaignIdIdx: index('campaign_indicators_campaign_id_idx').on(table.campaignId),
    mentionIdIdx: index('campaign_indicators_mention_id_idx').on(table.mentionId),
}));
