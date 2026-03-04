/**
 * AI Analysis Cache Schema
 * 
 * Stores AI-generated analysis results for entities to avoid
 * repeated API calls and provide instant retrieval.
 */

import { pgTable, uuid, varchar, text, timestamp, jsonb, index, pgEnum } from 'drizzle-orm/pg-core';

// ============================================================================
// Enums
// ============================================================================

export const aiEntityTypeEnum = pgEnum('ai_entity_type', ['ioc', 'cve', 'actor']);

// ============================================================================
// AI Analysis Cache Table
// ============================================================================

export const aiAnalysisCache = pgTable('ai_analysis_cache', {
    id: uuid('id').primaryKey().defaultRandom(),

    // Entity reference
    entityType: aiEntityTypeEnum('entity_type').notNull(),
    entityId: uuid('entity_id').notNull(),

    // Analysis result
    analysisData: jsonb('analysis_data').notNull(),

    // Provider info
    provider: varchar('provider', { length: 50 }).notNull(),
    tokensUsed: varchar('tokens_used', { length: 20 }),

    // Entity data snapshot (to detect if entity changed)
    entityDataHash: varchar('entity_data_hash', { length: 64 }).notNull(),

    // Timestamps
    analyzedAt: timestamp('analyzed_at', { withTimezone: true }).defaultNow().notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
    entityIdx: index('ai_analysis_cache_entity_idx').on(table.entityType, table.entityId),
    entityHashIdx: index('ai_analysis_cache_entity_hash_idx').on(table.entityId, table.entityDataHash),
}));

// Type exports
export type AIAnalysisCache = typeof aiAnalysisCache.$inferSelect;
export type NewAIAnalysisCache = typeof aiAnalysisCache.$inferInsert;
