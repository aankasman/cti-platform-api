/**
 * Database Schema - Warninglists
 *
 * Curated lists of known benign indicators for false-positive mitigation.
 * Match types: cidr, hostname, string, regex
 */

import { pgTable, uuid, text, boolean, timestamp, index } from 'drizzle-orm/pg-core';

// ============================================================================
// Warninglists (list metadata)
// ============================================================================

export const warninglists = pgTable('warninglists', {
    id: uuid('id').primaryKey().defaultRandom(),
    name: text('name').notNull().unique(),
    description: text('description'),
    type: text('type').notNull(), // cidr, hostname, string, regex
    category: text('category').notNull().default('false_positive'), // false_positive, known_benign, exclusion
    enabled: boolean('enabled').notNull().default(true),
    source: text('source'), // where this list came from
    version: text('version'),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
    enabledIdx: index('warninglists_enabled_idx').on(table.enabled),
    categoryIdx: index('warninglists_category_idx').on(table.category),
}));

// ============================================================================
// Warninglist Entries (individual items in a list)
// ============================================================================

export const warninglistEntries = pgTable('warninglist_entries', {
    id: uuid('id').primaryKey().defaultRandom(),
    warninglistId: uuid('warninglist_id').notNull().references(() => warninglists.id, { onDelete: 'cascade' }),
    value: text('value').notNull(),
}, (table) => ({
    warninglistIdIdx: index('warninglist_entries_wl_id_idx').on(table.warninglistId),
    valueIdx: index('warninglist_entries_value_idx').on(table.value),
}));

// Type exports
export type Warninglist = typeof warninglists.$inferSelect;
export type NewWarninglist = typeof warninglists.$inferInsert;
export type WarninglistEntry = typeof warninglistEntries.$inferSelect;
export type NewWarninglistEntry = typeof warninglistEntries.$inferInsert;
