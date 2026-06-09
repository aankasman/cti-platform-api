/**
 * Phase 5 #4 — Dark-web monitoring via Ahmia (indexed search only).
 *
 * Migration: drizzle/0054_dark_web_monitoring.sql
 */
import {
    pgTable, uuid, varchar, text, integer, boolean, timestamp,
    index, unique,
} from 'drizzle-orm/pg-core';

export type DarkWebSource = 'ahmia';
export type DarkWebMentionStatus = 'new' | 'triaging' | 'escalated' | 'benign' | 'blocked';

export const darkWebWatchterms = pgTable('dark_web_watchterms', {
    id: uuid('id').primaryKey().defaultRandom(),
    term: varchar('term', { length: 255 }).notNull().unique(),
    kind: varchar('kind', { length: 50 }),
    owner: varchar('owner', { length: 255 }),
    enabled: boolean('enabled').notNull().default(true),
    lastSearchedAt: timestamp('last_searched_at', { withTimezone: true }),
    createdBy: text('created_by'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
    enabledIdx: index('dark_web_watchterms_enabled_idx').on(table.enabled),
}));

export const darkWebMentions = pgTable('dark_web_mentions', {
    id: uuid('id').primaryKey().defaultRandom(),
    watchtermId: uuid('watchterm_id').notNull()
        .references(() => darkWebWatchterms.id, { onDelete: 'cascade' }),
    source: varchar('source', { length: 50 }).notNull().default('ahmia').$type<DarkWebSource>(),
    title: text('title').notNull(),
    onionUrl: text('onion_url').notNull(),
    snippet: text('snippet'),
    score: integer('score').notNull().default(50),
    status: varchar('status', { length: 20 }).notNull().default('new').$type<DarkWebMentionStatus>(),
    firstSeenAt: timestamp('first_seen_at', { withTimezone: true }).notNull().defaultNow(),
    lastSeenAt: timestamp('last_seen_at', { withTimezone: true }).notNull().defaultNow(),
    notes: text('notes'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
    watchtermIdx: index('dark_web_mentions_watchterm_idx').on(table.watchtermId),
    statusIdx: index('dark_web_mentions_status_idx').on(table.status),
    lastSeenIdx: index('dark_web_mentions_last_seen_idx').on(table.lastSeenAt),
    scoreIdx: index('dark_web_mentions_score_idx').on(table.score),
    uniqueMention: unique('dark_web_mentions_unique')
        .on(table.watchtermId, table.source, table.onionUrl),
}));

export type DarkWebWatchterm = typeof darkWebWatchterms.$inferSelect;
export type NewDarkWebWatchterm = typeof darkWebWatchterms.$inferInsert;
export type DarkWebMention = typeof darkWebMentions.$inferSelect;
export type NewDarkWebMention = typeof darkWebMentions.$inferInsert;
