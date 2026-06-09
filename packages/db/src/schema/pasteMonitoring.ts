/**
 * Phase 5 #5 — Paste-site monitoring (GitHub Gist firehose).
 *
 * Migration: drizzle/0055_paste_monitoring.sql
 */
import {
    pgTable, uuid, varchar, text, integer, boolean, timestamp,
    index, unique,
} from 'drizzle-orm/pg-core';

export type PasteSource = 'github_gist';
export type PasteMentionStatus = 'new' | 'triaging' | 'escalated' | 'benign' | 'blocked';

export const pasteWatchterms = pgTable('paste_watchterms', {
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
    enabledIdx: index('paste_watchterms_enabled_idx').on(table.enabled),
}));

export const pasteMentions = pgTable('paste_mentions', {
    id: uuid('id').primaryKey().defaultRandom(),
    watchtermId: uuid('watchterm_id').notNull()
        .references(() => pasteWatchterms.id, { onDelete: 'cascade' }),
    source: varchar('source', { length: 50 }).notNull().default('github_gist').$type<PasteSource>(),
    author: varchar('author', { length: 255 }),
    filename: varchar('filename', { length: 255 }),
    title: text('title'),
    externalUrl: text('external_url').notNull(),
    externalId: varchar('external_id', { length: 255 }).notNull(),
    snippet: text('snippet'),
    score: integer('score').notNull().default(50),
    status: varchar('status', { length: 20 }).notNull().default('new').$type<PasteMentionStatus>(),
    firstSeenAt: timestamp('first_seen_at', { withTimezone: true }).notNull().defaultNow(),
    lastSeenAt: timestamp('last_seen_at', { withTimezone: true }).notNull().defaultNow(),
    notes: text('notes'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
    watchtermIdx: index('paste_mentions_watchterm_idx').on(table.watchtermId),
    statusIdx: index('paste_mentions_status_idx').on(table.status),
    lastSeenIdx: index('paste_mentions_last_seen_idx').on(table.lastSeenAt),
    scoreIdx: index('paste_mentions_score_idx').on(table.score),
    uniqueMention: unique('paste_mentions_unique')
        .on(table.watchtermId, table.source, table.externalId),
}));

export type PasteWatchterm = typeof pasteWatchterms.$inferSelect;
export type NewPasteWatchterm = typeof pasteWatchterms.$inferInsert;
export type PasteMention = typeof pasteMentions.$inferSelect;
export type NewPasteMention = typeof pasteMentions.$inferInsert;
