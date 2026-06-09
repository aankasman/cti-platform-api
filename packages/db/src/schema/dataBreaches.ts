/**
 * Phase 5 #3 — HIBP breach catalog (free-tier sync only).
 *
 * Migration: drizzle/0053_data_breaches.sql
 */
import {
    pgTable, uuid, varchar, text, bigint, boolean, jsonb, timestamp, index,
} from 'drizzle-orm/pg-core';

export const dataBreaches = pgTable('data_breaches', {
    id: uuid('id').primaryKey().defaultRandom(),
    name: varchar('name', { length: 255 }).notNull().unique(),
    title: varchar('title', { length: 255 }).notNull(),
    domain: varchar('domain', { length: 255 }),
    breachDate: timestamp('breach_date', { withTimezone: true }),
    addedDate: timestamp('added_date', { withTimezone: true }),
    modifiedDate: timestamp('modified_date', { withTimezone: true }),
    pwnCount: bigint('pwn_count', { mode: 'number' }).notNull().default(0),
    description: text('description'),
    dataClasses: jsonb('data_classes').$type<string[]>().notNull().default([]),
    isVerified: boolean('is_verified').notNull().default(false),
    isFabricated: boolean('is_fabricated').notNull().default(false),
    isSensitive: boolean('is_sensitive').notNull().default(false),
    isRetired: boolean('is_retired').notNull().default(false),
    isSpamList: boolean('is_spam_list').notNull().default(false),
    logoPath: text('logo_path'),
    firstSyncedAt: timestamp('first_synced_at', { withTimezone: true }).notNull().defaultNow(),
    lastSyncedAt: timestamp('last_synced_at', { withTimezone: true }).notNull().defaultNow(),
    rawData: jsonb('raw_data'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
    addedDateIdx: index('data_breaches_added_date_idx').on(table.addedDate),
    modifiedDateIdx: index('data_breaches_modified_date_idx').on(table.modifiedDate),
    breachDateIdx: index('data_breaches_breach_date_idx').on(table.breachDate),
}));

export type DataBreach = typeof dataBreaches.$inferSelect;
export type NewDataBreach = typeof dataBreaches.$inferInsert;
