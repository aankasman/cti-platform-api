/**
 * Phase 5 #1 — Brand / typo-squat monitoring.
 *
 * Migration: drizzle/0051_brand_monitoring.sql
 *
 * Operator pins apex domains for sweep; the worker generates dnstwist-
 * style permutations, DNS-resolves each, and records anything that
 * resolves as a brand_alerts row.
 */
import {
    pgTable, uuid, varchar, text, integer, boolean, timestamp,
    index, unique,
} from 'drizzle-orm/pg-core';

export type BrandAlertDnsState = 'active' | 'mx_only' | 'nx' | 'error';
export type BrandAlertStatus = 'new' | 'triaging' | 'escalated' | 'benign' | 'blocked';
export type BrandAlgorithm =
    | 'bitsquat' | 'homoglyph' | 'insertion' | 'omission'
    | 'substitution' | 'transposition' | 'vowel-swap' | 'hyphenation' | 'subdomain';

export const monitoredDomains = pgTable('monitored_domains', {
    id: uuid('id').primaryKey().defaultRandom(),
    apexDomain: varchar('apex_domain', { length: 255 }).notNull().unique(),
    label: varchar('label', { length: 255 }),
    owner: varchar('owner', { length: 255 }),
    enabled: boolean('enabled').notNull().default(true),
    lastSweptAt: timestamp('last_swept_at', { withTimezone: true }),
    createdBy: text('created_by'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
    enabledIdx: index('monitored_domains_enabled_idx').on(table.enabled),
}));

export const brandAlerts = pgTable('brand_alerts', {
    id: uuid('id').primaryKey().defaultRandom(),
    monitoredDomainId: uuid('monitored_domain_id').notNull()
        .references(() => monitoredDomains.id, { onDelete: 'cascade' }),
    permutation: varchar('permutation', { length: 255 }).notNull(),
    algorithm: varchar('algorithm', { length: 50 }).notNull().$type<BrandAlgorithm>(),
    dnsState: varchar('dns_state', { length: 20 }).notNull().$type<BrandAlertDnsState>(),
    ipAddresses: text('ip_addresses'),
    score: integer('score').notNull().default(0),
    status: varchar('status', { length: 20 }).notNull().default('new').$type<BrandAlertStatus>(),
    firstSeenAt: timestamp('first_seen_at', { withTimezone: true }).notNull().defaultNow(),
    lastCheckedAt: timestamp('last_checked_at', { withTimezone: true }).notNull().defaultNow(),
    notes: text('notes'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
    monitoredIdx: index('brand_alerts_monitored_idx').on(table.monitoredDomainId),
    statusIdx: index('brand_alerts_status_idx').on(table.status),
    dnsStateIdx: index('brand_alerts_dns_state_idx').on(table.dnsState),
    scoreIdx: index('brand_alerts_score_idx').on(table.score),
    uniquePerApex: unique('brand_alerts_unique_per_apex')
        .on(table.monitoredDomainId, table.permutation),
}));

export type MonitoredDomain = typeof monitoredDomains.$inferSelect;
export type NewMonitoredDomain = typeof monitoredDomains.$inferInsert;
export type BrandAlert = typeof brandAlerts.$inferSelect;
export type NewBrandAlert = typeof brandAlerts.$inferInsert;
