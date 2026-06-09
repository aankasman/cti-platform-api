/**
 * Phase 4 #6 — External ticket links for cases.
 *
 * Migration: drizzle/0048_ticket_links.sql
 *
 * One row per (case, vendor, vendor-issue) join. A case can carry
 * multiple external tickets across vendors. Sync status + last error
 * are persisted so the dashboard can render a freshness indicator.
 */
import { pgTable, uuid, varchar, text, jsonb, timestamp, index, uniqueIndex } from 'drizzle-orm/pg-core';

export type TicketVendor = 'github' | 'jira';
export type TicketStatus = 'open' | 'closed' | 'unknown';

export const ticketLinks = pgTable('ticket_links', {
    id: uuid('id').primaryKey().defaultRandom(),
    /** FK to cases.id (text — the existing cases bootstrap uses text PKs). */
    caseId: text('case_id').notNull(),
    vendor: varchar('vendor', { length: 50 }).notNull().$type<TicketVendor>(),
    /** github: `owner/repo`. jira: project key. */
    vendorRepo: varchar('vendor_repo', { length: 255 }).notNull(),
    /** github: issue number. jira: issue key like PROJ-123. */
    vendorIssueId: varchar('vendor_issue_id', { length: 255 }).notNull(),
    vendorIssueUrl: text('vendor_issue_url').notNull(),
    title: text('title').notNull(),
    status: varchar('status', { length: 50 }).notNull().default('open').$type<TicketStatus>(),
    labels: jsonb('labels').$type<string[]>().notNull().default([]),
    lastSyncedAt: timestamp('last_synced_at', { withTimezone: true }),
    lastSyncError: text('last_sync_error'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
    caseIdx: index('ticket_links_case_idx').on(table.caseId),
    vendorIdx: index('ticket_links_vendor_idx').on(table.vendor),
    vendorUnique: uniqueIndex('ticket_links_vendor_unique')
        .on(table.vendor, table.vendorRepo, table.vendorIssueId),
}));

export type TicketLink = typeof ticketLinks.$inferSelect;
export type NewTicketLink = typeof ticketLinks.$inferInsert;
