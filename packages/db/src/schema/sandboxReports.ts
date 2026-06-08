/**
 * Phase 4 #5 — Sandbox submissions + reports.
 *
 * Migration: drizzle/0047_sandbox_reports.sql
 *
 * One row per (vendor, submission). Tracks vendor task id so we can
 * poll later, links back to the originating IOC when there is one,
 * and stashes the full vendor JSON for the dashboard to render.
 */
import { pgTable, uuid, varchar, text, integer, jsonb, timestamp, index, uniqueIndex } from 'drizzle-orm/pg-core';
import { iocs } from './feeds';

export type SandboxVendor = 'anyrun' | 'joesandbox' | 'hybridanalysis';
export type SandboxStatus = 'queued' | 'running' | 'completed' | 'failed' | 'timeout';
export type SandboxVerdict = 'malicious' | 'suspicious' | 'benign' | 'unknown';
export type SandboxSubmissionType = 'url' | 'hash' | 'file' | 'ioc';

export const sandboxReports = pgTable('sandbox_reports', {
    id: uuid('id').primaryKey().defaultRandom(),
    vendor: varchar('vendor', { length: 50 }).notNull().$type<SandboxVendor>(),
    /** Vendor's own task / analysis id — used for polling. */
    vendorTaskId: varchar('vendor_task_id', { length: 255 }),
    /** Originating IOC, if the submission came from a known indicator. */
    submittedIocId: uuid('submitted_ioc_id').references(() => iocs.id, { onDelete: 'set null' }),
    submittedValue: text('submitted_value').notNull(),
    submittedType: varchar('submitted_type', { length: 50 }).notNull().$type<SandboxSubmissionType>(),
    status: varchar('status', { length: 50 }).notNull().default('queued').$type<SandboxStatus>(),
    /** NULL until completion. */
    verdict: varchar('verdict', { length: 50 }).$type<SandboxVerdict>(),
    /** Normalised 0-100 score. NULL until completion. */
    score: integer('score'),
    /** Vendor's UI link to the full report. */
    reportUrl: text('report_url'),
    /** Full raw report payload from the vendor. */
    reportJson: jsonb('report_json').$type<Record<string, unknown>>(),
    submittedAt: timestamp('submitted_at', { withTimezone: true }).notNull().defaultNow(),
    completedAt: timestamp('completed_at', { withTimezone: true }),
    error: text('error'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
    vendorIdx: index('sandbox_reports_vendor_idx').on(table.vendor),
    iocIdx: index('sandbox_reports_ioc_idx').on(table.submittedIocId),
    statusIdx: index('sandbox_reports_status_idx').on(table.status),
    verdictIdx: index('sandbox_reports_verdict_idx').on(table.verdict),
    vendorTaskUnique: uniqueIndex('sandbox_reports_vendor_task_unique')
        .on(table.vendor, table.vendorTaskId),
}));

export type SandboxReport = typeof sandboxReports.$inferSelect;
export type NewSandboxReport = typeof sandboxReports.$inferInsert;
