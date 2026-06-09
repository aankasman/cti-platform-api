/**
 * Phase 3 #1 follow-on — persisted report ingestion drafts.
 *
 * Migration: drizzle/0049_extracted_reports.sql
 *
 * Operators submit a report (text/url/pdf), the extractor produces a
 * draft, and that draft is persisted here for review. The COMMIT step
 * is what writes selected IOCs / entities into the canonical tables;
 * this row tracks that lifecycle.
 */
import { pgTable, uuid, varchar, text, integer, jsonb, timestamp, index } from 'drizzle-orm/pg-core';

export type ReportSourceKind = 'text' | 'url' | 'pdf';
export type ReportStatus = 'draft' | 'committed' | 'dismissed';

export const extractedReports = pgTable('extracted_reports', {
    id: uuid('id').primaryKey().defaultRandom(),
    source: text('source'),
    sourceKind: varchar('source_kind', { length: 20 }).notNull().$type<ReportSourceKind>(),
    sourceMeta: jsonb('source_meta').notNull().default({}).$type<Record<string, unknown>>(),
    extractedAt: timestamp('extracted_at', { withTimezone: true }).notNull().defaultNow(),
    textLength: integer('text_length').notNull(),
    iocs: jsonb('iocs').notNull().default({}).$type<Record<string, unknown>>(),
    entities: jsonb('entities').notNull().default({}).$type<Record<string, unknown>>(),
    llmProvider: varchar('llm_provider', { length: 50 }),
    llmError: text('llm_error'),
    status: varchar('status', { length: 20 }).notNull().default('draft').$type<ReportStatus>(),
    committedAt: timestamp('committed_at', { withTimezone: true }),
    committedBy: text('committed_by'),
    commitSummary: jsonb('commit_summary').$type<Record<string, unknown>>(),
    createdBy: text('created_by'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
    statusIdx: index('extracted_reports_status_idx').on(table.status),
    createdAtIdx: index('extracted_reports_created_at_idx').on(table.createdAt),
    createdByIdx: index('extracted_reports_created_by_idx').on(table.createdBy),
}));

export type ExtractedReport = typeof extractedReports.$inferSelect;
export type NewExtractedReport = typeof extractedReports.$inferInsert;
