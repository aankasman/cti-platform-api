/**
 * Phase 3 #5 — Hypothesis tracking.
 *
 * Migration: drizzle/0050_hypotheses.sql
 *
 * An analyst-authored claim + the evidence accumulating for or against
 * it. The LLM grades the current evidence list into a confidence score
 * so the claim's strength is visible at a glance and changes as new
 * sightings/IOCs/relationships come in.
 */
import { pgTable, uuid, varchar, text, integer, timestamp, index } from 'drizzle-orm/pg-core';

export type HypothesisStatus = 'active' | 'confirmed' | 'refuted';
export type HypothesisSubjectType =
    | 'threat_actor' | 'malware' | 'campaign' | 'infrastructure' | 'ioc' | 'cve';

export type EvidenceKind = 'supports' | 'refutes';
export type EvidenceType =
    | 'ioc' | 'relationship' | 'sighting' | 'actor' | 'malware'
    | 'campaign' | 'report' | 'freeform';

export const hypotheses = pgTable('hypotheses', {
    id: uuid('id').primaryKey().defaultRandom(),
    title: varchar('title', { length: 500 }).notNull(),
    claim: text('claim').notNull(),
    status: varchar('status', { length: 20 }).notNull().default('active').$type<HypothesisStatus>(),
    confidenceScore: integer('confidence_score').notNull().default(50),
    subjectType: varchar('subject_type', { length: 50 }).$type<HypothesisSubjectType>(),
    subjectId: uuid('subject_id'),

    lastGradedAt: timestamp('last_graded_at', { withTimezone: true }),
    lastGradingReason: text('last_grading_reason'),
    lastGradingProvider: varchar('last_grading_provider', { length: 50 }),

    createdBy: text('created_by'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
    statusIdx: index('hypotheses_status_idx').on(table.status),
    subjectIdx: index('hypotheses_subject_idx').on(table.subjectType, table.subjectId),
    createdAtIdx: index('hypotheses_created_at_idx').on(table.createdAt),
}));

export const hypothesisEvidence = pgTable('hypothesis_evidence', {
    id: uuid('id').primaryKey().defaultRandom(),
    hypothesisId: uuid('hypothesis_id').notNull().references(() => hypotheses.id, { onDelete: 'cascade' }),
    evidenceType: varchar('evidence_type', { length: 50 }).notNull().$type<EvidenceType>(),
    entityId: text('entity_id'),
    kind: varchar('kind', { length: 20 }).notNull().$type<EvidenceKind>(),
    weight: integer('weight').notNull().default(50),
    note: text('note'),
    createdBy: text('created_by'),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
    hypothesisIdx: index('hypothesis_evidence_hypothesis_idx').on(table.hypothesisId),
    kindIdx: index('hypothesis_evidence_kind_idx').on(table.kind),
}));

export type Hypothesis = typeof hypotheses.$inferSelect;
export type NewHypothesis = typeof hypotheses.$inferInsert;
export type HypothesisEvidence = typeof hypothesisEvidence.$inferSelect;
export type NewHypothesisEvidence = typeof hypothesisEvidence.$inferInsert;
