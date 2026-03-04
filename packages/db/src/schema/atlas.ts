/**
 * MITRE ATLAS Database Schema
 *
 * Tables for storing ATLAS (Adversarial Threat Landscape for AI Systems) data.
 * Separate from ATT&CK / FiGHT tables to maintain distinct data domains.
 *
 * Data source: https://github.com/mitre-atlas/atlas-data (ATLAS.yaml)
 */

import { pgTable, uuid, varchar, text, timestamp, jsonb, integer } from 'drizzle-orm/pg-core';

// ============================================================================
// ATLAS Tactics (AML.TA prefixed)
// ============================================================================

export const atlasTactics = pgTable('atlas_tactics', {
    id: uuid('id').defaultRandom().primaryKey(),
    atlasId: varchar('atlas_id', { length: 20 }).notNull().unique(),     // AML.TA0002
    name: varchar('name', { length: 256 }).notNull(),                      // Reconnaissance
    description: text('description'),
    attackReferenceId: varchar('attack_reference_id', { length: 20 }),    // TA0043 (ATT&CK cross-ref)
    attackReferenceUrl: varchar('attack_reference_url', { length: 512 }),
    url: varchar('url', { length: 512 }),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

// ============================================================================
// ATLAS Techniques (AML.T prefixed, AI/ML-specific)
// ============================================================================

export const atlasTechniques = pgTable('atlas_techniques', {
    id: uuid('id').defaultRandom().primaryKey(),
    atlasId: varchar('atlas_id', { length: 64 }).notNull().unique(),     // AML.T0000, AML.T0000.000
    name: varchar('name', { length: 256 }).notNull(),                      // Search Open Technical Databases
    description: text('description'),
    maturity: varchar('maturity', { length: 64 }),                          // demonstrated, feasible, theoretical
    subtechniqueOf: varchar('subtechnique_of', { length: 64 }),           // AML.T0000 (parent technique)
    tacticIds: jsonb('tactic_ids').$type<string[]>(),                      // ["AML.TA0002"]
    attackReferenceId: varchar('attack_reference_id', { length: 20 }),    // T1596 (ATT&CK cross-ref)
    attackReferenceUrl: varchar('attack_reference_url', { length: 512 }),
    url: varchar('url', { length: 512 }),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

// ============================================================================
// ATLAS Mitigations (AML.M prefixed)
// ============================================================================

export const atlasMitigations = pgTable('atlas_mitigations', {
    id: uuid('id').defaultRandom().primaryKey(),
    atlasId: varchar('atlas_id', { length: 64 }).notNull().unique(),     // AML.M0000
    name: varchar('name', { length: 256 }).notNull(),
    description: text('description'),
    techniqueIds: jsonb('technique_ids').$type<string[]>(),                // AML.T IDs this mitigates
    mlLifecycle: jsonb('ml_lifecycle').$type<string[]>(),                   // ["ML Model Engineering"]
    category: jsonb('category').$type<string[]>(),                          // ["Technical - ML"]
    url: varchar('url', { length: 512 }),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

// ============================================================================
// ATLAS Case Studies (AML.CS prefixed — real-world incidents)
// ============================================================================

export const atlasCaseStudies = pgTable('atlas_case_studies', {
    id: uuid('id').defaultRandom().primaryKey(),
    atlasId: varchar('atlas_id', { length: 64 }).notNull().unique(),     // AML.CS0000
    name: varchar('name', { length: 512 }).notNull(),
    summary: text('summary'),
    incidentDate: varchar('incident_date', { length: 64 }),                // 2020-01-01
    reporter: varchar('reporter', { length: 256 }),
    target: varchar('target', { length: 256 }),
    actor: varchar('actor', { length: 256 }),
    techniqueIds: jsonb('technique_ids').$type<string[]>(),                // AML.T IDs used in the case study
    procedureSteps: jsonb('procedure_steps').$type<Array<{ tactic: string; technique: string; description: string }>>(),
    references: jsonb('references').$type<Array<{ url: string; title?: string }>>(),
    url: varchar('url', { length: 512 }),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
});
