/**
 * MITRE FiGHT Database Schema
 *
 * Tables for storing FiGHT (5G Hierarchy of Threats) framework data.
 * Separate from ATT&CK tables to maintain distinct data domains.
 *
 * Data source: https://github.com/mitre/FiGHT (fight.yaml)
 */

import { pgTable, uuid, varchar, text, timestamp, jsonb, integer } from 'drizzle-orm/pg-core';

// ============================================================================
// FiGHT Tactics (shares ATT&CK TA IDs + unique TA5001 Fraud)
// ============================================================================

export const fightTactics = pgTable('fight_tactics', {
    id: uuid('id').defaultRandom().primaryKey(),
    mitreId: varchar('mitre_id', { length: 20 }).notNull().unique(),   // TA0001 or TA5001
    name: varchar('name', { length: 256 }).notNull(),                    // Fraud
    description: text('description'),
    shortName: varchar('short_name', { length: 64 }),                    // fraud
    url: varchar('url', { length: 512 }),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

// ============================================================================
// FiGHT Techniques (FGT-prefixed, 5G-specific)
// ============================================================================

export const fightTechniques = pgTable('fight_techniques', {
    id: uuid('id').defaultRandom().primaryKey(),
    fightId: varchar('fight_id', { length: 64 }).notNull().unique(),   // FGT1014, FGT5004
    name: varchar('name', { length: 256 }).notNull(),                    // Rootkit
    description: text('description'),
    bluf: text('bluf'),                                                    // Bottom Line Up Front
    status: varchar('status', { length: 128 }),                             // theoretical, PoC, observed
    architectureSegment: varchar('architecture_segment', { length: 256 }), // RAN, Core, UE, OA&M
    typecode: varchar('typecode', { length: 64 }),                         // fight_technique
    tacticIds: jsonb('tactic_ids').$type<string[]>(),                    // ["TA0005", "TA0004"]
    platforms: jsonb('platforms').$type<string[]>(),                      // ["5G RAN", "5G Core"]
    preconditions: jsonb('preconditions').$type<Array<{ name: string; description: string }>>(),
    postconditions: jsonb('postconditions').$type<Array<{ name: string; description: string }>>(),
    criticalAssets: jsonb('critical_assets').$type<Array<{ name: string; description: string }>>(),
    detections: jsonb('detections').$type<Array<{ name: string; description: string }>>(),
    procedureExamples: jsonb('procedure_examples').$type<Array<{ name: string; description: string }>>(),
    references: jsonb('references').$type<Array<{ url: string; description: string }>>(),
    url: varchar('url', { length: 512 }),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

// ============================================================================
// FiGHT Mitigations
// ============================================================================

export const fightMitigations = pgTable('fight_mitigations', {
    id: uuid('id').defaultRandom().primaryKey(),
    fightId: varchar('fight_id', { length: 64 }).notNull().unique(),   // FGM5001
    name: varchar('name', { length: 256 }).notNull(),
    description: text('description'),
    techniqueIds: jsonb('technique_ids').$type<string[]>(),              // FGT IDs this mitigates
    url: varchar('url', { length: 512 }),
    createdAt: timestamp('created_at').defaultNow().notNull(),
    updatedAt: timestamp('updated_at').defaultNow().notNull(),
});

// ============================================================================
// FiGHT Group → Technique mapping (separate from ATT&CK relationships)
// ============================================================================

export const fightGroupTechniques = pgTable('fight_group_techniques', {
    id: uuid('id').defaultRandom().primaryKey(),
    groupId: varchar('group_id', { length: 128 }).notNull(),              // threat_actors.id or stix_id
    groupName: varchar('group_name', { length: 256 }).notNull(),
    fightTechniqueId: varchar('fight_technique_id', { length: 64 }).notNull(), // FGT1059
    techniqueName: varchar('technique_name', { length: 256 }),
    description: text('description'),
    confidence: integer('confidence'),
    createdAt: timestamp('created_at').defaultNow().notNull(),
});
