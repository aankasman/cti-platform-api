/**
 * STIX 2.1 Domain Object tables — Phase 2 item #1.
 *
 * Migration: drizzle/0046_stix_entity_tables.sql
 *
 * Covers the three SDO types the importer was already mapping to but
 * silently dropping for lack of a backing table:
 *   - campaigns       ← STIX `campaign`
 *   - coursesOfAction ← STIX `course-of-action`
 *   - infrastructure  ← STIX `infrastructure`
 *
 * intrusion-set keeps aliasing threat_actors, attack-pattern keeps
 * aliasing techniques, tool stays in the MITRE schema. note + opinion
 * are commentary, not entities; the importer's skip-and-count path
 * is the correct behaviour for those.
 */
import { pgTable, uuid, varchar, text, jsonb, timestamp, index } from 'drizzle-orm/pg-core';

export const campaigns = pgTable('campaigns', {
    id: uuid('id').primaryKey().defaultRandom(),
    stixId: varchar('stix_id', { length: 255 }).notNull().unique(),
    name: varchar('name', { length: 500 }).notNull(),
    description: text('description'),
    aliases: jsonb('aliases').$type<string[]>().notNull().default([]),
    firstSeen: timestamp('first_seen', { withTimezone: true }),
    lastSeen: timestamp('last_seen', { withTimezone: true }),
    objective: text('objective'),
    externalReferences: jsonb('external_references').$type<Record<string, unknown>[]>().notNull().default([]),
    labels: jsonb('labels').$type<string[]>().notNull().default([]),
    stixCreated: timestamp('stix_created', { withTimezone: true }),
    stixModified: timestamp('stix_modified', { withTimezone: true }),
    syncedAt: timestamp('synced_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
    nameIdx: index('campaigns_name_idx').on(table.name),
    stixIdIdx: index('campaigns_stix_id_idx').on(table.stixId),
}));

export const coursesOfAction = pgTable('courses_of_action', {
    id: uuid('id').primaryKey().defaultRandom(),
    stixId: varchar('stix_id', { length: 255 }).notNull().unique(),
    name: varchar('name', { length: 500 }).notNull(),
    description: text('description'),
    actionType: varchar('action_type', { length: 100 }),
    actionDescription: text('action_description'),
    externalReferences: jsonb('external_references').$type<Record<string, unknown>[]>().notNull().default([]),
    labels: jsonb('labels').$type<string[]>().notNull().default([]),
    stixCreated: timestamp('stix_created', { withTimezone: true }),
    stixModified: timestamp('stix_modified', { withTimezone: true }),
    syncedAt: timestamp('synced_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
    nameIdx: index('courses_of_action_name_idx').on(table.name),
    stixIdIdx: index('courses_of_action_stix_id_idx').on(table.stixId),
}));

export const infrastructure = pgTable('infrastructure', {
    id: uuid('id').primaryKey().defaultRandom(),
    stixId: varchar('stix_id', { length: 255 }).notNull().unique(),
    name: varchar('name', { length: 500 }).notNull(),
    description: text('description'),
    infrastructureTypes: jsonb('infrastructure_types').$type<string[]>().notNull().default([]),
    aliases: jsonb('aliases').$type<string[]>().notNull().default([]),
    killChainPhases: jsonb('kill_chain_phases').$type<Record<string, unknown>[]>().notNull().default([]),
    firstSeen: timestamp('first_seen', { withTimezone: true }),
    lastSeen: timestamp('last_seen', { withTimezone: true }),
    externalReferences: jsonb('external_references').$type<Record<string, unknown>[]>().notNull().default([]),
    labels: jsonb('labels').$type<string[]>().notNull().default([]),
    stixCreated: timestamp('stix_created', { withTimezone: true }),
    stixModified: timestamp('stix_modified', { withTimezone: true }),
    syncedAt: timestamp('synced_at', { withTimezone: true }),
    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
    nameIdx: index('infrastructure_name_idx').on(table.name),
    stixIdIdx: index('infrastructure_stix_id_idx').on(table.stixId),
}));
