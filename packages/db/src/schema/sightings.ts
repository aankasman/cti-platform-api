/**
 * Database Schema - Sightings
 *
 * Tracks observations of IOCs in the wild.
 * Sighting types: 'sighting' (true positive), 'false-positive', 'expiration'
 */

import { pgTable, uuid, text, integer, timestamp, index } from 'drizzle-orm/pg-core';
import { iocs } from './feeds';
import { users } from './users';

export const sightings = pgTable('sightings', {
    id: uuid('id').primaryKey().defaultRandom(),
    iocId: uuid('ioc_id').notNull().references(() => iocs.id, { onDelete: 'cascade' }),
    type: text('type').notNull().default('sighting'), // sighting, false-positive, expiration
    source: text('source').notNull(), // sensor name, honeypot, SIEM, analyst
    description: text('description'),
    confidence: integer('confidence').default(50), // 0-100
    count: integer('count').default(1), // number of observations
    observedAt: timestamp('observed_at', { withTimezone: true }).defaultNow().notNull(),
    createdBy: uuid('created_by').references(() => users.id),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
    iocIdIdx: index('sightings_ioc_id_idx').on(table.iocId),
    typeIdx: index('sightings_type_idx').on(table.type),
    observedAtIdx: index('sightings_observed_at_idx').on(table.observedAt),
    sourceIdx: index('sightings_source_idx').on(table.source),
}));

// Type exports
export type Sighting = typeof sightings.$inferSelect;
export type NewSighting = typeof sightings.$inferInsert;
