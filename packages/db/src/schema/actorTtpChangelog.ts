/**
 * Phase 5 #2 — Threat-actor TTP changelog.
 *
 * Migration: drizzle/0052_actor_ttp_changelog.sql
 *
 * `actor_ttp_state` holds the current (actor, technique) tuples the
 * differ knows about; `actor_ttp_changes` is the append-only log of
 * additions and removals.
 */
import {
    pgTable, uuid, varchar, text, timestamp, index, unique,
} from 'drizzle-orm/pg-core';

export type TtpChangeType = 'added' | 'removed';

export const actorTtpState = pgTable('actor_ttp_state', {
    id: uuid('id').primaryKey().defaultRandom(),
    actorId: varchar('actor_id', { length: 128 }).notNull(),
    techniqueId: varchar('technique_id', { length: 128 }).notNull(),
    observedAt: timestamp('observed_at', { withTimezone: true }).notNull().defaultNow(),
    confirmedAt: timestamp('confirmed_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
    actorIdx: index('actor_ttp_state_actor_idx').on(table.actorId),
    techniqueIdx: index('actor_ttp_state_technique_idx').on(table.techniqueId),
    uniquePair: unique('actor_ttp_state_unique').on(table.actorId, table.techniqueId),
}));

export const actorTtpChanges = pgTable('actor_ttp_changes', {
    id: uuid('id').primaryKey().defaultRandom(),
    actorId: varchar('actor_id', { length: 128 }).notNull(),
    techniqueId: varchar('technique_id', { length: 128 }).notNull(),
    changeType: varchar('change_type', { length: 20 }).notNull().$type<TtpChangeType>(),
    detectedAt: timestamp('detected_at', { withTimezone: true }).notNull().defaultNow(),
    note: text('note'),
}, (table) => ({
    actorIdx: index('actor_ttp_changes_actor_idx').on(table.actorId),
    techniqueIdx: index('actor_ttp_changes_technique_idx').on(table.techniqueId),
    detectedAtIdx: index('actor_ttp_changes_detected_at_idx').on(table.detectedAt),
    typeIdx: index('actor_ttp_changes_type_idx').on(table.changeType),
}));

export type ActorTtpState = typeof actorTtpState.$inferSelect;
export type NewActorTtpState = typeof actorTtpState.$inferInsert;
export type ActorTtpChange = typeof actorTtpChanges.$inferSelect;
export type NewActorTtpChange = typeof actorTtpChanges.$inferInsert;
