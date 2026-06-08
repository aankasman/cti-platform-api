/**
 * Database Schema - Playbooks
 *
 * Event-driven automation rules: "when EVENT occurs, if CONDITIONS match, run ACTIONS."
 * Integrates with the webhook event system for trigger evaluation.
 */

import { pgTable, uuid, text, boolean, jsonb, timestamp, index } from 'drizzle-orm/pg-core';
import { users } from './users';

// ============================================================================
// Playbooks (automation rule definitions)
// ============================================================================

export const playbooks = pgTable('playbooks', {
    id: uuid('id').primaryKey().defaultRandom(),
    name: text('name').notNull(),
    description: text('description'),
    triggerEvent: text('trigger_event').notNull(), // webhook event name: ioc.created, alert.critical, etc.
    conditions: jsonb('conditions').$type<Record<string, unknown>>().default({}), // filter conditions
    actions: jsonb('actions').$type<PlaybookAction[]>().notNull().default([]), // ordered actions
    enabled: boolean('enabled').notNull().default(true),
    createdBy: uuid('created_by').references(() => users.id),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
    triggerEventIdx: index('playbooks_trigger_event_idx').on(table.triggerEvent),
    enabledIdx: index('playbooks_enabled_idx').on(table.enabled),
}));

// ============================================================================
// Playbook Executions (execution history / audit trail)
// ============================================================================

export const playbookExecutions = pgTable('playbook_executions', {
    id: uuid('id').primaryKey().defaultRandom(),
    playbookId: uuid('playbook_id').notNull().references(() => playbooks.id, { onDelete: 'cascade' }),
    triggerData: jsonb('trigger_data').$type<Record<string, unknown>>().default({}),
    status: text('status').notNull().default('running'), // running, completed, failed
    results: jsonb('results').$type<PlaybookActionResult[]>().default([]),
    error: text('error'),
    startedAt: timestamp('started_at', { withTimezone: true }).defaultNow().notNull(),
    completedAt: timestamp('completed_at', { withTimezone: true }),
}, (table) => ({
    playbookIdIdx: index('playbook_executions_pb_id_idx').on(table.playbookId),
    statusIdx: index('playbook_executions_status_idx').on(table.status),
    startedAtIdx: index('playbook_executions_started_at_idx').on(table.startedAt),
}));

// ============================================================================
// Action Types
// ============================================================================

export interface PlaybookAction {
    type: 'enrich' | 'notify' | 'alert' | 'tag' | 'warninglist_check' | 'sandbox_trigger';
    config: Record<string, unknown>;
}

export interface PlaybookActionResult {
    action: string;
    success: boolean;
    result?: unknown;
    error?: string;
    executedAt: string;
}

// Type exports
export type Playbook = typeof playbooks.$inferSelect;
export type NewPlaybook = typeof playbooks.$inferInsert;
export type PlaybookExecution = typeof playbookExecutions.$inferSelect;
export type NewPlaybookExecution = typeof playbookExecutions.$inferInsert;
