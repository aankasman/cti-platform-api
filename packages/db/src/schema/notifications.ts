/**
 * Database Schema - In-App Notifications
 *
 * Persistent notification feed displayed in the dashboard header bell.
 * Created by playbook executions, feed syncs, system alerts, etc.
 */

import { pgTable, uuid, text, boolean, jsonb, timestamp, index } from 'drizzle-orm/pg-core';

export const notifications = pgTable('notifications', {
    id: uuid('id').primaryKey().defaultRandom(),
    type: text('type').notNull().default('info'),           // info | warning | error | success
    title: text('title').notNull(),
    message: text('message').notNull(),
    source: text('source').notNull().default('system'),     // playbook | feed | system | alert
    read: boolean('read').notNull().default(false),
    metadata: jsonb('metadata').$type<Record<string, unknown>>().default({}),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
}, (table) => ({
    readIdx: index('notifications_read_idx').on(table.read),
    createdAtIdx: index('notifications_created_at_idx').on(table.createdAt),
    sourceIdx: index('notifications_source_idx').on(table.source),
}));

// Type exports
export type Notification = typeof notifications.$inferSelect;
export type NewNotification = typeof notifications.$inferInsert;
