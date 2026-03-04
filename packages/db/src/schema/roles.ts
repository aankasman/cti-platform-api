/**
 * Database Schema - Roles & Permissions
 * 
 * Stores role definitions and permission module definitions in PostgreSQL
 * instead of hardcoded constants. Supports runtime CRUD via admin API.
 */

import { pgTable, uuid, varchar, text, timestamp, boolean, jsonb } from 'drizzle-orm/pg-core';

// ============================================================================
// Roles Table
// ============================================================================

export const roles = pgTable('roles', {
    id: varchar('id', { length: 50 }).primaryKey(),        // e.g. 'admin', 'analyst'
    name: varchar('name', { length: 255 }).notNull(),       // Human-readable: 'Administrator'
    description: text('description').notNull().default(''),
    defaultPermissions: jsonb('default_permissions').$type<string[]>().default([]),
    isSystem: boolean('is_system').default(false).notNull(), // Protect built-in roles from deletion
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
});

// ============================================================================
// Permission Modules Table
// ============================================================================

export interface PermissionDef {
    id: string;
    name: string;
    description: string;
}

export const permissionModules = pgTable('permission_modules', {
    id: varchar('id', { length: 50 }).primaryKey(),         // e.g. 'api-keys', 'threat-intel'
    name: varchar('name', { length: 255 }).notNull(),
    icon: varchar('icon', { length: 50 }).notNull().default('settings'),
    permissions: jsonb('permissions').$type<PermissionDef[]>().default([]),
    isSystem: boolean('is_system').default(false).notNull(),
    createdAt: timestamp('created_at', { withTimezone: true }).defaultNow().notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).defaultNow().notNull(),
});

// Type exports
export type Role = typeof roles.$inferSelect;
export type NewRole = typeof roles.$inferInsert;
export type PermissionModule = typeof permissionModules.$inferSelect;
export type NewPermissionModule = typeof permissionModules.$inferInsert;
