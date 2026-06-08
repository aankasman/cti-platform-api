/**
 * Remote TAXII 2.1 servers we push to.
 *
 * Migration: drizzle/0044_taxii_remote_targets.sql
 *
 * Each row describes one (api_root, collection_id) pair on a downstream
 * server. A push job grabs filtered objects from our DB, builds a STIX
 * bundle (via packages/core/src/stix.ts), and POSTs it to the target's
 * /collections/<id>/objects/ endpoint.
 */
import { pgTable, uuid, varchar, text, boolean, integer, timestamp, jsonb, index } from 'drizzle-orm/pg-core';

export const taxiiRemoteTargets = pgTable('taxii_remote_targets', {
    id: uuid('id').primaryKey().defaultRandom(),
    /** Human-readable label — also UNIQUE so operators can't double-add. */
    name: varchar('name', { length: 255 }).notNull(),
    /** TAXII discovery URL — `https://server/taxii2/` per spec §4.1. */
    discoveryUrl: text('discovery_url').notNull(),
    /** API root URL we POST against. */
    apiRoot: text('api_root').notNull(),
    /** Collection id within the api_root. */
    collectionId: varchar('collection_id', { length: 255 }).notNull(),
    /**
     * Either the id of a row in config_api_keys (where the operator
     * vaulted the bearer token) or NULL — in which case we fall back to
     * the TAXII_PUSH_API_KEY env var.
     */
    apiKeyRef: varchar('api_key_ref', { length: 255 }),
    enabled: boolean('enabled').notNull().default(true),

    // Push-history bookkeeping (last attempt only — finer-grained history
    // can live in feed_sync_runs if needed later).
    lastPushAt: timestamp('last_push_at', { withTimezone: true }),
    lastPushStatus: varchar('last_push_status', { length: 50 }),
    lastPushError: text('last_push_error'),
    lastPushObjects: integer('last_push_objects').notNull().default(0),

    /** Filter applied when building the bundle (iocType / iocSource / severity / defaultTlp). */
    pushFilter: jsonb('push_filter').$type<Record<string, unknown>>().notNull().default({}),

    createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
}, (table) => ({
    enabledIdx: index('taxii_remote_targets_enabled_idx').on(table.enabled),
}));
