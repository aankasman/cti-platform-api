-- Footgun #14 · schema-vs-migration drift
--
-- Three pieces of schema that the TypeScript schema files and/or the API
-- routes assume exist, but which no prior migration (0000-0042) actually
-- creates. On a fresh deploy:
--
--   - OAuth login crashes with `column "avatar_url" does not exist` because
--     `apps/api/src/services/oauth.ts` writes the provider's avatar URL into
--     `users.avatar_url`, and `packages/db/src/schema/users.ts:20` declares
--     `avatarUrl: text('avatar_url')` — but no migration adds the column.
--
--   - MISP Galaxy generic-cluster ingest crashes with `relation
--     "galaxy_clusters" does not exist` — `packages/db/src/schema/threats.ts`
--     defines the table with all its indexes, but no migration creates it.
--
--   - Confidence-decay / alerts / reputation / landscape endpoints all read
--     `iocs.risk_score` (scoring engine writes it). The column was never in
--     the schema TypeScript OR a migration — every query against it
--     produced a 42703 error in production until hot-patched on the droplet.
--
-- We hot-patched the droplet on 2026-06-02 via direct ALTER TABLE / CREATE
-- TABLE. This migration is the upstream version of the same patch — so a
-- fresh deploy doesn't need the hot-patch. `IF NOT EXISTS` everywhere
-- because the prod droplet already has these and re-running the migration
-- must be a no-op there.

-- 1. users.avatar_url — populated by OAuth login flow
ALTER TABLE "users" ADD COLUMN IF NOT EXISTS "avatar_url" text;

-- 2. iocs.risk_score — composite 0-100 score from the scoring engine
ALTER TABLE "iocs" ADD COLUMN IF NOT EXISTS "risk_score" integer DEFAULT 0;
-- Backfill existing rows that arrived before this column existed. Rows
-- still get re-scored by the scoring engine on next ingest; 0 is the
-- "not yet scored" sentinel.
UPDATE "iocs" SET "risk_score" = 0 WHERE "risk_score" IS NULL;

-- 3. galaxy_clusters — MISP Galaxy generic-cluster ingest target
CREATE TABLE IF NOT EXISTS "galaxy_clusters" (
    "id" uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    "galaxy_type" varchar(100) NOT NULL,
    "uuid" varchar(255) NOT NULL UNIQUE,
    "name" varchar(500) NOT NULL,
    "description" text,
    "aliases" jsonb DEFAULT '[]'::jsonb,
    "meta" jsonb DEFAULT '{}'::jsonb,
    "labels" jsonb DEFAULT '[]'::jsonb,
    "external_references" jsonb DEFAULT '[]'::jsonb,
    "source" varchar(100) DEFAULT 'misp-galaxy',
    "synced_at" timestamp with time zone,
    "created_at" timestamp with time zone DEFAULT NOW() NOT NULL,
    "updated_at" timestamp with time zone DEFAULT NOW() NOT NULL
);

CREATE INDEX IF NOT EXISTS "galaxy_clusters_type_idx" ON "galaxy_clusters" ("galaxy_type");
CREATE INDEX IF NOT EXISTS "galaxy_clusters_uuid_idx" ON "galaxy_clusters" ("uuid");
CREATE INDEX IF NOT EXISTS "galaxy_clusters_name_idx" ON "galaxy_clusters" ("name");
