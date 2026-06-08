-- Phase 2 item #1: add three of the seven missing STIX 2.1 SDO tables.
--
-- intrusion-set is already covered by threat_actors (aliased by the
-- relationships table); attack-pattern is covered by techniques;
-- tool is covered by tools (MITRE); note + opinion stay skip-only
-- because they're commentary, not entities.
--
-- These three tables are the ones that the STIX importer
-- (apps/api/src/routes/v1/stixPipeline.ts) was already mapping to but
-- silently dropping for lack of a backing table. After this migration,
-- the importer can ingest them.

CREATE TABLE IF NOT EXISTS "campaigns" (
    "id"                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    "stix_id"              varchar(255) NOT NULL UNIQUE,
    "name"                 varchar(500) NOT NULL,
    "description"          text,
    "aliases"              jsonb NOT NULL DEFAULT '[]'::jsonb,
    "first_seen"           timestamptz,
    "last_seen"            timestamptz,
    "objective"            text,
    "external_references"  jsonb NOT NULL DEFAULT '[]'::jsonb,
    "labels"               jsonb NOT NULL DEFAULT '[]'::jsonb,
    "stix_created"         timestamptz,
    "stix_modified"        timestamptz,
    "synced_at"            timestamptz,
    "created_at"           timestamptz NOT NULL DEFAULT NOW(),
    "updated_at"           timestamptz NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS "campaigns_name_idx" ON "campaigns" ("name");
CREATE INDEX IF NOT EXISTS "campaigns_stix_id_idx" ON "campaigns" ("stix_id");

CREATE TABLE IF NOT EXISTS "courses_of_action" (
    "id"                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    "stix_id"              varchar(255) NOT NULL UNIQUE,
    "name"                 varchar(500) NOT NULL,
    "description"          text,
    -- STIX 2.1 §4.9 deprecates action_type in favour of `action`, but most
    -- producers still emit one or the other — keep both columns optional.
    "action_type"          varchar(100),
    "action_description"   text,
    "external_references"  jsonb NOT NULL DEFAULT '[]'::jsonb,
    "labels"               jsonb NOT NULL DEFAULT '[]'::jsonb,
    "stix_created"         timestamptz,
    "stix_modified"        timestamptz,
    "synced_at"            timestamptz,
    "created_at"           timestamptz NOT NULL DEFAULT NOW(),
    "updated_at"           timestamptz NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS "courses_of_action_name_idx" ON "courses_of_action" ("name");
CREATE INDEX IF NOT EXISTS "courses_of_action_stix_id_idx" ON "courses_of_action" ("stix_id");

CREATE TABLE IF NOT EXISTS "infrastructure" (
    "id"                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    "stix_id"              varchar(255) NOT NULL UNIQUE,
    "name"                 varchar(500) NOT NULL,
    "description"          text,
    -- STIX 2.1 infrastructure_types: e.g. amplification, anonymization,
    -- botnet, command-and-control, exfiltration, hosting-malware,
    -- phishing, reconnaissance, staging, undefined, unknown
    "infrastructure_types" jsonb NOT NULL DEFAULT '[]'::jsonb,
    "aliases"              jsonb NOT NULL DEFAULT '[]'::jsonb,
    "kill_chain_phases"    jsonb NOT NULL DEFAULT '[]'::jsonb,
    "first_seen"           timestamptz,
    "last_seen"            timestamptz,
    "external_references"  jsonb NOT NULL DEFAULT '[]'::jsonb,
    "labels"               jsonb NOT NULL DEFAULT '[]'::jsonb,
    "stix_created"         timestamptz,
    "stix_modified"        timestamptz,
    "synced_at"            timestamptz,
    "created_at"           timestamptz NOT NULL DEFAULT NOW(),
    "updated_at"           timestamptz NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS "infrastructure_name_idx" ON "infrastructure" ("name");
CREATE INDEX IF NOT EXISTS "infrastructure_stix_id_idx" ON "infrastructure" ("stix_id");
