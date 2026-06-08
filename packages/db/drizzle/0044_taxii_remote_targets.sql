-- Phase 2 item #4: TAXII 2.1 outbound push targets.
--
-- Each row describes a remote TAXII server we can push a STIX bundle to.
-- Pull (we ingest from remotes) is a separate feature; this table is
-- write-only-to-remote.
--
-- api_key_ref is the row id from config_api_keys when the operator has
-- vaulted the token there; or NULL when the token lives in the
-- TAXII_PUSH_API_KEY env var (single-target shortcut).

CREATE TABLE IF NOT EXISTS "taxii_remote_targets" (
    "id"             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    "name"           varchar(255) NOT NULL,
    "discovery_url"  text NOT NULL,
    "api_root"       text NOT NULL,
    "collection_id"  varchar(255) NOT NULL,
    "api_key_ref"    varchar(255),
    "enabled"        boolean NOT NULL DEFAULT true,
    "last_push_at"   timestamptz,
    "last_push_status" varchar(50),
    "last_push_error"  text,
    "last_push_objects" integer NOT NULL DEFAULT 0,
    "push_filter"    jsonb NOT NULL DEFAULT '{}'::jsonb,
    "created_at"     timestamptz NOT NULL DEFAULT NOW(),
    "updated_at"     timestamptz NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS "taxii_remote_targets_enabled_idx"
    ON "taxii_remote_targets" ("enabled");
CREATE UNIQUE INDEX IF NOT EXISTS "taxii_remote_targets_name_unique_idx"
    ON "taxii_remote_targets" ("name");
