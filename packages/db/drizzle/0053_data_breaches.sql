-- Phase 5 #3 — HIBP breach catalog (free-tier sync only).
--
-- haveibeenpwned.com's `/breaches` endpoint is unauthenticated and
-- returns the full vetted breach catalog (~700 entries as of 2026-06).
-- The per-account `/breachedaccount` endpoint requires a paid key
-- and is intentionally OUT of scope for this phase.
--
-- The /breaches catalog is enough to power "newly disclosed breaches
-- in the last 30 days affecting your monitored email domains" — which
-- is the question Phase 5 actually needs to answer.

CREATE TABLE IF NOT EXISTS "data_breaches" (
    "id"              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- HIBP's canonical machine name for the breach, e.g. "Adobe".
    "name"            varchar(255) NOT NULL UNIQUE,
    -- HIBP's display title, e.g. "Adobe".
    "title"           varchar(255) NOT NULL,
    -- The domain at which the breach occurred. May be empty for breaches
    -- that aren't tied to a specific domain (combo lists, etc.).
    "domain"          varchar(255),

    -- Dates HIBP exposes per breach. All optional because the older
    -- entries occasionally have missing fields.
    "breach_date"     timestamptz,
    "added_date"      timestamptz,
    "modified_date"   timestamptz,

    -- Number of accounts affected. Stored as bigint because some
    -- combo lists exceed the int32 range.
    "pwn_count"       bigint NOT NULL DEFAULT 0,

    "description"     text,
    -- Array of data class labels, e.g. ["Email addresses", "Passwords"].
    "data_classes"    jsonb NOT NULL DEFAULT '[]'::jsonb,

    -- HIBP quality flags. Mirror them directly.
    "is_verified"     boolean NOT NULL DEFAULT FALSE,
    "is_fabricated"   boolean NOT NULL DEFAULT FALSE,
    "is_sensitive"    boolean NOT NULL DEFAULT FALSE,
    "is_retired"      boolean NOT NULL DEFAULT FALSE,
    "is_spam_list"    boolean NOT NULL DEFAULT FALSE,

    "logo_path"       text,

    -- Sync provenance.
    "first_synced_at" timestamptz NOT NULL DEFAULT NOW(),
    "last_synced_at"  timestamptz NOT NULL DEFAULT NOW(),
    -- Stash the raw HIBP payload for forensic debugging.
    "raw_data"        jsonb,

    "created_at"      timestamptz NOT NULL DEFAULT NOW(),
    "updated_at"      timestamptz NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS "data_breaches_domain_idx"
    ON "data_breaches" (LOWER("domain"));
CREATE INDEX IF NOT EXISTS "data_breaches_added_date_idx"
    ON "data_breaches" ("added_date" DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS "data_breaches_modified_date_idx"
    ON "data_breaches" ("modified_date" DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS "data_breaches_breach_date_idx"
    ON "data_breaches" ("breach_date" DESC NULLS LAST);
