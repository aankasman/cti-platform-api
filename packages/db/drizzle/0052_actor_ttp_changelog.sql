-- Phase 5 #2 — Threat-actor TTP changelog.
--
-- MITRE updates per-actor technique lists on roughly a weekly cadence
-- (new techniques get attributed to existing groups, deprecated ones
-- get dropped). Today we lose that signal: we re-ingest the latest
-- MITRE data and overwrite the relationships table, so an analyst
-- can't tell that APT38 picked up T1059.001 last week.
--
-- This migration adds a snapshot-based differ:
--   - actor_ttp_state    Current known (actor, technique) tuples
--   - actor_ttp_changes  Append-only change log
--
-- The differ service walks every threat-actor source_id in the
-- `relationships` table, builds the current set of techniques each
-- one uses, compares against the snapshot, and emits add/remove
-- rows. Operators filter the change log by actor / technique /
-- change_type / time and surface "what's new for APT99 this month"
-- on the actor page.

CREATE TABLE IF NOT EXISTS "actor_ttp_state" (
    "id"              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- MITRE-style actor identifier. Matches `relationships.source_id`
    -- when source_type='threat_actor', e.g. 'G0016'.
    "actor_id"        varchar(128) NOT NULL,
    -- MITRE-style technique identifier, e.g. 'T1059.001'.
    "technique_id"    varchar(128) NOT NULL,
    -- When this tuple was first observed by the differ.
    "observed_at"     timestamptz NOT NULL DEFAULT NOW(),
    -- When the most recent diff run confirmed this tuple still exists.
    "confirmed_at"    timestamptz NOT NULL DEFAULT NOW(),
    CONSTRAINT actor_ttp_state_unique UNIQUE ("actor_id", "technique_id")
);

CREATE INDEX IF NOT EXISTS "actor_ttp_state_actor_idx"
    ON "actor_ttp_state" ("actor_id");
CREATE INDEX IF NOT EXISTS "actor_ttp_state_technique_idx"
    ON "actor_ttp_state" ("technique_id");

CREATE TABLE IF NOT EXISTS "actor_ttp_changes" (
    "id"           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    "actor_id"     varchar(128) NOT NULL,
    "technique_id" varchar(128) NOT NULL,
    -- 'added'    — diff saw this tuple for the first time
    -- 'removed'  — tuple was in the snapshot but is no longer in the live
    --              MITRE relationships (or the actor has been deprecated)
    "change_type"  varchar(20) NOT NULL,
    "detected_at"  timestamptz NOT NULL DEFAULT NOW(),
    -- Optional analyst note. NULL for differ-generated rows.
    "note"         text,

    CONSTRAINT actor_ttp_changes_type_check
        CHECK (change_type IN ('added', 'removed'))
);

CREATE INDEX IF NOT EXISTS "actor_ttp_changes_actor_idx"
    ON "actor_ttp_changes" ("actor_id");
CREATE INDEX IF NOT EXISTS "actor_ttp_changes_technique_idx"
    ON "actor_ttp_changes" ("technique_id");
CREATE INDEX IF NOT EXISTS "actor_ttp_changes_detected_at_idx"
    ON "actor_ttp_changes" ("detected_at" DESC);
CREATE INDEX IF NOT EXISTS "actor_ttp_changes_type_idx"
    ON "actor_ttp_changes" ("change_type");
