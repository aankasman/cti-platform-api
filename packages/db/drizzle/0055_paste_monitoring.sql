-- Phase 5 #5 — Paste-site monitoring (GitHub Gist firehose).
--
-- Operator pins watchterms (brand names, product names, leaked-cred
-- indicators). A scheduled job walks GitHub's public Gist firehose
-- and records any gist whose filename or description contains a
-- watchterm.
--
-- Scope discipline: gist firehose only in this PR. Telegram channel
-- monitoring (bot token + per-channel subscription) is a documented
-- follow-on with different operational shape. Pastebin's free /scrape
-- endpoint was deprecated and the paid one is intentionally out of
-- scope.
--
-- Two tables:
--   paste_watchterms  Operator-curated search terms
--   paste_mentions    Recorded matches per (watchterm, source, url)

CREATE TABLE IF NOT EXISTS "paste_watchterms" (
    "id"                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    "term"              varchar(255) NOT NULL UNIQUE,
    -- Free-form classification — 'brand', 'creds', 'project', etc.
    "kind"              varchar(50),
    "owner"             varchar(255),
    "enabled"           boolean NOT NULL DEFAULT TRUE,
    "last_searched_at"  timestamptz,
    "created_by"        text,
    "created_at"        timestamptz NOT NULL DEFAULT NOW(),
    "updated_at"        timestamptz NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS "paste_watchterms_enabled_idx"
    ON "paste_watchterms" ("enabled");

CREATE TABLE IF NOT EXISTS "paste_mentions" (
    "id"             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    "watchterm_id"   uuid NOT NULL REFERENCES "paste_watchterms"("id") ON DELETE CASCADE,
    -- 'github_gist' for the initial scaffold. Future sources (Telegram,
    -- other paste sites) would slot in here without schema changes.
    "source"         varchar(50) NOT NULL DEFAULT 'github_gist',
    -- The author's gist or paste's owner login.
    "author"         varchar(255),
    -- Filename for gist hits; left null for sources without a filename concept.
    "filename"       varchar(255),
    -- Free-form gist description / paste title.
    "title"          text,
    -- Public URL of the gist / paste itself.
    "external_url"   text NOT NULL,
    -- Stable identifier from the source (gist id for github_gist).
    "external_id"    varchar(255) NOT NULL,
    -- Short text snippet around the matched term, capped.
    "snippet"        text,
    -- 0..100 composite. Initial fixed at 50 (operator can re-rank via
    -- triage); future PR can score on "term in filename" / "freshness" / etc.
    "score"          integer NOT NULL DEFAULT 50,
    -- Lifecycle. Same vocabulary as the other Phase 5 surfaces.
    "status"         varchar(20) NOT NULL DEFAULT 'new',
    -- When the watchterm scanner first matched this paste.
    "first_seen_at"  timestamptz NOT NULL DEFAULT NOW(),
    -- Most recent run that confirmed the paste still matches.
    "last_seen_at"   timestamptz NOT NULL DEFAULT NOW(),
    "notes"          text,
    "created_at"     timestamptz NOT NULL DEFAULT NOW(),
    "updated_at"     timestamptz NOT NULL DEFAULT NOW(),

    CONSTRAINT paste_mentions_unique
        UNIQUE ("watchterm_id", "source", "external_id"),
    CONSTRAINT paste_mentions_status_check
        CHECK (status IN ('new', 'triaging', 'escalated', 'benign', 'blocked')),
    CONSTRAINT paste_mentions_score_range
        CHECK (score >= 0 AND score <= 100)
);

CREATE INDEX IF NOT EXISTS "paste_mentions_watchterm_idx"
    ON "paste_mentions" ("watchterm_id");
CREATE INDEX IF NOT EXISTS "paste_mentions_status_idx"
    ON "paste_mentions" ("status");
CREATE INDEX IF NOT EXISTS "paste_mentions_last_seen_idx"
    ON "paste_mentions" ("last_seen_at" DESC);
CREATE INDEX IF NOT EXISTS "paste_mentions_score_idx"
    ON "paste_mentions" ("score" DESC);
