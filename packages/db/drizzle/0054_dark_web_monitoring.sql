-- Phase 5 #4 — Dark-web monitoring via Ahmia (indexed search only).
--
-- Operationally narrow on purpose: NO direct .onion crawling on a
-- single-VPS deployment (operationally messy, legally fraught in
-- several jurisdictions, outside solo-maintainer scope). Instead we
-- query Ahmia's clearnet search index daily for operator-pinned
-- watchterms (brand names, product names, leaked-credential indicators)
-- and record any matches.
--
-- Ahmia's search is unauthenticated, returns clearnet-rendered metadata
-- about Tor hidden services that have opted into indexing — so the
-- platform itself never touches the Tor network. That's the deal.
--
-- Two tables:
--   dark_web_watchterms  Operator-curated search terms
--   dark_web_mentions    Recorded matches per watchterm

CREATE TABLE IF NOT EXISTS "dark_web_watchterms" (
    "id"                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The text we hand to Ahmia's search. Case preserved as the operator
    -- typed it; the matcher itself is case-insensitive anyway.
    "term"              varchar(255) NOT NULL UNIQUE,
    -- Free-form classification — 'brand', 'product', 'actor', 'creds', etc.
    -- The UI groups the triage view by this; the matcher doesn't use it.
    "kind"              varchar(50),
    -- Free-form ownership note ("Marketing", "Legal", etc.).
    "owner"             varchar(255),
    -- Whether the scheduler should search this term. Defaults true.
    "enabled"           boolean NOT NULL DEFAULT TRUE,
    -- Last time the scanner ran a query for this term. NULL = never.
    "last_searched_at"  timestamptz,
    "created_by"        text,
    "created_at"        timestamptz NOT NULL DEFAULT NOW(),
    "updated_at"        timestamptz NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS "dark_web_watchterms_enabled_idx"
    ON "dark_web_watchterms" ("enabled");

CREATE TABLE IF NOT EXISTS "dark_web_mentions" (
    "id"             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    "watchterm_id"   uuid NOT NULL REFERENCES "dark_web_watchterms"("id") ON DELETE CASCADE,
    -- Always 'ahmia' for the initial scaffold. Future sources (e.g. Tor2Web
    -- index mirrors) would slot in here.
    "source"         varchar(50) NOT NULL DEFAULT 'ahmia',
    "title"          text NOT NULL,
    -- The .onion URL the index records. Stored as-is. NOT a URL we crawl.
    "onion_url"      text NOT NULL,
    -- A short snippet around the hit, as returned by the index. Capped at 2000
    -- chars (Ahmia truncates well below that; the cap protects against an
    -- unexpected payload size).
    "snippet"        text,
    -- Composite 0..100 score. Initial fixed at 50 (operator can re-rank via
    -- triage); a future PR can wire signals like "term in title" / "fresh
    -- index entry" / "repeat appearance across runs" into a real score.
    "score"          integer NOT NULL DEFAULT 50,
    -- Lifecycle. Same vocabulary as brand_alerts so the UI can reuse the chip.
    --   new        | triaging | escalated | benign | blocked
    "status"         varchar(20) NOT NULL DEFAULT 'new',
    "first_seen_at"  timestamptz NOT NULL DEFAULT NOW(),
    "last_seen_at"   timestamptz NOT NULL DEFAULT NOW(),
    "notes"          text,
    "created_at"     timestamptz NOT NULL DEFAULT NOW(),
    "updated_at"     timestamptz NOT NULL DEFAULT NOW(),

    -- Same (term, source, onion_url) tuple seen across runs collapses to a
    -- single row (last_seen_at bumped); we never create duplicates.
    CONSTRAINT dark_web_mentions_unique
        UNIQUE ("watchterm_id", "source", "onion_url"),
    CONSTRAINT dark_web_mentions_status_check
        CHECK (status IN ('new', 'triaging', 'escalated', 'benign', 'blocked')),
    CONSTRAINT dark_web_mentions_score_range
        CHECK (score >= 0 AND score <= 100)
);

CREATE INDEX IF NOT EXISTS "dark_web_mentions_watchterm_idx"
    ON "dark_web_mentions" ("watchterm_id");
CREATE INDEX IF NOT EXISTS "dark_web_mentions_status_idx"
    ON "dark_web_mentions" ("status");
CREATE INDEX IF NOT EXISTS "dark_web_mentions_last_seen_idx"
    ON "dark_web_mentions" ("last_seen_at" DESC);
CREATE INDEX IF NOT EXISTS "dark_web_mentions_score_idx"
    ON "dark_web_mentions" ("score" DESC);
