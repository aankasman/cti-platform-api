-- Phase 5 #1 — Brand / typo-squat monitoring.
--
-- Operator pins their apex domain(s) for monitoring. A scheduled
-- sweep generates dnstwist-style permutations (bitsquats, homoglyphs,
-- insertions, etc.), DNS-resolves each, and records anything that
-- exists as a brand_alerts row. Operators triage the alerts and
-- decide whether to escalate, ignore, or block via the existing
-- blocklist exports.
--
-- Two tables:
--   monitored_domains  Operator-curated list of apex domains to watch
--   brand_alerts        Permutations that resolved to something + a score

CREATE TABLE IF NOT EXISTS "monitored_domains" (
    "id"             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- The apex domain we generate permutations FROM. e.g. "rinjanianalytics.com"
    "apex_domain"    varchar(255) NOT NULL UNIQUE,
    -- Display label so the dashboard doesn't have to render the bare domain.
    "label"          varchar(255),
    -- Free-form ownership note — "Marketing", "Legal handles", etc.
    "owner"          varchar(255),
    -- Whether the scheduler should sweep this domain. Defaults true.
    "enabled"        boolean NOT NULL DEFAULT TRUE,
    -- Last time the sweep ran for this domain. NULL = never.
    "last_swept_at"  timestamptz,
    "created_by"     text,
    "created_at"     timestamptz NOT NULL DEFAULT NOW(),
    "updated_at"     timestamptz NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS "monitored_domains_enabled_idx"
    ON "monitored_domains" ("enabled");

CREATE TABLE IF NOT EXISTS "brand_alerts" (
    "id"                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    "monitored_domain_id" uuid NOT NULL REFERENCES "monitored_domains"("id") ON DELETE CASCADE,
    -- The look-alike domain we found. e.g. "rinjanianalitics.com"
    "permutation"         varchar(255) NOT NULL,
    -- Which generator algorithm produced this. One of:
    --   bitsquat | homoglyph | insertion | omission | substitution
    --   transposition | vowel-swap | hyphenation | subdomain
    "algorithm"           varchar(50) NOT NULL,
    -- Did the permutation resolve via DNS at last_checked_at?
    --   active   — has A/AAAA record
    --   mx_only  — has MX but no A/AAAA (often used for phishing email)
    --   nx       — NXDOMAIN at last check (kept for history; auto-cleared)
    --   error    — DNS lookup failed (transient or rate-limited)
    "dns_state"           varchar(20) NOT NULL,
    -- Comma-joined A records when state=active. NULL otherwise.
    "ip_addresses"        text,
    -- 0..100 — composite score the dashboard sorts on.
    --   +40 if dns_state=active or mx_only
    --   +20 if first_seen within last 7 days
    --   +20 if shares the same TLD as the apex
    --   +20 if Levenshtein distance from apex is 1 or 2
    -- Operators can override via the manual triage flow later.
    "score"               integer NOT NULL DEFAULT 0,
    -- Lifecycle. Defaults to 'new'; analyst flips via PATCH.
    --   new        | triaging | escalated | benign | blocked
    "status"              varchar(20) NOT NULL DEFAULT 'new',
    "first_seen_at"       timestamptz NOT NULL DEFAULT NOW(),
    "last_checked_at"     timestamptz NOT NULL DEFAULT NOW(),
    "notes"               text,
    "created_at"          timestamptz NOT NULL DEFAULT NOW(),
    "updated_at"          timestamptz NOT NULL DEFAULT NOW(),

    CONSTRAINT brand_alerts_unique_per_apex
        UNIQUE ("monitored_domain_id", "permutation"),
    CONSTRAINT brand_alerts_dns_state_check
        CHECK (dns_state IN ('active', 'mx_only', 'nx', 'error')),
    CONSTRAINT brand_alerts_status_check
        CHECK (status IN ('new', 'triaging', 'escalated', 'benign', 'blocked')),
    CONSTRAINT brand_alerts_score_range
        CHECK (score >= 0 AND score <= 100)
);

CREATE INDEX IF NOT EXISTS "brand_alerts_monitored_idx"
    ON "brand_alerts" ("monitored_domain_id");
CREATE INDEX IF NOT EXISTS "brand_alerts_status_idx"
    ON "brand_alerts" ("status");
CREATE INDEX IF NOT EXISTS "brand_alerts_dns_state_idx"
    ON "brand_alerts" ("dns_state");
CREATE INDEX IF NOT EXISTS "brand_alerts_score_idx"
    ON "brand_alerts" ("score" DESC);
