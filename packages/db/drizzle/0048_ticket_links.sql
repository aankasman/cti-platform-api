-- Phase 4 #6 (scaffold): external ticket links for cases.
--
-- One row per (case, vendor, vendor-issue) join. Lets a case carry
-- many external tickets (e.g., a critical investigation might open a
-- GitHub Issue for the engineering team AND a JIRA ticket for SOC
-- triage). Sync status and the last vendor error are tracked here so
-- the dashboard can show a yellow/red dot next to a stale link.

CREATE TABLE IF NOT EXISTS "ticket_links" (
    "id"                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- cases.id is TEXT (not UUID) per the existing routes/v1/cases.ts
    -- bootstrap shape; match its type here.
    "case_id"              text NOT NULL,
    -- Vendor: 'github' wired now; 'jira' deferred to follow-up.
    "vendor"               varchar(50) NOT NULL,
    -- For github: "<owner>/<repo>". For jira: project key.
    "vendor_repo"          varchar(255) NOT NULL,
    -- The vendor's own integer / string id for the issue.
    "vendor_issue_id"      varchar(255) NOT NULL,
    "vendor_issue_url"     text NOT NULL,
    "title"                text NOT NULL,
    "status"               varchar(50) NOT NULL DEFAULT 'open',
    "labels"               jsonb NOT NULL DEFAULT '[]'::jsonb,
    "last_synced_at"       timestamptz,
    "last_sync_error"      text,
    "created_at"           timestamptz NOT NULL DEFAULT NOW(),
    "updated_at"           timestamptz NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS "ticket_links_case_idx"
    ON "ticket_links" ("case_id");
CREATE INDEX IF NOT EXISTS "ticket_links_vendor_idx"
    ON "ticket_links" ("vendor");
CREATE UNIQUE INDEX IF NOT EXISTS "ticket_links_vendor_unique"
    ON "ticket_links" ("vendor", "vendor_repo", "vendor_issue_id");
