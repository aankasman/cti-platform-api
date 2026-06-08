-- Phase 4 #5 (scaffold): malware sandbox submissions + reports.
--
-- One row per (vendor, submission). Tracks vendor task id so we can
-- poll later, links back to the originating IOC when there is one,
-- and stashes the full vendor JSON for the dashboard to render.

CREATE TABLE IF NOT EXISTS "sandbox_reports" (
    "id"                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Vendor + task id together are unique. Same value resubmitted to
    -- the same vendor yields a new task id from the vendor, so we
    -- don't dedupe at the schema level.
    "vendor"              varchar(50) NOT NULL,
    "vendor_task_id"      varchar(255),
    -- Submission context.
    "submitted_ioc_id"    uuid REFERENCES iocs(id) ON DELETE SET NULL,
    "submitted_value"     text NOT NULL,
    "submitted_type"      varchar(50) NOT NULL,
    -- Vendor-reported lifecycle. Values: queued | running | completed | failed | timeout.
    "status"              varchar(50) NOT NULL DEFAULT 'queued',
    -- Normalised verdict: malicious | suspicious | benign | unknown. NULL until completion.
    "verdict"             varchar(50),
    -- Normalised score on 0-100. NULL until completion.
    "score"               integer,
    "report_url"          text,
    "report_json"         jsonb,
    "submitted_at"        timestamptz NOT NULL DEFAULT NOW(),
    "completed_at"        timestamptz,
    "error"               text,
    "created_at"          timestamptz NOT NULL DEFAULT NOW(),
    "updated_at"          timestamptz NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS "sandbox_reports_vendor_idx"
    ON "sandbox_reports" ("vendor");
CREATE INDEX IF NOT EXISTS "sandbox_reports_ioc_idx"
    ON "sandbox_reports" ("submitted_ioc_id");
CREATE INDEX IF NOT EXISTS "sandbox_reports_status_idx"
    ON "sandbox_reports" ("status");
CREATE INDEX IF NOT EXISTS "sandbox_reports_verdict_idx"
    ON "sandbox_reports" ("verdict");
CREATE UNIQUE INDEX IF NOT EXISTS "sandbox_reports_vendor_task_unique"
    ON "sandbox_reports" ("vendor", "vendor_task_id")
    WHERE "vendor_task_id" IS NOT NULL;
