-- Phase 3 #1 follow-on — persist report ingestion drafts.
--
-- Operators ingest a report (text / URL / PDF) and the extractor
-- returns a draft (IOCs + entities). Today the draft is response-only
-- and disappears the moment the request completes. This table lets
-- the draft survive — operator can review later, commit the subset of
-- IOCs / entities they actually want imported, or dismiss the report
-- without action.
--
-- Lifecycle:
--   draft  → committed (operator approved at least one IOC/entity)
--   draft  → dismissed (operator rejected the whole thing)
--   draft  → draft (still under review)
--
-- We store the full extraction payload as JSONB rather than relational
-- IOC rows: the draft is a snapshot for review, not a normalised
-- entity store. The COMMIT step is what writes into the canonical
-- `iocs` / `threat_actors` / etc. tables.

CREATE TABLE IF NOT EXISTS "extracted_reports" (
    "id"             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Free-form attribution: original URL, PDF filename, "pasted from Slack", etc.
    "source"         text,
    -- 'text' | 'url' | 'pdf' — drives any source-specific re-fetch later.
    "source_kind"    varchar(20) NOT NULL,
    -- Per-source metadata: { finalUrl, pageCount, title, contentType, bytes, ... }
    -- Same shape as the route's response.sourceMeta field.
    "source_meta"    jsonb NOT NULL DEFAULT '{}'::jsonb,

    "extracted_at"   timestamptz NOT NULL DEFAULT NOW(),
    "text_length"    integer NOT NULL,

    -- ExtractedIoc[] + the grouped summary.
    "iocs"           jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- ExtractedEntities from the LLM (or {} when LLM was skipped/failed).
    "entities"       jsonb NOT NULL DEFAULT '{}'::jsonb,
    "llm_provider"   varchar(50),
    "llm_error"      text,

    -- Lifecycle.
    "status"         varchar(20) NOT NULL DEFAULT 'draft',
    "committed_at"   timestamptz,
    "committed_by"   text,
    -- Per-commit summary: how many IOCs created / updated / skipped, etc.
    -- Captured for audit even after rollback because the IOC rows themselves
    -- carry no back-reference.
    "commit_summary" jsonb,

    "created_by"     text,
    "created_at"     timestamptz NOT NULL DEFAULT NOW(),

    CONSTRAINT extracted_reports_status_check
        CHECK (status IN ('draft', 'committed', 'dismissed'))
);

CREATE INDEX IF NOT EXISTS "extracted_reports_status_idx"
    ON "extracted_reports" ("status");

CREATE INDEX IF NOT EXISTS "extracted_reports_created_at_idx"
    ON "extracted_reports" ("created_at" DESC);

CREATE INDEX IF NOT EXISTS "extracted_reports_created_by_idx"
    ON "extracted_reports" ("created_by");
