-- Phase 3 #5 — Hypothesis tracking.
--
-- An analyst's claim about the world — "Group A is using infrastructure
-- X" — backed by evidence rows from feeds + sightings. The LLM grades
-- the evidence list into a current confidence score so the analyst can
-- watch a claim strengthen / weaken as ingest brings in new data.
--
-- Two tables:
--
--   hypotheses          The claim itself + its current grade + lifecycle
--   hypothesis_evidence Per-supporting-fact rows pinned to entities

CREATE TABLE IF NOT EXISTS "hypotheses" (
    "id"                   uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    "title"                varchar(500) NOT NULL,
    -- The claim itself in the analyst's own words. The LLM grades against this.
    "claim"                text NOT NULL,
    -- 'active'   — under review, can accept new evidence
    -- 'confirmed'— analyst marked closed-with-prejudice (claim believed true)
    -- 'refuted'  — analyst marked closed-with-prejudice (claim believed false)
    "status"               varchar(20) NOT NULL DEFAULT 'active',
    -- 0..100 confidence the claim is true. Updated by /grade. Default 50
    -- so a fresh hypothesis with no evidence reads as "no signal yet".
    "confidence_score"     integer NOT NULL DEFAULT 50,
    -- Optional subject anchor — the entity the claim is *about*.
    -- One of: threat_actor | malware | campaign | infrastructure | ioc | cve
    "subject_type"         varchar(50),
    "subject_id"           uuid,

    -- Last LLM grading run — captured for audit + UI display.
    "last_graded_at"       timestamptz,
    "last_grading_reason"  text,
    "last_grading_provider" varchar(50),

    "created_by"           text,
    "created_at"           timestamptz NOT NULL DEFAULT NOW(),
    "updated_at"           timestamptz NOT NULL DEFAULT NOW(),

    CONSTRAINT hypotheses_status_check
        CHECK (status IN ('active', 'confirmed', 'refuted')),
    CONSTRAINT hypotheses_confidence_range
        CHECK (confidence_score >= 0 AND confidence_score <= 100)
);

CREATE INDEX IF NOT EXISTS "hypotheses_status_idx"
    ON "hypotheses" ("status");
CREATE INDEX IF NOT EXISTS "hypotheses_subject_idx"
    ON "hypotheses" ("subject_type", "subject_id");
CREATE INDEX IF NOT EXISTS "hypotheses_created_at_idx"
    ON "hypotheses" ("created_at" DESC);

CREATE TABLE IF NOT EXISTS "hypothesis_evidence" (
    "id"             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    "hypothesis_id"  uuid NOT NULL REFERENCES "hypotheses"("id") ON DELETE CASCADE,
    -- What type of entity this evidence row points at.
    -- One of: ioc | relationship | sighting | actor | malware | campaign | report | freeform
    "evidence_type"  varchar(50) NOT NULL,
    -- The entity's id when entity_type is concrete. NULL for 'freeform' notes
    -- that only carry a human description.
    "entity_id"      text,
    -- 'supports' or 'refutes' — which way this evidence cuts.
    "kind"           varchar(20) NOT NULL,
    -- 0..100 — analyst-provided strength. Defaults to 50.
    "weight"         integer NOT NULL DEFAULT 50,
    -- Analyst's note explaining WHY this evidence supports/refutes.
    -- Crucial for the LLM grader — it explains the evidence in context.
    "note"           text,
    "created_by"     text,
    "created_at"     timestamptz NOT NULL DEFAULT NOW(),

    CONSTRAINT hypothesis_evidence_kind_check
        CHECK (kind IN ('supports', 'refutes')),
    CONSTRAINT hypothesis_evidence_weight_range
        CHECK (weight >= 0 AND weight <= 100)
);

CREATE INDEX IF NOT EXISTS "hypothesis_evidence_hypothesis_idx"
    ON "hypothesis_evidence" ("hypothesis_id");
CREATE INDEX IF NOT EXISTS "hypothesis_evidence_kind_idx"
    ON "hypothesis_evidence" ("kind");
