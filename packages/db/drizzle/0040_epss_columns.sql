-- Phase 1 · Vulnerability scoring upgrades — EPSS columns
--
-- FIRST.org's daily exploit-prediction score. Two numeric fields and
-- a refresh timestamp. Index on epss_score because the analyst query
-- pattern is "show me critical CVEs with EPSS >= 0.7" (i.e., a real
-- exploitation likelihood, not just severity volume).

ALTER TABLE "vulnerabilities" ADD COLUMN IF NOT EXISTS "epss_score" numeric(6, 5);
ALTER TABLE "vulnerabilities" ADD COLUMN IF NOT EXISTS "epss_percentile" numeric(6, 5);
ALTER TABLE "vulnerabilities" ADD COLUMN IF NOT EXISTS "epss_updated_at" timestamp with time zone;

CREATE INDEX IF NOT EXISTS "vulnerabilities_epss_score_idx" ON "vulnerabilities" ("epss_score");
