-- PR #46 followup · rename pulses.references → pulses.reference_urls
--
-- `references` is a reserved keyword in PostgreSQL (used by FOREIGN KEY
-- ... REFERENCES). Every query that touched the column had to quote it
-- ("references"), and the first ad-hoc verification query forgot — see
-- the 2026-06-05 deploy verification: `syntax error at or near
-- "references"`.
--
-- Rename to a non-reserved name. The Drizzle field stays as
-- `references` on the TypeScript side (the schema decouples JS property
-- from SQL column name), so no JS / API / dashboard code changes.

ALTER TABLE "pulses" RENAME COLUMN "references" TO "reference_urls";
