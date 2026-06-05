-- PR #46 · pulses.references
--
-- OTX returns a `references` array on every pulse (URLs to source
-- articles, vendor write-ups, blog posts the analyst published with).
-- The schema previously dropped these on the floor; persisting them
-- lets the dashboard's pulse-detail page render a "References" section
-- instead of forcing analysts to bounce to otx.alienvault.com.

ALTER TABLE "pulses" ADD COLUMN IF NOT EXISTS "references" text[];
