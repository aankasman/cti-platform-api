-- Dedup existing duplicate tags in iocs.tags.
--
-- Discovered while triaging a React duplicate-key warning in the IOC
-- drawer ("Encountered two children with the same key, `ClearFake`").
-- Root cause: the threatfox + malwarebazaar feed handlers assembled
-- their `tags` arrays by spreading both their own static labels AND
-- the upstream feed's `tags` array — when the upstream already
-- contained the same label, the spread produced duplicates. Live
-- audit before this migration:
--
--   rows_with_dup_tags: 6,441
--     malwarebazaar:    4,691  (e.g. {malwarebazaar,elf,Prometei,elf,Prometei,wraith})
--     threatfox:        1,750
--     others:           0
--
-- The ingest path is fixed in the same PR — apps/worker/src/feeds/
-- threatfox.ts + malwarebazaar.ts now wrap their tags array in the
-- new `dedupTags()` helper from @rinjani/core/deduplication. This
-- migration cleans rows already in the DB so:
--
--   • `/v1/stats/trending-tags` stops over-counting (each duplicate
--     used to be unnested separately, inflating `cnt`)
--   • the IOC drawer's `TagsRow` doesn't trip React's duplicate-key
--     check (already deduped defensively in dashboard PR #29, but
--     no need for the client to mask a data problem)
--
-- Dedup is case-insensitive (matches the new helper's behavior) but
-- preserves the FIRST-SEEN casing for display via `ROW_NUMBER()`
-- partitioned by lowercased value, ordered by array position.
-- Trims whitespace and drops empty strings on the same pass.
--
-- Idempotent — the WHERE clause's `array_length(...) <> COUNT(DISTINCT
-- LOWER(TRIM(t)))` filter skips rows already clean, so re-running this
-- migration on already-deduped tables is a no-op.

UPDATE iocs
SET tags = (
    SELECT ARRAY(
        SELECT t FROM (
            SELECT
                TRIM(t) AS t,
                ord,
                ROW_NUMBER() OVER (PARTITION BY LOWER(TRIM(t)) ORDER BY ord) AS rn
            FROM unnest(iocs.tags) WITH ORDINALITY AS u(t, ord)
            WHERE t IS NOT NULL AND TRIM(t) <> ''
        ) ranked
        WHERE rn = 1
        ORDER BY ord
    )
)
WHERE tags IS NOT NULL
  AND array_length(tags, 1) > 1
  AND array_length(tags, 1) <> (
      SELECT COUNT(DISTINCT LOWER(TRIM(t)))
      FROM unnest(tags) AS t
      WHERE t IS NOT NULL AND TRIM(t) <> ''
  );
