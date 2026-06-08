-- Phase 2 item #2: constrain relationships.relationship_type to a known
-- vocabulary instead of accepting any VARCHAR(64).
--
-- We use a CHECK constraint rather than a pgEnum so adding new types
-- later doesn't require ALTER TYPE / new migration round-trips and so
-- existing rows aren't blocked while we backfill.
--
-- Allowed values:
--   STIX 2.1 §5 common SRO vocab — uses, targets, attributed-to,
--   mitigates, derived-from, indicates, related-to, beacons-to,
--   communicates-with, exfiltrates-to, downloads, drops, exploits,
--   originates-from, characterizes, av-classification, controls,
--   delivers, hosts, owns, authored-by, sub-technique-of, revoked-by,
--   detects, impersonates
--   Project-specific: unknown (legacy MITRE fallback)

DO $$
BEGIN
    -- Drop the constraint first if it already exists (idempotent migration).
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'relationships_relationship_type_check'
    ) THEN
        ALTER TABLE relationships DROP CONSTRAINT relationships_relationship_type_check;
    END IF;

    -- Normalise any pre-existing rows that don't match the new vocab — map
    -- them to 'related-to' so the CHECK can be added without failing.
    UPDATE relationships
    SET relationship_type = 'related-to'
    WHERE relationship_type NOT IN (
        'uses', 'targets', 'attributed-to', 'mitigates', 'derived-from',
        'indicates', 'related-to', 'beacons-to', 'communicates-with',
        'exfiltrates-to', 'downloads', 'drops', 'exploits',
        'originates-from', 'characterizes', 'av-classification',
        'controls', 'delivers', 'hosts', 'owns', 'authored-by',
        'sub-technique-of', 'revoked-by', 'detects', 'impersonates',
        'unknown'
    );

    ALTER TABLE relationships
        ADD CONSTRAINT relationships_relationship_type_check
        CHECK (relationship_type IN (
            'uses', 'targets', 'attributed-to', 'mitigates', 'derived-from',
            'indicates', 'related-to', 'beacons-to', 'communicates-with',
            'exfiltrates-to', 'downloads', 'drops', 'exploits',
            'originates-from', 'characterizes', 'av-classification',
            'controls', 'delivers', 'hosts', 'owns', 'authored-by',
            'sub-technique-of', 'revoked-by', 'detects', 'impersonates',
            'unknown'
        ));
END$$;
