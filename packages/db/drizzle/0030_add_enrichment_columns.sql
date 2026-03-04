-- Add enrichment persistence columns to the iocs table
-- These columns store on-demand enrichment results from external APIs
-- (VirusTotal, AbuseIPDB, Shodan, etc.) so they don't need to be re-fetched.
-- All columns are nullable to avoid breaking existing records.

ALTER TABLE iocs ADD COLUMN IF NOT EXISTS enrichment_score INTEGER;
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS enrichment_level TEXT;
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS enrichment_tags TEXT[];
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS enrichment_data JSONB;
ALTER TABLE iocs ADD COLUMN IF NOT EXISTS enriched_at TIMESTAMP;
