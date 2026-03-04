-- OpenSearch Real-Time Sync Triggers
-- Automatically notifies the API when data is inserted or updated

-- Create the notification function
CREATE OR REPLACE FUNCTION notify_opensearch_sync()
RETURNS TRIGGER AS $$
BEGIN
    -- Send notification with table name, operation, and record ID
    PERFORM pg_notify('opensearch_sync', 
        json_build_object(
            'table', TG_TABLE_NAME,
            'operation', TG_OP,
            'id', NEW.id::text
        )::text
    );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- IOCs table trigger
DROP TRIGGER IF EXISTS iocs_opensearch_trigger ON iocs;
CREATE TRIGGER iocs_opensearch_trigger
    AFTER INSERT OR UPDATE ON iocs
    FOR EACH ROW 
    EXECUTE FUNCTION notify_opensearch_sync();

-- Vulnerabilities table trigger
DROP TRIGGER IF EXISTS vulnerabilities_opensearch_trigger ON vulnerabilities;
CREATE TRIGGER vulnerabilities_opensearch_trigger
    AFTER INSERT OR UPDATE ON vulnerabilities
    FOR EACH ROW 
    EXECUTE FUNCTION notify_opensearch_sync();

-- Threat actors table trigger
DROP TRIGGER IF EXISTS threat_actors_opensearch_trigger ON threat_actors;
CREATE TRIGGER threat_actors_opensearch_trigger
    AFTER INSERT OR UPDATE ON threat_actors
    FOR EACH ROW 
    EXECUTE FUNCTION notify_opensearch_sync();

-- Verify triggers are created
SELECT trigger_name, event_object_table, action_timing, event_manipulation 
FROM information_schema.triggers 
WHERE trigger_name LIKE '%opensearch%';
