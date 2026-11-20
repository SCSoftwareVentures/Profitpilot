BEGIN;
ALTER TABLE import_source_receipts ADD COLUMN scan_status text NOT NULL DEFAULT 'not_configured'
 CHECK(scan_status IN ('not_configured','scanner_reported_clean'));
GRANT SELECT(scan_status),INSERT(scan_status) ON import_source_receipts TO profitpilot_app;
COMMIT;
