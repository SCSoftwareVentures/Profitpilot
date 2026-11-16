-- ProfitPilot migration 012: approved contract tax-basis metadata.
-- Legacy versions default to unknown and must be explicitly reviewed before
-- their invoice revenue can participate in a contribution calculation.
BEGIN;
ALTER TABLE contract_versions
  ADD COLUMN IF NOT EXISTS tax_basis text NOT NULL DEFAULT 'unknown'
  CHECK(tax_basis IN ('gst_inclusive','gst_exclusive','no_gst','unknown'));
COMMIT;
