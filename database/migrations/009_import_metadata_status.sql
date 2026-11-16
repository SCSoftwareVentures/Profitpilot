-- ProfitPilot migration 009: distinguish metadata registration from binary upload.
-- No secure binary object storage is implemented yet; never claim a file is stored.
BEGIN;
ALTER TABLE import_batches DROP CONSTRAINT import_batches_status_check;
UPDATE import_batches SET status='registered' WHERE status='uploaded';
ALTER TABLE import_batches ADD CONSTRAINT import_batches_status_check
 CHECK(status IN ('registered','validating','review','accepted','rejected','failed'));
COMMIT;
