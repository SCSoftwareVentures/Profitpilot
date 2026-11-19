-- Remove blanket future privileges. New tables, sequences and fields must
-- be reviewed explicitly. Limit mutable public evidence to route-owned fields.
BEGIN;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER ON TABLES FROM profitpilot_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public REVOKE USAGE,SELECT,UPDATE ON SEQUENCES FROM profitpilot_app;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM profitpilot_app;
REVOKE UPDATE ON public.import_batches,public.mapping_decisions,public.match_reviews FROM profitpilot_app;
GRANT UPDATE(status) ON public.import_batches TO profitpilot_app;
GRANT UPDATE(decision,reason) ON public.mapping_decisions TO profitpilot_app;
GRANT UPDATE(decision,reviewer_id,reviewed_at) ON public.match_reviews TO profitpilot_app;
COMMIT;
