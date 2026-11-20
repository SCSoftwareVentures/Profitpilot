-- Runtime role enforcement and actor attribution, independent of HTTP role checks.
BEGIN;
CREATE FUNCTION private.actor_id() RETURNS uuid
 LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,public,private
 AS $$ SELECT u.id FROM users u JOIN tenant_memberships m ON m.user_id=u.id
 WHERE m.tenant_id=private.current_tenant_id() AND u.auth_subject=nullif(current_setting('app.tenant_subject',true),'')
 AND m.status='active' AND u.status='active' $$;
CREATE FUNCTION private.actor_role() RETURNS text
 LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog,public,private
 AS $$ SELECT m.role FROM tenant_memberships m WHERE m.tenant_id=private.current_tenant_id() AND m.user_id=private.actor_id() AND m.status='active' $$;
REVOKE ALL ON FUNCTION private.actor_id(),private.actor_role() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.actor_id(),private.actor_role() TO profitpilot_app;
CREATE POLICY import_actor_insert ON import_batches AS RESTRICTIVE FOR INSERT TO profitpilot_app
 WITH CHECK(created_by=private.actor_id() AND private.actor_role() IN ('owner','admin','analyst') AND status='uploaded');
CREATE POLICY import_actor_update ON import_batches AS RESTRICTIVE FOR UPDATE TO profitpilot_app
 USING(private.actor_role() IN ('owner','admin','analyst','reviewer'))
 WITH CHECK((status='review' AND private.actor_role() IN ('owner','admin','analyst','reviewer')) OR (status='accepted' AND private.actor_role() IN ('owner','admin','reviewer')));
CREATE POLICY raw_actor_insert ON raw_import_rows AS RESTRICTIVE FOR INSERT TO profitpilot_app
 WITH CHECK(private.actor_role() IN ('owner','admin','analyst'));
CREATE POLICY mapping_actor_insert ON mapping_decisions AS RESTRICTIVE FOR INSERT TO profitpilot_app
 WITH CHECK(private.actor_role() IN ('owner','admin','analyst','reviewer') AND decision IN ('candidate','held') AND reviewer_id IS NULL AND reviewed_at IS NULL AND target_id IS NULL);
-- No current endpoint updates mappings. Remove unused authority.
REVOKE UPDATE(decision,reason) ON mapping_decisions FROM profitpilot_app;
CREATE POLICY match_reviewer_update ON match_reviews AS RESTRICTIVE FOR UPDATE TO profitpilot_app
 USING(private.actor_role() IN ('owner','admin','reviewer') AND decision IN ('candidate','held'))
 WITH CHECK(private.actor_role() IN ('owner','admin','reviewer') AND reviewer_id=private.actor_id() AND reviewed_at IS NOT NULL AND decision IN ('confirmed','held','rejected'));
CREATE POLICY calculation_actor_insert ON calculation_runs AS RESTRICTIVE FOR INSERT TO profitpilot_app
 WITH CHECK(created_by=private.actor_id() AND private.actor_role() IN ('owner','admin','analyst','reviewer') AND completeness='incomplete');
CREATE POLICY audit_actor_insert ON audit_events AS RESTRICTIVE FOR INSERT TO profitpilot_app
 WITH CHECK(actor_user_id=private.actor_id() AND private.actor_role() IN ('owner','admin','analyst','reviewer'));
COMMIT;
