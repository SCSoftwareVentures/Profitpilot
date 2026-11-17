-- ProfitPilot migration 013: bind privileged financial decisions to the signed tenant actor.
-- Application route middleware is not a substitute for database-enforced authority.
BEGIN;

CREATE OR REPLACE FUNCTION private.current_actor_role()
RETURNS text
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path=pg_catalog,public,private
AS $function$
  SELECT tm.role
  FROM public.tenant_memberships tm
  JOIN public.users u ON u.id=tm.user_id
  WHERE tm.tenant_id=private.current_tenant_id()
    AND u.auth_subject=nullif(current_setting('app.tenant_subject',true),'')
    AND tm.status='active'
    AND u.status='active'
  LIMIT 1
$function$;
ALTER FUNCTION private.current_actor_role() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.current_actor_role() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.current_actor_role() TO profitpilot_app;

-- A restrictive policy ANDs with the existing tenant-isolation policy.
-- It cannot be bypassed by adding another permissive tenant policy.
CREATE POLICY match_reviews_actor_update
ON public.match_reviews
AS RESTRICTIVE
FOR UPDATE
TO profitpilot_app
USING (private.current_actor_role() IN ('owner','admin','reviewer'))
WITH CHECK (private.current_actor_role() IN ('owner','admin','reviewer'));

CREATE FUNCTION private.enforce_payroll_confirmation_actor()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,public,private
AS $function$
DECLARE
  actor_id uuid;
  actor_role text;
BEGIN
  IF NEW.status<>'confirmed' OR current_user<>'profitpilot_app' THEN
    RETURN NEW;
  END IF;

  IF private.current_tenant_id() IS DISTINCT FROM NEW.tenant_id THEN
    RAISE EXCEPTION 'Payroll confirmation requires a valid signed tenant context'
      USING ERRCODE='42501';
  END IF;

  SELECT u.id,tm.role
    INTO actor_id,actor_role
  FROM public.users u
  JOIN public.tenant_memberships tm ON tm.user_id=u.id
  WHERE u.auth_subject=nullif(current_setting('app.tenant_subject',true),'')
    AND tm.tenant_id=NEW.tenant_id
    AND u.status='active'
    AND tm.status='active'
  LIMIT 1;

  IF actor_id IS NULL
    OR actor_id IS DISTINCT FROM NEW.reviewer_id
    OR actor_role NOT IN ('reviewer','admin','owner') THEN
    RAISE EXCEPTION 'Payroll confirmation reviewer must be the authenticated signed tenant actor with reviewer, admin or owner authority'
      USING ERRCODE='42501';
  END IF;

  RETURN NEW;
END;
$function$;

CREATE TRIGGER allocation_runs_actor_authority
BEFORE INSERT OR UPDATE ON public.allocation_runs
FOR EACH ROW
EXECUTE FUNCTION private.enforce_payroll_confirmation_actor();

COMMIT;
