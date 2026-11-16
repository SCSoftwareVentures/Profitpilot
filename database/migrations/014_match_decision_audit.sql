-- ProfitPilot migration 014: make invoice-match decisions immutable, actor-bound and automatically audited.
BEGIN;

CREATE FUNCTION private.enforce_match_review_decision()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,public,private
AS $function$
DECLARE
  actor_id uuid;
  actor_role text;
  audit_reason text;
BEGIN
  IF current_user<>'profitpilot_app' THEN
    RETURN NEW;
  END IF;

  IF OLD.decision NOT IN ('candidate','held') THEN
    RAISE EXCEPTION 'Finalised invoice match decisions are immutable'
      USING ERRCODE='55000';
  END IF;

  IF ROW(NEW.id,NEW.tenant_id,NEW.invoice_line_id,NEW.contract_id,NEW.site_id,
         NEW.service_period_start,NEW.service_period_end,NEW.confidence,NEW.evidence)
     IS DISTINCT FROM
     ROW(OLD.id,OLD.tenant_id,OLD.invoice_line_id,OLD.contract_id,OLD.site_id,
         OLD.service_period_start,OLD.service_period_end,OLD.confidence,OLD.evidence) THEN
    RAISE EXCEPTION 'Invoice match evidence and identity fields are immutable after candidate creation'
      USING ERRCODE='55000';
  END IF;

  IF NEW.decision NOT IN ('confirmed','rejected','held') THEN
    RAISE EXCEPTION 'Unsupported invoice match decision transition'
      USING ERRCODE='23514';
  END IF;

  IF private.current_tenant_id() IS DISTINCT FROM NEW.tenant_id THEN
    RAISE EXCEPTION 'Invoice match decision requires a valid signed tenant context'
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
    OR actor_role NOT IN ('reviewer','admin','owner')
    OR NEW.reviewed_at IS NULL THEN
    RAISE EXCEPTION 'Invoice match reviewer must be the authenticated signed tenant actor with reviewer, admin or owner authority'
      USING ERRCODE='42501';
  END IF;

  audit_reason:=nullif(current_setting('app.audit_reason',true),'');
  IF audit_reason IS NULL OR length(btrim(audit_reason))<3 OR length(audit_reason)>2000 THEN
    RAISE EXCEPTION 'Invoice match decision requires an audit reason of 3 to 2000 characters'
      USING ERRCODE='23514';
  END IF;

  RETURN NEW;
END;
$function$;

CREATE TRIGGER match_reviews_enforce_decision
BEFORE UPDATE ON public.match_reviews
FOR EACH ROW
EXECUTE FUNCTION private.enforce_match_review_decision();

CREATE FUNCTION private.audit_match_review_decision()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog,public,private
AS $function$
DECLARE
  audit_reason text;
BEGIN
  IF current_user<>'profitpilot_app' THEN
    RETURN NEW;
  END IF;

  audit_reason:=nullif(current_setting('app.audit_reason',true),'');
  INSERT INTO public.audit_events(
    tenant_id,actor_user_id,action,object_type,object_id,reason,metadata
  ) VALUES (
    NEW.tenant_id,NEW.reviewer_id,'invoice_match_decision','match_review',NEW.id,
    audit_reason,jsonb_build_object('previousDecision',OLD.decision,'decision',NEW.decision)
  );

  RETURN NEW;
END;
$function$;

CREATE TRIGGER match_reviews_audit_decision
AFTER UPDATE ON public.match_reviews
FOR EACH ROW
EXECUTE FUNCTION private.audit_match_review_decision();

COMMIT;
