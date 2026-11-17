-- Limited processing restriction: block creation/staging of new source records attributed to the requester.
BEGIN;
CREATE TABLE private.source_ingestion_restrictions(
 request_id uuid PRIMARY KEY REFERENCES public.privacy_requests(id),
 tenant_id uuid NOT NULL,user_id uuid NOT NULL,reviewed_by uuid NOT NULL,
 activated_at timestamptz NOT NULL,release_request_id uuid UNIQUE REFERENCES public.privacy_requests(id),
 released_at timestamptz,release_reviewed_by uuid,
 FOREIGN KEY(tenant_id,user_id) REFERENCES public.tenant_memberships(tenant_id,user_id),
 FOREIGN KEY(tenant_id,reviewed_by) REFERENCES public.tenant_memberships(tenant_id,user_id),
 FOREIGN KEY(tenant_id,release_reviewed_by) REFERENCES public.tenant_memberships(tenant_id,user_id),
 CHECK(user_id<>reviewed_by AND (release_reviewed_by IS NULL OR release_reviewed_by<>user_id)),
 CHECK((released_at IS NULL AND release_request_id IS NULL AND release_reviewed_by IS NULL) OR
 (released_at>=activated_at AND release_request_id IS NOT NULL AND release_reviewed_by IS NOT NULL AND release_request_id<>request_id))
);
ALTER TABLE private.source_ingestion_restrictions OWNER TO profitpilot_context_owner;
REVOKE ALL ON private.source_ingestion_restrictions FROM PUBLIC,profitpilot_app;
CREATE UNIQUE INDEX one_active_source_ingestion_restriction ON private.source_ingestion_restrictions(tenant_id,user_id) WHERE released_at IS NULL;

CREATE FUNCTION private.apply_source_ingestion_restriction(p_tenant uuid,p_request uuid,p_mode text,p_auth_time bigint,p_proof text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE actor uuid; item public.privacy_requests%ROWTYPE; active_item private.source_ingestion_restrictions%ROWTYPE; at_time timestamptz;
BEGIN
 IF p_mode IS NULL OR p_mode NOT IN ('activate','release') THEN RAISE EXCEPTION 'Invalid restriction action' USING ERRCODE='22023'; END IF;
 actor:=private.assert_privacy_step_up(p_tenant,p_request,'source_ingestion_restriction:'||p_mode,p_auth_time,p_proof);
 IF private.has_scoped_permission(p_tenant,'privacy.requests.submit') IS DISTINCT FROM true THEN RAISE EXCEPTION 'Privacy permission required' USING ERRCODE='42501'; END IF;
 SELECT * INTO item FROM public.privacy_requests WHERE tenant_id=p_tenant AND id=p_request AND subject_user_id=actor FOR UPDATE;
 IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'error','Privacy request not found'); END IF;
 PERFORM private.lock_privacy_retention_subject(p_tenant,actor);
 at_time:=clock_timestamp();
 IF item.request_type<>'restriction' OR item.status<>'under_review' OR item.account_confirmed_at IS NULL
 OR item.account_confirmed_at<at_time-interval '24 hours'
 OR p_auth_time<=floor(extract(epoch FROM item.updated_at))::bigint
 OR item.assigned_to IS NULL OR item.assigned_to=actor
 OR NOT EXISTS(SELECT 1 FROM public.tenant_memberships m JOIN public.users u ON u.id=m.user_id WHERE m.tenant_id=p_tenant AND m.user_id=item.assigned_to AND m.status='active' AND m.role IN ('owner','admin') AND u.status='active')
 OR EXISTS(SELECT 1 FROM private.source_ingestion_restrictions WHERE request_id=p_request OR release_request_id=p_request)
 THEN RETURN jsonb_build_object('status',409,'error','Separate reviewed restriction request and new requester MFA required'); END IF;
 SELECT * INTO active_item FROM private.source_ingestion_restrictions WHERE tenant_id=p_tenant AND user_id=actor AND released_at IS NULL FOR UPDATE;
 IF p_mode='activate' THEN
  IF FOUND THEN RETURN jsonb_build_object('status',409,'error','Source ingestion restriction already active');END IF;
  INSERT INTO private.source_ingestion_restrictions(request_id,tenant_id,user_id,reviewed_by,activated_at) VALUES(p_request,p_tenant,actor,item.assigned_to,at_time);
 ELSE
  IF NOT FOUND OR item.created_at<=active_item.activated_at
  OR EXISTS(SELECT 1 FROM private.privacy_retention_holds WHERE tenant_id=p_tenant AND subject_user_id=actor)
  OR EXISTS(SELECT 1 FROM public.privacy_requests WHERE tenant_id=p_tenant AND subject_user_id=actor AND status='legal_hold')
  THEN RETURN jsonb_build_object('status',409,'error','Active restriction, subsequent request and absence of legal holds required');END IF;
  UPDATE private.source_ingestion_restrictions SET release_request_id=p_request,released_at=at_time,release_reviewed_by=item.assigned_to WHERE request_id=active_item.request_id;
 END IF;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES(p_tenant,actor,'privacy_source_ingestion_'||p_mode,'privacy_request',p_request,'Reviewed limited source ingestion restriction changed',jsonb_build_object('scope','new-source-ingestion','completeProcessingRestriction',false));
 RETURN jsonb_build_object('status',200,'item',jsonb_build_object('requestId',p_request,'scope','new-source-ingestion','active',p_mode='activate','completeProcessingRestriction',false));
END
$fn$;
ALTER FUNCTION private.apply_source_ingestion_restriction(uuid,uuid,text,bigint,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.apply_source_ingestion_restriction(uuid,uuid,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.apply_source_ingestion_restriction(uuid,uuid,text,bigint,text) TO profitpilot_app;

CREATE FUNCTION private.guard_restricted_source_ingestion() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE owner_id uuid;
BEGIN
 IF TG_TABLE_NAME='import_batches' OR TG_TABLE_NAME='quarantined_attachments' THEN owner_id:=NEW.created_by;
 ELSE SELECT created_by INTO owner_id FROM public.import_batches WHERE tenant_id=NEW.tenant_id AND id=NEW.batch_id;
 END IF;
 IF owner_id IS NULL THEN RAISE EXCEPTION 'Source owner is required' USING ERRCODE='23503';END IF;
 PERFORM private.lock_privacy_retention_subject(NEW.tenant_id,owner_id);
 IF EXISTS(SELECT 1 FROM private.source_ingestion_restrictions WHERE tenant_id=NEW.tenant_id AND user_id=owner_id AND released_at IS NULL)
 THEN RAISE EXCEPTION 'Source ingestion is restricted' USING ERRCODE='PPR01';END IF;
 RETURN NEW;
END
$fn$;
ALTER FUNCTION private.guard_restricted_source_ingestion() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.guard_restricted_source_ingestion() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER restrict_new_import_batch BEFORE INSERT ON public.import_batches FOR EACH ROW EXECUTE FUNCTION private.guard_restricted_source_ingestion();
CREATE TRIGGER restrict_new_raw_row BEFORE INSERT ON public.raw_import_rows FOR EACH ROW EXECUTE FUNCTION private.guard_restricted_source_ingestion();
CREATE TRIGGER restrict_new_quarantine BEFORE INSERT ON private.quarantined_attachments FOR EACH ROW EXECUTE FUNCTION private.guard_restricted_source_ingestion();

CREATE FUNCTION private.guard_source_ingestion_receipt() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Restriction receipts must be retained' USING ERRCODE='55000';END IF;
 IF OLD.released_at IS NOT NULL OR NEW.released_at IS NULL
 OR ROW(NEW.request_id,NEW.tenant_id,NEW.user_id,NEW.reviewed_by,NEW.activated_at) IS DISTINCT FROM ROW(OLD.request_id,OLD.tenant_id,OLD.user_id,OLD.reviewed_by,OLD.activated_at)
 THEN RAISE EXCEPTION 'Restriction receipts are immutable except verified release' USING ERRCODE='55000';END IF;
 RETURN NEW;
END
$fn$;
ALTER FUNCTION private.guard_source_ingestion_receipt() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.guard_source_ingestion_receipt() FROM PUBLIC;
CREATE TRIGGER source_ingestion_receipt_guard BEFORE UPDATE OR DELETE ON private.source_ingestion_restrictions FOR EACH ROW EXECUTE FUNCTION private.guard_source_ingestion_receipt();

ALTER FUNCTION private.privacy_restore_state() RENAME TO privacy_restore_state_before_ingestion_restriction;
CREATE FUNCTION private.privacy_restore_state() RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
 SELECT jsonb_build_object('markers',s.state->'markers'||COALESCE((
 SELECT jsonb_agg(marker ORDER BY marker->>'id',marker->>'kind') FROM (
 SELECT jsonb_build_object('kind','source_ingestion_restricted','id',r.request_id,'tenantId',r.tenant_id,'userId',r.user_id,'at',extract(epoch FROM r.activated_at)::text) AS marker FROM private.source_ingestion_restrictions r
 UNION ALL SELECT jsonb_build_object('kind','source_ingestion_released','id',r.release_request_id,'tenantId',r.tenant_id,'userId',r.user_id,'at',extract(epoch FROM r.released_at)::text) FROM private.source_ingestion_restrictions r WHERE r.released_at IS NOT NULL
 ) x),'[]'::jsonb),'violations',s.state->'violations')
 FROM (SELECT private.privacy_restore_state_before_ingestion_restriction() AS state) s
$fn$;
ALTER FUNCTION private.privacy_restore_state() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.privacy_restore_state(),private.privacy_restore_state_before_ingestion_restriction() FROM PUBLIC,profitpilot_app;
COMMIT;
