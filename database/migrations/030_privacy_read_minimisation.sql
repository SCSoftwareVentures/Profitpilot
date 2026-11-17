-- Remove broad manager narrative access from ordinary runtime SQL.
BEGIN;
DROP POLICY privacy_requests_subject_read ON public.privacy_requests;
CREATE POLICY privacy_requests_subject_read ON public.privacy_requests FOR SELECT
 USING (tenant_id=private.current_tenant_id() AND subject_user_id=private.current_user_id());

CREATE FUNCTION private.read_privacy_queue(p_tenant uuid,p_auth_time bigint,p_proof text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE actor uuid; items jsonb;
BEGIN
 actor:=private.assert_privacy_step_up(p_tenant,p_tenant,'read_privacy_queue',p_auth_time,p_proof);
 IF NOT private.can_manage_privacy_requests() THEN RAISE EXCEPTION 'Privacy manager required' USING ERRCODE='42501'; END IF;
 SELECT COALESCE(jsonb_agg(to_jsonb(q) ORDER BY q.created_at DESC,q.id DESC),'[]'::jsonb) INTO items
 FROM (SELECT id,subject_user_id,request_type,status,assigned_to,created_at,updated_at,resolved_at,account_confirmed_at,details_redacted_at
  FROM public.privacy_requests WHERE tenant_id=p_tenant ORDER BY created_at DESC,id DESC LIMIT 201) q;
 RETURN jsonb_build_object('items',CASE WHEN jsonb_array_length(items)>200 THEN items-200 ELSE items END,
  'truncated',jsonb_array_length(items)>200,'scope','metadata_only');
END
$fn$;
ALTER FUNCTION private.read_privacy_queue(uuid,bigint,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.read_privacy_queue(uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.read_privacy_queue(uuid,bigint,text) TO profitpilot_app;

CREATE FUNCTION private.read_privacy_details(p_tenant uuid,p_request uuid,p_purpose text,p_auth_time bigint,p_proof text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE actor uuid; result jsonb; purpose text;
BEGIN
 purpose:=btrim(p_purpose);
 IF purpose IS NULL OR length(purpose) NOT BETWEEN 3 AND 500 OR p_purpose ~ '[[:cntrl:]]' THEN RAISE EXCEPTION 'Access purpose required' USING ERRCODE='22023'; END IF;
 actor:=private.assert_privacy_step_up(p_tenant,p_request,'read_privacy_details:'||encode(public.digest(convert_to(purpose,'UTF8'),'sha256'),'hex'),p_auth_time,p_proof);
 IF NOT private.can_manage_privacy_requests() THEN RAISE EXCEPTION 'Privacy manager required' USING ERRCODE='42501'; END IF;
 SELECT jsonb_build_object('id',id,'subject_user_id',subject_user_id,'request_type',request_type,'status',status,
  'details',details,'resolution_summary',resolution_summary,'legal_hold_reason',legal_hold_reason,'details_redacted_at',details_redacted_at)
 INTO result FROM public.privacy_requests WHERE tenant_id=p_tenant AND id=p_request FOR SHARE;
 IF NOT FOUND THEN RETURN jsonb_build_object('status',404,'error','Privacy request not found'); END IF;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES(p_tenant,actor,'privacy_request_details_read','privacy_request',p_request,'Manager accessed a specific privacy request',
  jsonb_build_object('purpose',purpose));
 RETURN jsonb_build_object('status',200,'item',result);
END
$fn$;
ALTER FUNCTION private.read_privacy_details(uuid,uuid,text,bigint,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.read_privacy_details(uuid,uuid,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.read_privacy_details(uuid,uuid,text,bigint,text) TO profitpilot_app;
COMMIT;
