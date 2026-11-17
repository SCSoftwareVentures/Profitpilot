-- Audit narratives remain inaccessible to direct runtime SQL.
BEGIN;
GRANT SELECT ON public.role_permissions TO profitpilot_context_owner;
CREATE FUNCTION private.has_scoped_permission(p_tenant uuid,p_permission text)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
 SELECT p_tenant=private.current_tenant_id() AND EXISTS(
  SELECT 1 FROM public.tenant_memberships tm JOIN public.users u ON u.id=tm.user_id
  JOIN public.tenants t ON t.id=tm.tenant_id
  WHERE tm.tenant_id=p_tenant AND tm.user_id=private.current_user_id()
   AND tm.status='active' AND u.status='active' AND t.status='active'
   AND NOT EXISTS(SELECT 1 FROM public.tenant_membership_permission_overrides o
    WHERE o.tenant_id=p_tenant AND o.user_id=tm.user_id AND o.permission_key=p_permission AND o.effect='deny')
   AND (EXISTS(SELECT 1 FROM public.tenant_membership_permission_overrides o
    WHERE o.tenant_id=p_tenant AND o.user_id=tm.user_id AND o.permission_key=p_permission AND o.effect='grant')
    OR EXISTS(SELECT 1 FROM public.role_permissions r WHERE r.role=tm.role AND r.permission_key=p_permission))
 )
$fn$;
ALTER FUNCTION private.has_scoped_permission(uuid,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.has_scoped_permission(uuid,text) FROM PUBLIC,profitpilot_app;

CREATE FUNCTION private.read_audit_summary(p_tenant uuid,p_limit integer,p_auth_time bigint,p_proof text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE actor uuid; integrity jsonb; items jsonb;
BEGIN
 IF p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 100 THEN RAISE EXCEPTION 'Invalid audit limit' USING ERRCODE='22023'; END IF;
 actor:=private.assert_privacy_step_up(p_tenant,p_tenant,'read_audit_summary:'||p_limit,p_auth_time,p_proof);
 IF private.has_scoped_permission(p_tenant,'security.audit.read') IS DISTINCT FROM true THEN RAISE EXCEPTION 'Audit permission required' USING ERRCODE='42501'; END IF;
 SELECT jsonb_build_object('is_valid',v.is_valid,'event_count',v.event_count::text,'first_invalid_event',v.first_invalid_event)
 INTO integrity FROM private.verify_audit_chain(p_tenant) v;
 SELECT COALESCE(jsonb_agg(to_jsonb(q) ORDER BY q.chain_position::bigint DESC),'[]'::jsonb) INTO items
 FROM (SELECT id,actor_user_id,action,object_type,object_id,correlation_id,created_at,chain_position::text AS chain_position,
  encode(previous_hash,'hex') AS previous_hash,encode(event_hash,'hex') AS event_hash
  FROM public.audit_events WHERE tenant_id=p_tenant ORDER BY audit_events.chain_position DESC LIMIT p_limit) q;
 RETURN jsonb_build_object('integrity',integrity,'items',items,'scope','audit_metadata_only');
END
$fn$;
-- Sort before casting the position to text, or lexical ordering would be incorrect.
ALTER FUNCTION private.read_audit_summary(uuid,integer,bigint,text) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.read_audit_summary(uuid,integer,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.read_audit_summary(uuid,integer,bigint,text) TO profitpilot_app;

CREATE FUNCTION private.read_invoice_manifest_events(p_tenant uuid,p_batch uuid)
RETURNS TABLE(metadata jsonb) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
BEGIN
 IF private.has_scoped_permission(p_tenant,'matching.decide') IS DISTINCT FROM true
 OR private.has_scoped_permission(p_tenant,'payroll.allocations.read') IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'Financial review permissions required' USING ERRCODE='42501';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM public.import_batches b WHERE b.tenant_id=p_tenant AND b.id=p_batch
  AND b.source_type IN ('customer_invoice','supplier_invoice')) THEN RETURN; END IF;
 RETURN QUERY SELECT jsonb_build_object('rowCount',a.metadata->'rowCount','manifest',a.metadata->'manifest')
 FROM public.audit_events a WHERE a.tenant_id=p_tenant AND a.object_id=p_batch
 AND a.action='invoice_batch_prepared' AND a.object_type='import_batch' ORDER BY a.chain_position LIMIT 2;
END
$fn$;
GRANT SELECT ON public.import_batches TO profitpilot_context_owner;
ALTER FUNCTION private.read_invoice_manifest_events(uuid,uuid) OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.read_invoice_manifest_events(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.read_invoice_manifest_events(uuid,uuid) TO profitpilot_app;
REVOKE SELECT ON public.audit_events FROM PUBLIC,profitpilot_app;
REVOKE EXECUTE ON FUNCTION private.verify_audit_chain(uuid) FROM PUBLIC,profitpilot_app;
COMMIT;
