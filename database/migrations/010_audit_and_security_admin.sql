-- ProfitPilot migration 010: tamper-evident tenant audit chain and security administration primitives.
-- Apply with the migration administrator. The runtime role receives no direct override DML.
BEGIN;

ALTER TABLE public.audit_events
  ADD COLUMN chain_position bigint,
  ADD COLUMN previous_hash bytea,
  ADD COLUMN event_hash bytea;

CREATE OR REPLACE FUNCTION private.audit_event_digest(
 p_id uuid,p_tenant_id uuid,p_actor_user_id uuid,p_action text,p_object_type text,
 p_object_id uuid,p_reason text,p_correlation_id uuid,p_metadata jsonb,
 p_created_at timestamptz,p_chain_position bigint,p_previous_hash bytea
) RETURNS bytea
LANGUAGE sql IMMUTABLE
SET search_path=pg_catalog,public,private
AS $function$
 SELECT public.digest(convert_to(jsonb_build_object(
  'id',p_id,'tenant_id',p_tenant_id,'actor_user_id',p_actor_user_id,
  'action',p_action,'object_type',p_object_type,'object_id',p_object_id,
  'reason',p_reason,'correlation_id',p_correlation_id,'metadata',p_metadata,
  'created_at',p_created_at,'chain_position',p_chain_position,
  'previous_hash',coalesce(encode(p_previous_hash,'hex'),'')
 )::text,'UTF8'),'sha256')
$function$;
ALTER FUNCTION private.audit_event_digest(uuid,uuid,uuid,text,text,uuid,text,uuid,jsonb,timestamptz,bigint,bytea)
 OWNER TO profitpilot_context_owner;
GRANT SELECT ON public.audit_events TO profitpilot_context_owner;
GRANT SELECT,INSERT,UPDATE,DELETE ON public.tenant_membership_permission_overrides TO profitpilot_context_owner;

DO $backfill$
DECLARE
 tenant_item record;
 event_item record;
 position_value bigint;
 previous_value bytea;
 next_value bytea;
BEGIN
 FOR tenant_item IN SELECT DISTINCT tenant_id FROM public.audit_events ORDER BY tenant_id LOOP
  position_value:=0;
  previous_value:=NULL;
  FOR event_item IN
   SELECT id,tenant_id,actor_user_id,action,object_type,object_id,reason,correlation_id,metadata,created_at
   FROM public.audit_events WHERE tenant_id=tenant_item.tenant_id ORDER BY created_at,id
  LOOP
   position_value:=position_value+1;
   next_value:=private.audit_event_digest(
    event_item.id,event_item.tenant_id,event_item.actor_user_id,event_item.action,
    event_item.object_type,event_item.object_id,event_item.reason,event_item.correlation_id,
    event_item.metadata,event_item.created_at,position_value,previous_value
   );
   UPDATE public.audit_events SET chain_position=position_value,previous_hash=previous_value,event_hash=next_value
    WHERE id=event_item.id;
   previous_value:=next_value;
  END LOOP;
 END LOOP;
END
$backfill$;

ALTER TABLE public.audit_events
 ALTER COLUMN chain_position SET NOT NULL,
 ALTER COLUMN event_hash SET NOT NULL;
ALTER TABLE public.audit_events
 ADD CONSTRAINT audit_events_tenant_chain_position_unique UNIQUE(tenant_id,chain_position);
CREATE INDEX audit_events_chain_lookup_idx ON public.audit_events(tenant_id,chain_position DESC);

CREATE OR REPLACE FUNCTION private.audit_event_chain_insert()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,public,private
AS $function$
DECLARE previous_value bytea;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text,0));
 SELECT event_hash INTO previous_value
 FROM public.audit_events WHERE tenant_id=NEW.tenant_id
 ORDER BY chain_position DESC LIMIT 1;
 SELECT COALESCE(MAX(chain_position),0)+1 INTO NEW.chain_position
 FROM public.audit_events WHERE tenant_id=NEW.tenant_id;
 NEW.previous_hash:=previous_value;
 NEW.created_at:=clock_timestamp();
 NEW.event_hash:=private.audit_event_digest(
  NEW.id,NEW.tenant_id,NEW.actor_user_id,NEW.action,NEW.object_type,NEW.object_id,
  NEW.reason,NEW.correlation_id,NEW.metadata,NEW.created_at,NEW.chain_position,NEW.previous_hash
 );
 RETURN NEW;
END
$function$;
ALTER FUNCTION private.audit_event_chain_insert() OWNER TO profitpilot_context_owner;

CREATE OR REPLACE FUNCTION private.audit_event_immutable()
RETURNS trigger
LANGUAGE plpgsql
SET search_path=pg_catalog
AS $function$
BEGIN
 RAISE EXCEPTION 'Audit events are append-only' USING ERRCODE='55000';
END
$function$;
ALTER FUNCTION private.audit_event_immutable() OWNER TO profitpilot_context_owner;

CREATE TRIGGER audit_events_chain_before_insert
 BEFORE INSERT ON public.audit_events
 FOR EACH ROW EXECUTE FUNCTION private.audit_event_chain_insert();
CREATE TRIGGER audit_events_immutable_before_change
 BEFORE UPDATE OR DELETE ON public.audit_events
 FOR EACH ROW EXECUTE FUNCTION private.audit_event_immutable();

REVOKE UPDATE,DELETE,TRUNCATE ON public.audit_events FROM profitpilot_app;

CREATE OR REPLACE FUNCTION private.verify_audit_chain(p_tenant_id uuid)
RETURNS TABLE(is_valid boolean,event_count bigint,first_invalid_event uuid)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,public,private
AS $function$
DECLARE item record;
 previous_value bytea;
 expected_value bytea;
 total bigint:=0;
BEGIN
 previous_value:=NULL;
 FOR item IN
  SELECT id,tenant_id,actor_user_id,action,object_type,object_id,reason,correlation_id,
         metadata,created_at,chain_position,previous_hash,event_hash
  FROM public.audit_events WHERE tenant_id=p_tenant_id ORDER BY chain_position
 LOOP
  total:=total+1;
  expected_value:=private.audit_event_digest(
   item.id,item.tenant_id,item.actor_user_id,item.action,item.object_type,item.object_id,
   item.reason,item.correlation_id,item.metadata,item.created_at,item.chain_position,previous_value
  );
  IF item.previous_hash IS DISTINCT FROM previous_value OR item.event_hash IS DISTINCT FROM expected_value
     OR item.chain_position<>total THEN
   RETURN QUERY SELECT false,total,item.id;
   RETURN;
  END IF;
  previous_value:=item.event_hash;
 END LOOP;
 RETURN QUERY SELECT true,total,NULL::uuid;
END
$function$;
ALTER FUNCTION private.verify_audit_chain(uuid) OWNER TO profitpilot_context_owner;

INSERT INTO permission_catalog(permission_key,description,sensitive) VALUES
 ('security.permissions.read','View tenant permission catalogue and member overrides',true),
 ('security.audit.read','View and verify tenant security audit history',true)
ON CONFLICT(permission_key) DO NOTHING;
INSERT INTO role_permissions(role,permission_key) VALUES
 ('owner','security.permissions.read'),('admin','security.permissions.read'),
 ('owner','security.audit.read'),('admin','security.audit.read')
ON CONFLICT DO NOTHING;

CREATE OR REPLACE FUNCTION private.set_member_permission_override(
 p_tenant_id uuid,p_actor_user_id uuid,p_target_user_id uuid,
 p_permission_key text,p_effect text,p_reason text
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,public,private
AS $function$
DECLARE verified_actor uuid;
BEGIN
 IF private.current_tenant_id() IS DISTINCT FROM p_tenant_id THEN
  RAISE EXCEPTION 'Tenant context mismatch' USING ERRCODE='42501';
 END IF;
 SELECT id INTO verified_actor FROM public.users
 WHERE auth_subject=current_setting('app.tenant_subject',true) AND status='active';
 IF verified_actor IS NULL OR verified_actor<>p_actor_user_id THEN
  RAISE EXCEPTION 'Actor identity mismatch' USING ERRCODE='42501';
 END IF;
 IF p_permission_key LIKE 'security.%' OR p_permission_key LIKE 'privacy.%' THEN
  RAISE EXCEPTION 'Security and privacy administration permissions cannot be overridden' USING ERRCODE='42501';
 END IF;
 IF p_effect NOT IN ('grant','deny') OR p_reason IS NULL OR length(btrim(p_reason)) NOT BETWEEN 3 AND 1000 THEN
  RAISE EXCEPTION 'Invalid permission override' USING ERRCODE='22023';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM public.tenant_memberships
               WHERE tenant_id=p_tenant_id AND user_id=p_actor_user_id AND role='owner' AND status='active') THEN
  RAISE EXCEPTION 'Active tenant owner required' USING ERRCODE='42501';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM public.tenant_memberships tm JOIN public.users u ON u.id=tm.user_id
               WHERE tm.tenant_id=p_tenant_id AND tm.user_id=p_target_user_id
                 AND tm.status='active' AND u.status='active') THEN
  RAISE EXCEPTION 'Active target membership required' USING ERRCODE='22023';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM public.permission_catalog WHERE permission_key=p_permission_key) THEN
  RAISE EXCEPTION 'Unknown permission' USING ERRCODE='22023';
 END IF;
 INSERT INTO public.tenant_membership_permission_overrides
  (tenant_id,user_id,permission_key,effect,reason,granted_by)
 VALUES(p_tenant_id,p_target_user_id,p_permission_key,p_effect,btrim(p_reason),p_actor_user_id)
 ON CONFLICT(tenant_id,user_id,permission_key) DO UPDATE
 SET effect=EXCLUDED.effect,reason=EXCLUDED.reason,granted_by=EXCLUDED.granted_by,created_at=clock_timestamp();
END
$function$;
ALTER FUNCTION private.set_member_permission_override(uuid,uuid,uuid,text,text,text)
 OWNER TO profitpilot_context_owner;

CREATE OR REPLACE FUNCTION private.remove_member_permission_override(
 p_tenant_id uuid,p_actor_user_id uuid,p_target_user_id uuid,p_permission_key text
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,public,private
AS $function$
DECLARE verified_actor uuid;
DECLARE changed integer;
BEGIN
 IF private.current_tenant_id() IS DISTINCT FROM p_tenant_id THEN
  RAISE EXCEPTION 'Tenant context mismatch' USING ERRCODE='42501';
 END IF;
 SELECT id INTO verified_actor FROM public.users
 WHERE auth_subject=current_setting('app.tenant_subject',true) AND status='active';
 IF verified_actor IS NULL OR verified_actor<>p_actor_user_id THEN
  RAISE EXCEPTION 'Actor identity mismatch' USING ERRCODE='42501';
 END IF;
 IF NOT EXISTS(SELECT 1 FROM public.tenant_memberships
               WHERE tenant_id=p_tenant_id AND user_id=p_actor_user_id AND role='owner' AND status='active') THEN
  RAISE EXCEPTION 'Active tenant owner required' USING ERRCODE='42501';
 END IF;
 DELETE FROM public.tenant_membership_permission_overrides
 WHERE tenant_id=p_tenant_id AND user_id=p_target_user_id AND permission_key=p_permission_key
   AND permission_key NOT LIKE 'security.%' AND permission_key NOT LIKE 'privacy.%';
 GET DIAGNOSTICS changed=ROW_COUNT;
 RETURN changed=1;
END
$function$;
ALTER FUNCTION private.remove_member_permission_override(uuid,uuid,uuid,text)
 OWNER TO profitpilot_context_owner;

REVOKE ALL ON FUNCTION private.verify_audit_chain(uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION private.set_member_permission_override(uuid,uuid,uuid,text,text,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION private.remove_member_permission_override(uuid,uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION private.verify_audit_chain(uuid) TO profitpilot_app;
GRANT EXECUTE ON FUNCTION private.set_member_permission_override(uuid,uuid,uuid,text,text,text) TO profitpilot_app;
GRANT EXECUTE ON FUNCTION private.remove_member_permission_override(uuid,uuid,uuid,text) TO profitpilot_app;

COMMIT;
