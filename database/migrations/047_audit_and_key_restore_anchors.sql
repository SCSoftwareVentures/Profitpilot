-- Independent restore checkpoints cover retired signing keys and retained audit prefixes.
BEGIN;
-- Avoid timezone-dependent hashes on new events. Historical non-UTC hashes require
-- reviewed reconciliation; never silently rewrite an audit history.
ALTER FUNCTION private.audit_event_digest(uuid,uuid,uuid,text,text,uuid,text,uuid,jsonb,timestamptz,bigint,bytea) SET timezone TO 'UTC';
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON public.audit_events FOR EACH STATEMENT EXECUTE FUNCTION private.audit_event_immutable();

CREATE TABLE private.audit_restore_anchors(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL REFERENCES public.tenants(id) ON DELETE RESTRICT,
 chain_position bigint NOT NULL CHECK(chain_position>0),
 event_hash bytea NOT NULL CHECK(octet_length(event_hash)=32),
 captured_at timestamptz NOT NULL CHECK(isfinite(captured_at)),
 UNIQUE(tenant_id,chain_position)
);
ALTER TABLE private.audit_restore_anchors OWNER TO profitpilot_context_owner;
REVOKE ALL ON private.audit_restore_anchors FROM PUBLIC,profitpilot_app;
CREATE FUNCTION private.guard_security_restore_anchor() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 RAISE EXCEPTION 'Security restore evidence must be retained' USING ERRCODE='55000';
END
$fn$;
ALTER FUNCTION private.guard_security_restore_anchor() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.guard_security_restore_anchor() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER audit_restore_anchor_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.audit_restore_anchors FOR EACH STATEMENT EXECUTE FUNCTION private.guard_security_restore_anchor();
CREATE TRIGGER tenant_key_no_truncate BEFORE TRUNCATE ON private.tenant_context_keys FOR EACH STATEMENT EXECUTE FUNCTION private.guard_security_restore_anchor();

CREATE FUNCTION private.capture_audit_restore_anchors() RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
DECLARE item record; n integer;
BEGIN
 -- Capture must use one snapshot across validation and insertion.
 IF current_setting('transaction_isolation') NOT IN ('repeatable read','serializable') THEN
  RAISE EXCEPTION 'Repeatable-read or serializable transaction required' USING ERRCODE='25000';
 END IF;
 FOR item IN SELECT DISTINCT tenant_id FROM public.audit_events ORDER BY tenant_id LOOP
  IF NOT EXISTS(SELECT 1 FROM private.verify_audit_chain(item.tenant_id) v WHERE v.is_valid)
  THEN RAISE EXCEPTION 'Audit history failed verification' USING ERRCODE='55000'; END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM private.audit_restore_anchors r
  LEFT JOIN public.audit_events a ON a.tenant_id=r.tenant_id AND a.chain_position=r.chain_position
  WHERE a.event_hash IS DISTINCT FROM r.event_hash)
 THEN RAISE EXCEPTION 'Existing audit anchor does not match retained history' USING ERRCODE='55000'; END IF;
 INSERT INTO private.audit_restore_anchors(tenant_id,chain_position,event_hash,captured_at)
 SELECT DISTINCT ON (tenant_id) tenant_id,chain_position,event_hash,clock_timestamp()
 FROM public.audit_events ORDER BY tenant_id,chain_position DESC
 ON CONFLICT(tenant_id,chain_position) DO NOTHING;
 GET DIAGNOSTICS n=ROW_COUNT;
 RETURN n;
END
$fn$;
ALTER FUNCTION private.capture_audit_restore_anchors() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.capture_audit_restore_anchors() FROM PUBLIC,profitpilot_app;

ALTER FUNCTION private.privacy_restore_state() RENAME TO privacy_restore_state_before_audit_key_anchors;
CREATE FUNCTION private.privacy_restore_state() RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
 SELECT jsonb_build_object(
  'markers',s.state->'markers'||COALESCE((
   SELECT jsonb_agg(marker ORDER BY marker->>'kind',marker->>'id') FROM (
    SELECT jsonb_build_object('kind','audit_restore_anchor','id',r.id,'tenantId',r.tenant_id,
    'position',r.chain_position::text,'eventHash',encode(r.event_hash,'hex'),'at',extract(epoch FROM r.captured_at)::text) AS marker
    FROM private.audit_restore_anchors r
    UNION ALL
    SELECT jsonb_build_object('kind','signing_key_retired','id',encode(public.digest(convert_to(k.key_id,'UTF8'),'sha256'),'hex'),
     'fingerprint',encode(k.key_fingerprint,'hex'),'at',extract(epoch FROM k.revoked_at)::text)
    FROM private.tenant_context_keys k WHERE NOT k.active AND k.revoked_at IS NOT NULL
   ) m
  ),'[]'::jsonb),
  'violations',s.state->'violations'||COALESCE((
   SELECT jsonb_agg(item ORDER BY item->>'kind',item->>'id') FROM (
    SELECT jsonb_build_object('kind','audit_anchor_mismatch','id',r.id) AS item
    FROM private.audit_restore_anchors r LEFT JOIN public.audit_events a
      ON a.tenant_id=r.tenant_id AND a.chain_position=r.chain_position
    WHERE a.event_hash IS DISTINCT FROM r.event_hash
    UNION ALL
    SELECT jsonb_build_object('kind','audit_chain_inconsistent','id',t.tenant_id)
    FROM (SELECT DISTINCT tenant_id FROM public.audit_events) t
    CROSS JOIN LATERAL private.verify_audit_chain(t.tenant_id) v WHERE NOT v.is_valid
    UNION ALL
    SELECT jsonb_build_object('kind','signing_key_material_mismatch','id',encode(public.digest(convert_to(k.key_id,'UTF8'),'sha256'),'hex'))
    FROM private.tenant_context_keys k
    WHERE (k.active AND (k.secret IS NULL OR public.digest(k.secret,'sha256') IS DISTINCT FROM k.key_fingerprint OR k.revoked_at IS NOT NULL))
     OR (NOT k.active AND (k.secret IS NOT NULL OR k.revoked_at IS NULL))
   ) x
  ),'[]'::jsonb))
 FROM (SELECT private.privacy_restore_state_before_audit_key_anchors() AS state) s
$fn$;
ALTER FUNCTION private.privacy_restore_state() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.privacy_restore_state(),private.privacy_restore_state_before_audit_key_anchors() FROM PUBLIC,profitpilot_app;
COMMIT;
