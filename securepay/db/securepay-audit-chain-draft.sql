-- Sandbox tamper-evident audit trail. External checkpoint custody is still required.
BEGIN;
CREATE ROLE securepay_audit_runtime NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
GRANT USAGE ON SCHEMA securepay_private TO securepay_audit_runtime;
CREATE TABLE securepay_private.audit_chain_heads(
 tenant_id uuid PRIMARY KEY, last_seq bigint NOT NULL CHECK(last_seq>=0),
 last_hash text NOT NULL CHECK(last_hash ~ '^[a-f0-9]{64}$')
);
CREATE TABLE securepay_private.audit_chain(
 tenant_id uuid NOT NULL, seq bigint NOT NULL CHECK(seq>0),
 source text NOT NULL CHECK(source ~ '^[a-z_]{1,64}$'),
 operation text NOT NULL CHECK(operation IN ('INSERT','UPDATE','DELETE','READ')),
 row_digest text NOT NULL CHECK(row_digest ~ '^[a-f0-9]{64}$'),
 occurred_us bigint NOT NULL CHECK(occurred_us>0),
 prev_hash text NOT NULL CHECK(prev_hash ~ '^[a-f0-9]{64}$'),
 entry_hash text NOT NULL CHECK(entry_hash ~ '^[a-f0-9]{64}$'),
 PRIMARY KEY(tenant_id,seq)
);
ALTER TABLE securepay_private.audit_chain_heads OWNER TO securepay_context_owner;
ALTER TABLE securepay_private.audit_chain OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.audit_chain_heads,securepay_private.audit_chain FROM PUBLIC,securepay_audit_runtime;
CREATE FUNCTION securepay_private.append_audit_chain(t uuid,src text,op text,row_hash text) RETURNS void
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE n bigint; prior text; h text; us bigint;
BEGIN
 IF t IS NULL THEN RAISE EXCEPTION 'Missing audit tenant'; END IF;
 INSERT INTO securepay_private.audit_chain_heads(tenant_id,last_seq,last_hash) VALUES(t,0,repeat('0',64)) ON CONFLICT DO NOTHING;
 SELECT last_seq+1,last_hash INTO n,prior FROM securepay_private.audit_chain_heads WHERE tenant_id=t FOR UPDATE;
 us:=floor(extract(epoch FROM clock_timestamp())*1000000)::bigint;
 h:=encode(public.digest(convert_to(concat_ws('|','sp-audit-v1',t,n,prior,src,op,row_hash,us),'UTF8'),'sha256'),'hex');
 INSERT INTO securepay_private.audit_chain(tenant_id,seq,source,operation,row_digest,occurred_us,prev_hash,entry_hash)
 VALUES(t,n,src,op,row_hash,us,prior,h);
 UPDATE securepay_private.audit_chain_heads SET last_seq=n,last_hash=h WHERE tenant_id=t;
END $$;
ALTER FUNCTION securepay_private.append_audit_chain(uuid,text,text,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.append_audit_chain(uuid,text,text,text) FROM PUBLIC;
CREATE FUNCTION securepay_private.capture_audit_chain() RETURNS trigger
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE old_json jsonb; new_json jsonb; row_json jsonb; t uuid; d uuid; h text;
BEGIN
 IF TG_OP<>'INSERT' THEN old_json:=to_jsonb(OLD); END IF;
 IF TG_OP<>'DELETE' THEN new_json:=to_jsonb(NEW); END IF;
 row_json:=coalesce(new_json,old_json);
 t:=(row_json->>'tenant_id')::uuid;
 IF t IS NULL THEN
  d:=(row_json->>'case_id')::uuid;
  SELECT tenant_id INTO t FROM securepay_private.dispute_cases WHERE case_id=d;
 END IF;
 -- Only a hash of old/new rows is retained, never photo bytes or case narratives.
 -- Exclude credential material from this general ledger; use the existing PIN audit events.
 h:=encode(public.digest(convert_to(jsonb_build_array(old_json,new_json)::text,'UTF8'),'sha256'),'hex');
 PERFORM securepay_private.append_audit_chain(t,TG_TABLE_NAME,TG_OP,h);
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
ALTER FUNCTION securepay_private.capture_audit_chain() OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.capture_audit_chain() FROM PUBLIC;
CREATE TRIGGER sp_chain_0 AFTER INSERT OR UPDATE OR DELETE ON securepay_private.audit_events FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE TRIGGER sp_chain_1 AFTER INSERT OR UPDATE OR DELETE ON public.securepay_milestones FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE TRIGGER sp_chain_2 AFTER INSERT OR UPDATE OR DELETE ON public.securepay_release_requests FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE TRIGGER sp_chain_3 AFTER INSERT OR UPDATE OR DELETE ON securepay_private.provider_funding FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE TRIGGER sp_chain_4 AFTER INSERT OR UPDATE OR DELETE ON securepay_private.provider_events FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE TRIGGER sp_chain_5 AFTER INSERT OR UPDATE OR DELETE ON securepay_private.provider_reconciliation FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE TRIGGER sp_chain_6 AFTER INSERT OR UPDATE OR DELETE ON securepay_private.dispute_cases FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE TRIGGER sp_chain_7 AFTER INSERT OR UPDATE OR DELETE ON securepay_private.dispute_events FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE TRIGGER sp_chain_8 AFTER INSERT OR UPDATE OR DELETE ON securepay_private.dispute_settlements FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE TRIGGER sp_chain_9 AFTER INSERT OR UPDATE OR DELETE ON securepay_private.dispute_deadline_events FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE TRIGGER sp_chain_10 AFTER INSERT OR UPDATE OR DELETE ON securepay_private.dispute_photos FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE TRIGGER sp_chain_11 AFTER INSERT OR UPDATE OR DELETE ON securepay_private.dispute_photo_reviewers FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE TRIGGER sp_chain_12 AFTER INSERT OR UPDATE OR DELETE ON securepay_private.recovery_notification_outbox FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
-- Existing records cannot be retroactively claimed as fully audited.
-- Refuse migration with historic financial/credential/evidence activity.
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM securepay_private.audit_events) OR EXISTS(SELECT 1 FROM public.securepay_milestones)
 OR EXISTS(SELECT 1 FROM securepay_private.provider_events) OR EXISTS(SELECT 1 FROM securepay_private.dispute_cases)
 THEN RAISE EXCEPTION 'Existing activity requires reviewed audit baseline'; END IF;
END $$;
CREATE FUNCTION securepay_private.audit_checkpoint(t uuid) RETURNS TABLE(last_seq bigint,last_hash text)
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT coalesce(h.last_seq,0),coalesce(h.last_hash,repeat('0',64))
 FROM (SELECT 1) b LEFT JOIN securepay_private.audit_chain_heads h ON h.tenant_id=t
$$;
CREATE FUNCTION securepay_private.audit_page(t uuid,after_seq bigint,through_seq bigint,page_size integer)
 RETURNS TABLE(seq bigint,source text,operation text,row_digest text,occurred_us bigint,prev_hash text,entry_hash text)
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT a.seq,a.source,a.operation,a.row_digest,a.occurred_us,a.prev_hash,a.entry_hash
 FROM securepay_private.audit_chain a
 WHERE a.tenant_id=t AND after_seq>=0 AND through_seq>=after_seq AND a.seq>after_seq AND a.seq<=through_seq
 AND page_size BETWEEN 1 AND 1000 ORDER BY a.seq LIMIT least(1000,greatest(0,page_size))
$$;
ALTER FUNCTION securepay_private.audit_checkpoint(uuid) OWNER TO securepay_context_owner;
ALTER FUNCTION securepay_private.audit_page(uuid,bigint,bigint,integer) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.audit_checkpoint(uuid),securepay_private.audit_page(uuid,bigint,bigint,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.audit_checkpoint(uuid),securepay_private.audit_page(uuid,bigint,bigint,integer) TO securepay_audit_runtime;
COMMIT;
