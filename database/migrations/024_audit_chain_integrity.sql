-- Make financial audit entries database-generated and chain them per tenant.
-- A privileged database owner can still rewrite the entire chain: independent
-- offsite head checkpoints are required for production tamper evidence.
BEGIN;
REVOKE INSERT,UPDATE,DELETE,TRUNCATE ON public.audit_events FROM profitpilot_app;
CREATE TABLE private.audit_chain_heads(
 tenant_id uuid PRIMARY KEY REFERENCES public.tenants(id),
 entry_count bigint NOT NULL CHECK(entry_count>=0),
 head_hash text NOT NULL CHECK(head_hash ~ '^[a-f0-9]{64}$')
);
CREATE TABLE private.audit_chain_entries(
 tenant_id uuid NOT NULL REFERENCES public.tenants(id),
 sequence_no bigint NOT NULL CHECK(sequence_no>0),
 event_id uuid NOT NULL UNIQUE REFERENCES public.audit_events(id),
 previous_hash text NOT NULL CHECK(previous_hash ~ '^[a-f0-9]{64}$'),
 event_hash text NOT NULL CHECK(event_hash ~ '^[a-f0-9]{64}$'),
 PRIMARY KEY(tenant_id,sequence_no)
);
REVOKE ALL ON private.audit_chain_heads,private.audit_chain_entries FROM PUBLIC,profitpilot_app;

CREATE FUNCTION private.audit_hash(p_previous text,p_seq bigint,p_event public.audit_events)
RETURNS text LANGUAGE sql STABLE SET search_path=pg_catalog SET timezone='UTC' AS $fn$
 SELECT encode(public.digest(convert_to('profitpilot-audit-v1:'||p_previous||':'||p_seq::text||':'||to_jsonb(p_event)::text,'UTF8'),'sha256'),'hex')
$fn$;

CREATE FUNCTION private.append_audit_chain(p_event public.audit_events)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE h private.audit_chain_heads%ROWTYPE; next_hash text;
BEGIN
 INSERT INTO private.audit_chain_heads(tenant_id,entry_count,head_hash)
 VALUES(p_event.tenant_id,0,repeat('0',64)) ON CONFLICT(tenant_id) DO NOTHING;
 SELECT * INTO h FROM private.audit_chain_heads WHERE tenant_id=p_event.tenant_id FOR UPDATE;
 next_hash:=private.audit_hash(h.head_hash,h.entry_count+1,p_event);
 INSERT INTO private.audit_chain_entries(tenant_id,sequence_no,event_id,previous_hash,event_hash)
 VALUES(p_event.tenant_id,h.entry_count+1,p_event.id,h.head_hash,next_hash);
 UPDATE private.audit_chain_heads SET entry_count=h.entry_count+1,head_hash=next_hash WHERE tenant_id=p_event.tenant_id;
END $fn$;

-- Deterministic initialization for existing audit records.
DO $backfill$
DECLARE e public.audit_events%ROWTYPE;
BEGIN
 LOCK TABLE public.audit_events IN ACCESS EXCLUSIVE MODE;
 FOR e IN SELECT * FROM public.audit_events ORDER BY tenant_id,created_at,id LOOP
  PERFORM private.append_audit_chain(e);
 END LOOP;
END $backfill$;
CREATE FUNCTION private.chain_new_audit_event()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 PERFORM private.append_audit_chain(NEW);
 RETURN NEW;
END $fn$;
CREATE TRIGGER audit_event_chain AFTER INSERT ON public.audit_events
 FOR EACH ROW EXECUTE FUNCTION private.chain_new_audit_event();

CREATE FUNCTION private.deny_audit_mutation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 RAISE EXCEPTION 'Audit evidence is append-only' USING ERRCODE='55000';
END $fn$;
CREATE TRIGGER audit_event_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON public.audit_events
 FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE TRIGGER audit_chain_entry_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.audit_chain_entries
 FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE TRIGGER audit_chain_head_no_delete BEFORE DELETE OR TRUNCATE ON private.audit_chain_heads
 FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();

-- The existing match decision validator is still an invoker trigger. Only the
-- audit insertion itself becomes privileged; callers cannot invoke it directly.
CREATE OR REPLACE FUNCTION private.audit_match_review_decision()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 IF session_user<>'profitpilot_app' THEN RETURN NEW; END IF;
 IF private.current_tenant_id() IS DISTINCT FROM NEW.tenant_id THEN
  RAISE EXCEPTION 'Audit tenant authority denied' USING ERRCODE='42501';
 END IF;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES(NEW.tenant_id,NEW.reviewer_id,'invoice_match_decision','match_review',NEW.id,
 nullif(current_setting('app.audit_reason',true),''),jsonb_build_object('previousDecision',OLD.decision,'decision',NEW.decision));
 RETURN NEW;
END $fn$;

CREATE FUNCTION private.audit_calculation_creation()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE actor uuid;
BEGIN
 IF session_user<>'profitpilot_app' THEN RETURN NEW; END IF;
 IF private.current_tenant_id() IS DISTINCT FROM NEW.tenant_id OR
 coalesce(private.current_actor_role(),'') NOT IN ('owner','admin','analyst','reviewer') THEN
  RAISE EXCEPTION 'Calculation authority denied' USING ERRCODE='42501';
 END IF;
 SELECT id INTO actor FROM public.users WHERE auth_subject=nullif(current_setting('app.tenant_subject',true),'') AND status='active';
 IF actor IS NULL OR actor IS DISTINCT FROM NEW.created_by THEN
  RAISE EXCEPTION 'Calculation actor must match authenticated identity' USING ERRCODE='42501';
 END IF;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason,metadata)
 VALUES(NEW.tenant_id,actor,'calculation_created','calculation_run',NEW.id,'Versioned management contribution calculation',
 jsonb_build_object('formulaVersion',NEW.formula_version,'periodStart',NEW.period_start,'periodEnd',NEW.period_end));
 RETURN NEW;
END $fn$;
CREATE TRIGGER calculation_creation_audit AFTER INSERT ON public.calculation_runs
 FOR EACH ROW EXECUTE FUNCTION private.audit_calculation_creation();

CREATE FUNCTION private.verify_audit_chain(p_tenant uuid)
RETURNS boolean LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $fn$
DECLARE h private.audit_chain_heads%ROWTYPE; prior text:=repeat('0',64); n bigint:=0; r record;
BEGIN
 IF p_tenant IS NULL THEN RETURN false; END IF;
 SELECT * INTO h FROM private.audit_chain_heads WHERE tenant_id=p_tenant;
 IF NOT FOUND THEN RETURN NOT EXISTS(SELECT 1 FROM public.audit_events WHERE tenant_id=p_tenant)
 AND NOT EXISTS(SELECT 1 FROM private.audit_chain_entries WHERE tenant_id=p_tenant); END IF;
 FOR r IN SELECT c.sequence_no,c.previous_hash,c.event_hash,e AS event_row
 FROM private.audit_chain_entries c JOIN public.audit_events e ON e.id=c.event_id
 WHERE c.tenant_id=p_tenant AND e.tenant_id=p_tenant ORDER BY c.sequence_no LOOP
  n:=n+1;
  IF r.sequence_no<>n OR r.previous_hash<>prior OR private.audit_hash(prior,n,r.event_row)<>r.event_hash THEN RETURN false; END IF;
  prior:=r.event_hash;
 END LOOP;
 RETURN n=h.entry_count AND prior=h.head_hash
 AND n=(SELECT count(*) FROM public.audit_events WHERE tenant_id=p_tenant)
 AND n=(SELECT count(*) FROM private.audit_chain_entries WHERE tenant_id=p_tenant);
END $fn$;
REVOKE ALL ON FUNCTION private.audit_hash(text,bigint,public.audit_events),private.append_audit_chain(public.audit_events),private.chain_new_audit_event(),private.deny_audit_mutation(),private.audit_match_review_decision(),private.audit_calculation_creation(),private.verify_audit_chain(uuid) FROM PUBLIC,profitpilot_app;
COMMIT;
