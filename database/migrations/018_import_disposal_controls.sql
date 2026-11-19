-- Narrow, operator-controlled disposal: rejected/failed invoice staging only.
-- Never deletes payroll, reviewed evidence, financial ledgers or audit events.
BEGIN;
CREATE TABLE private.import_disposal_controls (
 tenant_id uuid NOT NULL,
 batch_id uuid NOT NULL,
 hold_active boolean NOT NULL DEFAULT false,
 retention_until timestamptz,
 approval_ref text,
 PRIMARY KEY(tenant_id,batch_id)
);
CREATE TABLE private.import_disposal_events (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 tenant_id uuid NOT NULL,
 batch_id uuid NOT NULL,
 action text NOT NULL CHECK(action IN ('hold','release','approve','dispose','replay')),
 authority_ref text NOT NULL,
 operator_name text NOT NULL DEFAULT session_user,
 occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
-- No FK to the deleted batch: minimal tombstones must survive disposal.
CREATE TABLE private.import_disposal_tombstones (
 tenant_id uuid NOT NULL,
 batch_id uuid NOT NULL,
 file_sha256 text NOT NULL CHECK(file_sha256 ~ '^[a-f0-9]{64}$'),
 authority_ref text NOT NULL,
 disposed_at timestamptz NOT NULL,
 PRIMARY KEY(tenant_id,batch_id),
 UNIQUE(tenant_id,file_sha256)
);
REVOKE ALL ON private.import_disposal_controls,private.import_disposal_events,private.import_disposal_tombstones FROM PUBLIC,profitpilot_app;

CREATE FUNCTION private.disposal_reference_valid(p_ref text)
RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 SELECT coalesce(p_ref ~ '^[A-Za-z][A-Za-z0-9_-]{2,63}$',false)
$$;

-- Serialize every hold, approval, disposal and replay against the batch row.
CREATE FUNCTION private.set_import_disposal_hold(p_tenant uuid,p_batch uuid,p_active boolean,p_ref text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF p_active IS NULL OR NOT private.disposal_reference_valid(p_ref) THEN RAISE EXCEPTION 'Invalid hold authority'; END IF;
 PERFORM 1 FROM public.import_batches WHERE tenant_id=p_tenant AND id=p_batch FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Batch not found'; END IF;
 IF NOT p_active AND NOT EXISTS(SELECT 1 FROM private.import_disposal_controls WHERE tenant_id=p_tenant AND batch_id=p_batch AND hold_active) THEN RAISE EXCEPTION 'No active hold to release'; END IF;
 INSERT INTO private.import_disposal_controls(tenant_id,batch_id,hold_active)
 VALUES(p_tenant,p_batch,p_active)
 ON CONFLICT(tenant_id,batch_id) DO UPDATE SET hold_active=EXCLUDED.hold_active,approval_ref=NULL,retention_until=NULL;
 INSERT INTO private.import_disposal_events(tenant_id,batch_id,action,authority_ref)
 VALUES(p_tenant,p_batch,CASE WHEN p_active THEN 'hold' ELSE 'release' END,p_ref);
END $$;

CREATE FUNCTION private.approve_import_disposal(p_tenant uuid,p_batch uuid,p_until timestamptz,p_ref text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE kind text; state text;
BEGIN
 IF p_until IS NULL OR NOT isfinite(p_until) OR NOT private.disposal_reference_valid(p_ref) THEN RAISE EXCEPTION 'Invalid retention approval'; END IF;
 SELECT source_type,status INTO kind,state FROM public.import_batches WHERE tenant_id=p_tenant AND id=p_batch FOR UPDATE;
 IF NOT FOUND OR kind NOT IN ('customer_invoice','supplier_invoice') OR state NOT IN ('failed','rejected') THEN
  RAISE EXCEPTION 'Only rejected or failed invoice staging is eligible';
 END IF;
 IF EXISTS(SELECT 1 FROM private.import_disposal_controls WHERE tenant_id=p_tenant AND batch_id=p_batch AND hold_active) THEN
  RAISE EXCEPTION 'Active legal hold blocks disposal approval';
 END IF;
 INSERT INTO private.import_disposal_controls(tenant_id,batch_id,hold_active,retention_until,approval_ref)
 VALUES(p_tenant,p_batch,false,p_until,p_ref)
 ON CONFLICT(tenant_id,batch_id) DO UPDATE SET retention_until=EXCLUDED.retention_until,approval_ref=EXCLUDED.approval_ref;
 INSERT INTO private.import_disposal_events(tenant_id,batch_id,action,authority_ref) VALUES(p_tenant,p_batch,'approve',p_ref);
END $$;

-- Recheck all evidence links on each destructive attempt. Foreign keys guard
-- concurrent links not visible to the check; the whole transaction rolls back.
CREATE FUNCTION private.assert_disposable_import(p_tenant uuid,p_batch uuid)
RETURNS text LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE batch public.import_batches%ROWTYPE;
BEGIN
 SELECT * INTO batch FROM public.import_batches WHERE tenant_id=p_tenant AND id=p_batch FOR UPDATE;
 IF NOT FOUND OR batch.source_type NOT IN ('customer_invoice','supplier_invoice') OR batch.status NOT IN ('failed','rejected') THEN
  RAISE EXCEPTION 'Only rejected or failed invoice staging is eligible';
 END IF;
 IF EXISTS(SELECT 1 FROM private.import_disposal_controls WHERE tenant_id=p_tenant AND batch_id=p_batch AND hold_active) THEN RAISE EXCEPTION 'Active legal hold blocks disposal'; END IF;
 IF EXISTS(SELECT 1 FROM public.payroll_pools WHERE tenant_id=p_tenant AND batch_id=p_batch)
 OR EXISTS(SELECT 1 FROM public.raw_import_rows r JOIN public.mapping_decisions m ON m.tenant_id=r.tenant_id AND m.raw_row_id=r.id WHERE r.tenant_id=p_tenant AND r.batch_id=p_batch)
 OR EXISTS(SELECT 1 FROM public.raw_import_rows r JOIN public.invoice_lines i ON i.tenant_id=r.tenant_id AND i.source_row_id=r.id WHERE r.tenant_id=p_tenant AND r.batch_id=p_batch)
 OR EXISTS(SELECT 1 FROM public.raw_import_rows r JOIN public.payroll_source_rows p ON p.tenant_id=r.tenant_id AND p.raw_import_row_id=r.id WHERE r.tenant_id=p_tenant AND r.batch_id=p_batch)
 OR EXISTS(SELECT 1 FROM public.audit_events a WHERE a.tenant_id=p_tenant AND (a.object_id=p_batch OR a.object_id IN (SELECT id FROM public.raw_import_rows WHERE tenant_id=p_tenant AND batch_id=p_batch))) THEN
  RAISE EXCEPTION 'Referenced evidence cannot be disposed by the staging workflow';
 END IF;
 RETURN batch.file_sha256;
END $$;

-- Tombstones are admin-only, and checked on every subsequent registration.
CREATE FUNCTION private.guard_disposed_import()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF session_user='profitpilot_app' AND private.current_tenant_id() IS DISTINCT FROM NEW.tenant_id THEN RETURN NEW; END IF;
 IF EXISTS(SELECT 1 FROM private.import_disposal_tombstones WHERE tenant_id=NEW.tenant_id AND (batch_id=NEW.id OR file_sha256=NEW.file_sha256)) THEN
  RAISE EXCEPTION 'Import source was previously disposed' USING ERRCODE='23505';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER import_disposed_guard BEFORE INSERT OR UPDATE ON public.import_batches
 FOR EACH ROW EXECUTE FUNCTION private.guard_disposed_import();

CREATE FUNCTION private.guard_import_batch_delete()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM private.import_disposal_tombstones WHERE tenant_id=OLD.tenant_id AND batch_id=OLD.id AND file_sha256=OLD.file_sha256) THEN
  RAISE EXCEPTION 'Import disposal requires a recorded tombstone';
 END IF;
 IF EXISTS(SELECT 1 FROM private.import_disposal_controls WHERE tenant_id=OLD.tenant_id AND batch_id=OLD.id AND hold_active) THEN RAISE EXCEPTION 'Active legal hold blocks disposal'; END IF;
 RETURN OLD;
END $$;
CREATE TRIGGER import_batch_delete_guard BEFORE DELETE ON public.import_batches
 FOR EACH ROW EXECUTE FUNCTION private.guard_import_batch_delete();

CREATE FUNCTION private.guard_raw_import_delete()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM private.import_disposal_tombstones WHERE tenant_id=OLD.tenant_id AND batch_id=OLD.batch_id) THEN RAISE EXCEPTION 'Raw import disposal requires a recorded tombstone'; END IF;
 IF EXISTS(SELECT 1 FROM private.import_disposal_controls WHERE tenant_id=OLD.tenant_id AND batch_id=OLD.batch_id AND hold_active) THEN RAISE EXCEPTION 'Active legal hold blocks disposal'; END IF;
 RETURN OLD;
END $$;
CREATE TRIGGER raw_import_delete_guard BEFORE DELETE ON public.raw_import_rows
 FOR EACH ROW EXECUTE FUNCTION private.guard_raw_import_delete();

CREATE FUNCTION private.guard_import_terminal_state()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF current_user='profitpilot_app' AND TG_OP='INSERT' THEN
  IF NEW.status<>'registered' THEN RAISE EXCEPTION 'New imports must be registered' USING ERRCODE='42501'; END IF;
  RETURN NEW;
 END IF;
 IF current_user='profitpilot_app' AND (OLD.status IN ('accepted','rejected','failed') OR NEW.status IN ('accepted','rejected','failed')) AND OLD.status IS DISTINCT FROM NEW.status THEN
  RAISE EXCEPTION 'Terminal import states require administrator review' USING ERRCODE='42501';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER import_terminal_state_guard BEFORE INSERT OR UPDATE ON public.import_batches
 FOR EACH ROW EXECUTE FUNCTION private.guard_import_terminal_state();

CREATE FUNCTION private.execute_import_disposal(p_tenant uuid,p_batch uuid)
RETURNS integer LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE digest text; authority text; until_at timestamptz; removed integer;
BEGIN
 digest:=private.assert_disposable_import(p_tenant,p_batch);
 SELECT approval_ref,retention_until INTO authority,until_at FROM private.import_disposal_controls WHERE tenant_id=p_tenant AND batch_id=p_batch;
 IF authority IS NULL OR until_at IS NULL OR until_at>clock_timestamp() THEN RAISE EXCEPTION 'Retention approval missing or not due'; END IF;
 INSERT INTO private.import_disposal_tombstones(tenant_id,batch_id,file_sha256,authority_ref,disposed_at)
 VALUES(p_tenant,p_batch,digest,authority,clock_timestamp());
 DELETE FROM public.raw_import_rows WHERE tenant_id=p_tenant AND batch_id=p_batch;
 GET DIAGNOSTICS removed=ROW_COUNT;
 DELETE FROM public.import_batches WHERE tenant_id=p_tenant AND id=p_batch;
 INSERT INTO private.import_disposal_events(tenant_id,batch_id,action,authority_ref) VALUES(p_tenant,p_batch,'dispose',authority);
 RETURN removed;
END $$;

-- Recovery-only entry point. Caller must supply an authenticated authoritative
-- post-snapshot tombstone from outside the restored database. No public grant.
-- Fail closed if records differ, would violate a hold, or have become evidence.
CREATE FUNCTION private.replay_import_disposal(p_tenant uuid,p_batch uuid,p_digest text,p_ref text,p_disposed timestamptz)
RETURNS integer LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE actual text; removed integer:=0;
BEGIN
 IF p_digest IS NULL OR p_digest !~ '^[a-f0-9]{64}$' OR NOT private.disposal_reference_valid(p_ref) OR p_disposed IS NULL OR NOT isfinite(p_disposed) OR p_disposed>clock_timestamp() THEN RAISE EXCEPTION 'Invalid disposal tombstone'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_tenant::text||':'||p_batch::text,0));
 PERFORM 1 FROM public.import_batches WHERE tenant_id=p_tenant AND id=p_batch FOR UPDATE;
 IF FOUND THEN
  actual:=private.assert_disposable_import(p_tenant,p_batch);
  IF actual<>p_digest THEN RAISE EXCEPTION 'Restored import does not match authoritative tombstone'; END IF;
 END IF;
 IF EXISTS(SELECT 1 FROM private.import_disposal_controls WHERE tenant_id=p_tenant AND batch_id=p_batch AND hold_active) THEN RAISE EXCEPTION 'Active legal hold blocks replay'; END IF;
 IF EXISTS(SELECT 1 FROM public.import_batches WHERE tenant_id=p_tenant AND file_sha256=p_digest AND id<>p_batch) THEN RAISE EXCEPTION 'Restored checksum conflicts with another batch'; END IF;
 INSERT INTO private.import_disposal_tombstones(tenant_id,batch_id,file_sha256,authority_ref,disposed_at)
 VALUES(p_tenant,p_batch,p_digest,p_ref,p_disposed) ON CONFLICT(tenant_id,batch_id) DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM private.import_disposal_tombstones WHERE tenant_id=p_tenant AND batch_id=p_batch AND file_sha256=p_digest AND authority_ref=p_ref AND disposed_at=p_disposed) THEN RAISE EXCEPTION 'Conflicting disposal tombstone'; END IF;
 DELETE FROM public.raw_import_rows WHERE tenant_id=p_tenant AND batch_id=p_batch;
 GET DIAGNOSTICS removed=ROW_COUNT;
 DELETE FROM public.import_batches WHERE tenant_id=p_tenant AND id=p_batch;
 INSERT INTO private.import_disposal_events(tenant_id,batch_id,action,authority_ref) VALUES(p_tenant,p_batch,'replay',p_ref);
 RETURN removed;
END $$;

REVOKE ALL ON FUNCTION private.disposal_reference_valid(text),private.set_import_disposal_hold(uuid,uuid,boolean,text),private.approve_import_disposal(uuid,uuid,timestamptz,text),private.assert_disposable_import(uuid,uuid),private.guard_disposed_import(),private.guard_import_batch_delete(),private.guard_raw_import_delete(),private.guard_import_terminal_state(),private.execute_import_disposal(uuid,uuid),private.replay_import_disposal(uuid,uuid,text,text,timestamptz) FROM PUBLIC,profitpilot_app;
COMMIT;
