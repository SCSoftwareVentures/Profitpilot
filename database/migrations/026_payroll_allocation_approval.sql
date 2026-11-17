-- Migration 026: source-backed payroll pool, allocation maker-checker and immutability.
-- User-supplied totals must be reconciled to accepted source rows by the API.
BEGIN;

ALTER TABLE public.allocation_runs ADD COLUMN created_by uuid;
ALTER TABLE public.allocation_runs ADD CONSTRAINT allocation_runs_creator_same_tenant_fk
 FOREIGN KEY (tenant_id,created_by) REFERENCES public.tenant_memberships(tenant_id,user_id);
ALTER TABLE public.allocation_runs ADD COLUMN approved_at timestamptz;
ALTER TABLE public.allocation_runs ADD COLUMN approval_reason text;
ALTER TABLE public.allocation_runs ADD CONSTRAINT allocation_runs_approval_reason_length
 CHECK (approval_reason IS NULL OR length(btrim(approval_reason)) BETWEEN 3 AND 1000);

CREATE UNIQUE INDEX payroll_pools_unique_source_batch
 ON public.payroll_pools(tenant_id,batch_id);

INSERT INTO public.permission_catalog(permission_key,description,sensitive) VALUES
 ('payroll.rows.decide','Review source payroll rows without authorising allocations',true),
 ('payroll.pools.reconcile','Reconcile accepted payroll rows to a declared source total',true),
 ('payroll.allocations.draft','Prepare a source-referenced payroll allocation draft',true),
 ('payroll.allocations.confirm','Independently approve a fully reconciled payroll allocation',true),
 ('payroll.allocations.read','Read approved tenant payroll allocation evidence',true)
ON CONFLICT(permission_key) DO NOTHING;

INSERT INTO public.role_permissions(role,permission_key) VALUES
 ('owner','payroll.rows.decide'),('admin','payroll.rows.decide'),('reviewer','payroll.rows.decide'),
 ('owner','payroll.pools.reconcile'),('admin','payroll.pools.reconcile'),
 ('owner','payroll.allocations.draft'),('admin','payroll.allocations.draft'),('analyst','payroll.allocations.draft'),
 ('owner','payroll.allocations.confirm'),('admin','payroll.allocations.confirm'),('reviewer','payroll.allocations.confirm'),
 ('owner','payroll.allocations.read'),('admin','payroll.allocations.read'),
 ('analyst','payroll.allocations.read'),('reviewer','payroll.allocations.read')
ON CONFLICT(role,permission_key) DO NOTHING;

-- Payroll pools represent an immutable signed-off source snapshot, not mutable free-form totals.
REVOKE UPDATE,DELETE,TRUNCATE ON public.payroll_pools FROM profitpilot_app;
-- Allocation lines are written once as part of creating a review draft.
REVOKE UPDATE,DELETE,TRUNCATE ON public.allocation_lines FROM profitpilot_app;

CREATE FUNCTION private.protect_confirmed_allocation_run()
RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog,public,private
AS $function$
BEGIN
 IF OLD.status='confirmed' THEN
  RAISE EXCEPTION 'Confirmed payroll allocations are immutable' USING ERRCODE='55000';
 END IF;
 RETURN CASE WHEN TG_OP='DELETE' THEN OLD ELSE NEW END;
END
$function$;
CREATE TRIGGER confirmed_allocation_run_immutable
 BEFORE UPDATE OR DELETE ON public.allocation_runs
 FOR EACH ROW EXECUTE FUNCTION private.protect_confirmed_allocation_run();

CREATE FUNCTION private.protect_confirmed_allocation_lines()
RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog,public,private
AS $function$
DECLARE v_status text;
DECLARE v_tenant uuid;
DECLARE v_run uuid;
BEGIN
 IF TG_OP='DELETE' THEN
  v_tenant:=OLD.tenant_id;v_run:=OLD.allocation_run_id;
 ELSE
  v_tenant:=NEW.tenant_id;v_run:=NEW.allocation_run_id;
 END IF;
 SELECT status INTO v_status
 FROM public.allocation_runs
 WHERE tenant_id=v_tenant AND id=v_run FOR SHARE;
 IF v_status='confirmed' THEN
  RAISE EXCEPTION 'Confirmed allocation lines are immutable' USING ERRCODE='55000';
 END IF;
 IF TG_OP='UPDATE' THEN
  SELECT status INTO v_status FROM public.allocation_runs
   WHERE tenant_id=OLD.tenant_id AND id=OLD.allocation_run_id FOR SHARE;
  IF v_status='confirmed' THEN
   RAISE EXCEPTION 'Confirmed allocation lines are immutable' USING ERRCODE='55000';
  END IF;
 END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END
$function$;
CREATE TRIGGER confirmed_allocation_lines_immutable
 BEFORE INSERT OR UPDATE OR DELETE ON public.allocation_lines
 FOR EACH ROW EXECUTE FUNCTION private.protect_confirmed_allocation_lines();

COMMIT;
