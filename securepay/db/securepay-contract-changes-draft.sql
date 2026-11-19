-- Bilateral changes to untouched, unfunded work only. Historical payments immutable.
BEGIN;
ALTER TABLE public.securepay_milestones DROP CONSTRAINT securepay_milestones_status_check,
 ADD CONSTRAINT securepay_milestones_status_check CHECK(status IN ('planned','submitted','disputed','approved','release_pending','released','settled','cancelled'));
CREATE TABLE securepay_private.contract_changes(
 change_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,plan_id uuid NOT NULL REFERENCES securepay_private.payment_plans(plan_id),
 owner_id uuid NOT NULL,customer_id uuid NOT NULL,kind text NOT NULL CHECK(kind IN ('variation','cancel_remaining')),
 milestone_id uuid,old_total bigint NOT NULL,new_total bigint NOT NULL CHECK(new_total BETWEEN 0 AND 9007199254740991),
 new_amount bigint,new_description text,reason text NOT NULL CHECK(length(btrim(reason)) BETWEEN 10 AND 2000),
 before_state jsonb NOT NULL,
 state_digest text NOT NULL CHECK(state_digest ~ '^[a-f0-9]{64}$'),change_digest text NOT NULL CHECK(change_digest ~ '^[a-f0-9]{64}$'),
 status text NOT NULL DEFAULT 'offered' CHECK(status IN ('offered','accepted','withdrawn')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),accepted_at timestamptz,
 CHECK((status='accepted')=(accepted_at IS NOT NULL)),
 CHECK((kind='variation' AND milestone_id IS NOT NULL AND new_amount BETWEEN 1 AND 9007199254740991 AND new_description IS NOT NULL AND length(btrim(new_description)) BETWEEN 1 AND 500) OR
 (kind='cancel_remaining' AND milestone_id IS NULL AND new_amount IS NULL AND new_description IS NULL))
);
ALTER TABLE securepay_private.contract_changes OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.contract_changes FROM PUBLIC,securepay_payer_runtime,securepay_completion_runtime,securepay_provider_runtime,securepay_reporting_runtime;
CREATE UNIQUE INDEX sp_pending_contract_change ON securepay_private.contract_changes(plan_id) WHERE status='offered';
CREATE TRIGGER sp_chain_contract_changes AFTER INSERT OR UPDATE OR DELETE ON securepay_private.contract_changes FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE FUNCTION securepay_private.contract_state(t uuid,z uuid) RETURNS jsonb
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('planId',p.plan_id,'originalTotalCents',p.total_cents::text,'effectiveTotalCents',
 (SELECT coalesce(sum(m.amount_cents) FILTER(WHERE m.status<>'cancelled'),0)::text FROM securepay_private.payment_plan_milestones l JOIN public.securepay_milestones m ON m.tenant_id=l.tenant_id AND m.id=l.milestone_id WHERE l.plan_id=z AND l.tenant_id=t),
 'stages',(SELECT jsonb_agg(jsonb_build_object('milestoneId',m.id,'amountCents',m.amount_cents::text,'description',l.description,'status',m.status,'version',m.version::text,'final',m.is_final,
 'eligible',m.status='planned' AND NOT EXISTS(SELECT 1 FROM securepay_private.provider_funding f WHERE f.tenant_id=t AND f.milestone_id=m.id)
 AND NOT EXISTS(SELECT 1 FROM securepay_private.work_completion w WHERE w.tenant_id=t AND w.milestone_id=m.id)
 AND NOT EXISTS(SELECT 1 FROM securepay_private.dispute_cases d WHERE d.tenant_id=t AND d.milestone_id=m.id)
 AND NOT EXISTS(SELECT 1 FROM public.securepay_release_requests r WHERE r.tenant_id=t AND r.milestone_id=m.id),
 'terminalVerified',m.status IN ('released','settled') AND securepay_private.verify_financial_journal(t,m.id)
 AND NOT EXISTS(SELECT 1 FROM securepay_private.provider_reconciliation r WHERE r.tenant_id=t AND r.milestone_id=m.id AND r.resolved_at IS NULL)
 AND NOT EXISTS(SELECT 1 FROM securepay_private.dispute_cases d JOIN securepay_private.settlement_leg_conflicts r ON r.case_id=d.case_id WHERE d.tenant_id=t AND d.milestone_id=m.id AND r.resolved_at IS NULL)) ORDER BY l.stage)
 FROM securepay_private.payment_plan_milestones l JOIN public.securepay_milestones m ON m.tenant_id=l.tenant_id AND m.id=l.milestone_id WHERE l.plan_id=z AND l.tenant_id=t))
 FROM securepay_private.payment_plans p WHERE p.tenant_id=t AND p.plan_id=z AND p.status='accepted'
$$;
CREATE FUNCTION securepay_private.change_hash(v uuid,t uuid,z uuid,k text,m uuid,amount bigint,description text,reason text,state_hash text,old_total bigint,new_total bigint) RETURNS text
 LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT encode(public.digest(convert_to(jsonb_build_array('sp-change-v1',v,t,z,k,m,amount,description,reason,state_hash,old_total,new_total)::text,'UTF8'),'sha256'),'hex')
$$;
CREATE FUNCTION securepay_private.offer_contract_change(v uuid,t uuid,z uuid,a uuid,k text,m uuid,amount bigint,description text,reason text,expires bigint,sig text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p securepay_private.payment_plans%ROWTYPE;s jsonb;stage jsonb;old_total bigint;new_total numeric;h text;sh text;
BEGIN
 IF v IS NULL OR t IS NULL OR z IS NULL OR a IS NULL OR k IS NULL OR k NOT IN ('variation','cancel_remaining') OR reason IS NULL OR length(btrim(reason)) NOT BETWEEN 10 AND 2000
 OR (k='variation' AND (m IS NULL OR amount IS NULL OR amount NOT BETWEEN 1 AND 9007199254740991 OR description IS NULL OR length(btrim(description)) NOT BETWEEN 1 AND 500))
 OR (k='cancel_remaining' AND (m IS NOT NULL OR amount IS NOT NULL OR description IS NOT NULL))
 OR securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-change-offer-v1',v,t,z,a,k,coalesce(m::text,'-'),coalesce(amount::text,'-'),coalesce(encode(convert_to(description,'UTF8'),'hex'),'-'),encode(convert_to(reason,'UTF8'),'hex'),expires),expires,sig) IS DISTINCT FROM 'owner' THEN RETURN NULL; END IF;
 SELECT * INTO p FROM securepay_private.payment_plans WHERE tenant_id=t AND plan_id=z AND owner_id=a AND status='accepted' FOR UPDATE;
 IF NOT FOUND OR (SELECT count(*) FROM securepay_private.contract_changes WHERE plan_id=z)>=20 THEN RETURN NULL; END IF;
 PERFORM 1 FROM public.securepay_milestones x JOIN securepay_private.payment_plan_milestones l ON l.tenant_id=x.tenant_id AND l.milestone_id=x.id WHERE l.tenant_id=t AND l.plan_id=z ORDER BY x.id FOR UPDATE OF x;
 s:=securepay_private.contract_state(t,z);
 IF s IS NULL OR EXISTS(SELECT 1 FROM jsonb_array_elements(s->'stages') x WHERE x->>'status'<>'cancelled' AND NOT (x->>'eligible')::boolean AND NOT (x->>'terminalVerified')::boolean) THEN RETURN NULL; END IF;
 old_total:=(s->>'effectiveTotalCents')::bigint;
 IF k='variation' THEN
  SELECT value INTO stage FROM jsonb_array_elements(s->'stages') WHERE value->>'milestoneId'=m::text AND (value->>'eligible')::boolean;
  IF NOT FOUND OR ((stage->>'amountCents')::bigint=amount AND stage->>'description'=description) THEN RETURN NULL; END IF;
  new_total:=old_total-(stage->>'amountCents')::bigint+amount;
 ELSE
  IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(s->'stages') x WHERE (x->>'eligible')::boolean) THEN RETURN NULL; END IF;
  new_total:=old_total-(SELECT sum((x->>'amountCents')::numeric) FROM jsonb_array_elements(s->'stages') x WHERE (x->>'eligible')::boolean);
 END IF;
 IF new_total NOT BETWEEN 0 AND 9007199254740991 THEN RETURN NULL; END IF;
 sh:=encode(public.digest(convert_to(s::text,'UTF8'),'sha256'),'hex');
 h:=securepay_private.change_hash(v,t,z,k,m,amount,description,reason,sh,old_total,new_total::bigint);
 INSERT INTO securepay_private.contract_changes(change_id,tenant_id,plan_id,owner_id,customer_id,kind,milestone_id,old_total,new_total,new_amount,new_description,reason,before_state,state_digest,change_digest)
 VALUES(v,t,z,a,p.customer_id,k,m,old_total,new_total,amount,description,reason,s,sh,h);
 RETURN jsonb_build_object('changeId',v,'changeDigest',h,'oldTotalCents',old_total::text,'newTotalCents',new_total::text);
EXCEPTION WHEN unique_violation THEN RETURN NULL;
END $$;
CREATE FUNCTION securepay_private.accept_contract_change(t uuid,z uuid,v uuid,h text,total bigint) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c uuid;p securepay_private.payment_plans%ROWTYPE;r securepay_private.contract_changes%ROWTYPE;s jsonb;
BEGIN
 c:=securepay_private.current_payer(t);
 IF c IS NULL OR z IS NULL OR v IS NULL OR h IS NULL OR total IS NULL THEN RETURN false; END IF;
 SELECT * INTO p FROM securepay_private.payment_plans WHERE tenant_id=t AND plan_id=z AND customer_id=c AND status='accepted' FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM public.securepay_milestones x JOIN securepay_private.payment_plan_milestones l ON l.tenant_id=x.tenant_id AND l.milestone_id=x.id WHERE l.tenant_id=t AND l.plan_id=z ORDER BY x.id FOR UPDATE OF x;
 SELECT * INTO r FROM securepay_private.contract_changes WHERE change_id=v AND tenant_id=t AND plan_id=z AND customer_id=c AND status='offered' FOR UPDATE;
 IF NOT FOUND OR r.change_digest<>h OR r.new_total<>total OR r.owner_id<>p.owner_id OR NOT EXISTS(SELECT 1 FROM securepay_private.dispute_actors WHERE tenant_id=t AND actor_id=r.owner_id AND role='owner' AND active) THEN RETURN false; END IF;
 s:=securepay_private.contract_state(t,z);
 IF s IS NULL OR encode(public.digest(convert_to(s::text,'UTF8'),'sha256'),'hex')<>r.state_digest OR
 securepay_private.change_hash(v,t,z,r.kind,r.milestone_id,r.new_amount,r.new_description,r.reason,r.state_digest,r.old_total,r.new_total)<>h THEN RETURN false; END IF;
 IF r.kind='variation' THEN
  UPDATE public.securepay_milestones SET amount_cents=r.new_amount,version=version+1,updated_at=clock_timestamp() WHERE tenant_id=t AND id=r.milestone_id AND status='planned';
  IF NOT FOUND THEN RETURN false; END IF;
  UPDATE securepay_private.payment_plan_milestones SET description=r.new_description WHERE tenant_id=t AND plan_id=z AND milestone_id=r.milestone_id;
 ELSE
  UPDATE public.securepay_milestones x SET status='cancelled',version=version+1,updated_at=clock_timestamp() FROM securepay_private.payment_plan_milestones l WHERE l.tenant_id=t AND l.plan_id=z AND x.tenant_id=t AND x.id=l.milestone_id AND x.status='planned';
  IF NOT FOUND THEN RETURN false; END IF;
 END IF;
 IF (securepay_private.contract_state(t,z)->>'effectiveTotalCents')::bigint<>total THEN RAISE EXCEPTION 'Contract total mismatch'; END IF;
 UPDATE securepay_private.contract_changes SET status='accepted',accepted_at=clock_timestamp() WHERE change_id=v;
 RETURN true;
END $$;
CREATE FUNCTION securepay_private.withdraw_contract_change(t uuid,z uuid,v uuid,a uuid,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-change-withdraw-v1',t,z,v,a,expires),expires,sig) IS DISTINCT FROM 'owner' THEN RETURN false; END IF;
 PERFORM 1 FROM securepay_private.payment_plans WHERE tenant_id=t AND plan_id=z AND owner_id=a AND status='accepted' FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 UPDATE securepay_private.contract_changes SET status='withdrawn' WHERE tenant_id=t AND plan_id=z AND change_id=v AND owner_id=a AND status='offered';
 RETURN FOUND;
END $$;
CREATE FUNCTION securepay_private.contract_change_view(t uuid,z uuid) RETURNS jsonb
 LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('state',securepay_private.contract_state(t,z),'changes',coalesce((SELECT jsonb_agg(jsonb_build_object('changeId',c.change_id,'kind',c.kind,'milestoneId',c.milestone_id,'oldTotalCents',c.old_total::text,'newTotalCents',c.new_total::text,'newAmountCents',c.new_amount::text,'newDescription',c.new_description,'reason',c.reason,'status',c.status,'changeDigest',c.change_digest,'current',c.status='offered' AND c.state_digest=encode(public.digest(convert_to(securepay_private.contract_state(t,z)::text,'UTF8'),'sha256'),'hex'),'affectedStages',(SELECT coalesce(jsonb_agg(jsonb_build_object('milestoneId',x->>'milestoneId','amountCents',x->>'amountCents','description',x->>'description') ORDER BY x->>'milestoneId'),'[]'::jsonb) FROM jsonb_array_elements(c.before_state->'stages') x WHERE (c.kind='variation' AND x->>'milestoneId'=c.milestone_id::text) OR (c.kind='cancel_remaining' AND (x->>'eligible')::boolean))) ORDER BY c.created_at,c.change_id) FROM securepay_private.contract_changes c WHERE c.tenant_id=t AND c.plan_id=z),'[]'::jsonb))
$$;
CREATE FUNCTION securepay_private.payer_contract_view(t uuid,z uuid) RETURNS jsonb
 LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT securepay_private.contract_change_view(t,z) FROM securepay_private.payment_plans p WHERE p.tenant_id=t AND p.plan_id=z AND p.status='accepted' AND p.customer_id=securepay_private.current_payer(t)
$$;
CREATE FUNCTION securepay_private.owner_contract_view(t uuid,z uuid,a uuid,expires bigint,sig text) RETURNS jsonb
 LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT securepay_private.contract_change_view(t,z) FROM securepay_private.payment_plans p WHERE p.tenant_id=t AND p.plan_id=z AND p.status='accepted' AND p.owner_id=a AND securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-contract-view-v1',t,z,a,expires),expires,sig)='owner'
$$;
ALTER FUNCTION securepay_private.contract_state(uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.contract_state(uuid,uuid) FROM PUBLIC;
ALTER FUNCTION securepay_private.change_hash(uuid,uuid,uuid,text,uuid,bigint,text,text,text,bigint,bigint) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.change_hash(uuid,uuid,uuid,text,uuid,bigint,text,text,text,bigint,bigint) FROM PUBLIC;
ALTER FUNCTION securepay_private.offer_contract_change(uuid,uuid,uuid,uuid,text,uuid,bigint,text,text,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.offer_contract_change(uuid,uuid,uuid,uuid,text,uuid,bigint,text,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.offer_contract_change(uuid,uuid,uuid,uuid,text,uuid,bigint,text,text,bigint,text) TO securepay_completion_runtime;
ALTER FUNCTION securepay_private.accept_contract_change(uuid,uuid,uuid,text,bigint) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.accept_contract_change(uuid,uuid,uuid,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.accept_contract_change(uuid,uuid,uuid,text,bigint) TO securepay_payer_runtime;
ALTER FUNCTION securepay_private.withdraw_contract_change(uuid,uuid,uuid,uuid,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.withdraw_contract_change(uuid,uuid,uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.withdraw_contract_change(uuid,uuid,uuid,uuid,bigint,text) TO securepay_completion_runtime;
ALTER FUNCTION securepay_private.contract_change_view(uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.contract_change_view(uuid,uuid) FROM PUBLIC;
ALTER FUNCTION securepay_private.payer_contract_view(uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.payer_contract_view(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.payer_contract_view(uuid,uuid) TO securepay_payer_runtime;
ALTER FUNCTION securepay_private.owner_contract_view(uuid,uuid,uuid,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.owner_contract_view(uuid,uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.owner_contract_view(uuid,uuid,uuid,bigint,text) TO securepay_completion_runtime;
COMMIT;
