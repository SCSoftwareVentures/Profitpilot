-- Sandbox bilateral quote and milestone agreement. No provider execution.
BEGIN;
CREATE TABLE securepay_private.payment_plans(
 plan_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,job_id uuid NOT NULL,customer_id uuid NOT NULL,owner_id uuid NOT NULL,
 quote_digest text NOT NULL CHECK(quote_digest ~ '^[a-f0-9]{64}$'),
 total_cents bigint NOT NULL CHECK(total_cents>0 AND total_cents<=9007199254740991),
 currency text NOT NULL DEFAULT 'AUD' CHECK(currency='AUD'),
 items jsonb NOT NULL,plan_digest text NOT NULL CHECK(plan_digest ~ '^[a-f0-9]{64}$'),
 status text NOT NULL DEFAULT 'offered' CHECK(status IN ('offered','accepted','withdrawn')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),accepted_at timestamptz,
 FOREIGN KEY(tenant_id,customer_id) REFERENCES public.securepay_payer_identities(tenant_id,customer_id),
 FOREIGN KEY(tenant_id,owner_id) REFERENCES securepay_private.dispute_actors(tenant_id,actor_id),
 CHECK(customer_id<>owner_id),CHECK((status='accepted')=(accepted_at IS NOT NULL))
);
CREATE UNIQUE INDEX sp_active_plan_per_job ON securepay_private.payment_plans(tenant_id,job_id) WHERE status<>'withdrawn';
CREATE TABLE securepay_private.payment_plan_milestones(
 tenant_id uuid NOT NULL,plan_id uuid NOT NULL REFERENCES securepay_private.payment_plans(plan_id),milestone_id uuid NOT NULL,
 stage integer NOT NULL CHECK(stage BETWEEN 1 AND 20),description text NOT NULL,
 PRIMARY KEY(plan_id,stage),UNIQUE(milestone_id),
 FOREIGN KEY(tenant_id,milestone_id) REFERENCES public.securepay_milestones(tenant_id,id)
);
-- The trusted administrative provisioning path maps a real quote/job to both parties.
CREATE TABLE securepay_private.quote_assignments(
 tenant_id uuid NOT NULL,job_id uuid NOT NULL,owner_id uuid NOT NULL,customer_id uuid NOT NULL,
 quote_digest text NOT NULL CHECK(quote_digest ~ '^[a-f0-9]{64}$'),total_cents bigint NOT NULL CHECK(total_cents>0 AND total_cents<=9007199254740991),
 PRIMARY KEY(tenant_id,job_id),FOREIGN KEY(tenant_id,owner_id) REFERENCES securepay_private.dispute_actors(tenant_id,actor_id),
 FOREIGN KEY(tenant_id,customer_id) REFERENCES public.securepay_payer_identities(tenant_id,customer_id),CHECK(owner_id<>customer_id)
);
ALTER TABLE securepay_private.payment_plans OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.payment_plans FROM PUBLIC,securepay_payer_runtime,securepay_completion_runtime,securepay_provider_runtime,securepay_dispute_runtime;
CREATE TRIGGER sp_chain_payment_plans AFTER INSERT OR UPDATE OR DELETE ON securepay_private.payment_plans FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
ALTER TABLE securepay_private.payment_plan_milestones OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.payment_plan_milestones FROM PUBLIC,securepay_payer_runtime,securepay_completion_runtime,securepay_provider_runtime,securepay_dispute_runtime;
CREATE TRIGGER sp_chain_payment_plan_milestones AFTER INSERT OR UPDATE OR DELETE ON securepay_private.payment_plan_milestones FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
ALTER TABLE securepay_private.quote_assignments OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.quote_assignments FROM PUBLIC,securepay_payer_runtime,securepay_completion_runtime,securepay_provider_runtime,securepay_dispute_runtime;
CREATE TRIGGER sp_chain_quote_assignments AFTER INSERT OR UPDATE OR DELETE ON securepay_private.quote_assignments FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE FUNCTION securepay_private.plan_hash(z uuid,t uuid,j uuid,c uuid,a uuid,q text,total bigint,terms jsonb) RETURNS text
 LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT encode(public.digest(convert_to(jsonb_build_array('sp-plan-v1',z,t,j,c,a,q,total,'AUD',terms)::text,'UTF8'),'sha256'),'hex')
$$;
CREATE FUNCTION securepay_private.offer_payment_plan(z uuid,t uuid,j uuid,a uuid,terms_text text,expires bigint,sig text) RETURNS text
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE q securepay_private.quote_assignments%ROWTYPE;terms jsonb;item jsonb;num integer:=0;sum_cents numeric:=0;seen uuid[]:='{}';mid uuid;amount bigint;h text;
BEGIN
 IF z IS NULL OR t IS NULL OR j IS NULL OR a IS NULL OR terms_text IS NULL OR octet_length(terms_text)>32768
 OR securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-plan-offer-v1',z,t,j,a,encode(convert_to(terms_text,'UTF8'),'hex'),expires),expires,sig) IS DISTINCT FROM 'owner' THEN RETURN NULL; END IF;
 SELECT * INTO q FROM securepay_private.quote_assignments WHERE tenant_id=t AND job_id=j AND owner_id=a FOR UPDATE;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM public.securepay_payer_identities WHERE tenant_id=t AND customer_id=q.customer_id AND active) THEN RETURN NULL; END IF;
 terms:=terms_text::jsonb;
 IF jsonb_typeof(terms) IS DISTINCT FROM 'array' OR jsonb_array_length(terms) NOT BETWEEN 1 AND 20 THEN RETURN NULL; END IF;
 FOR item IN SELECT value FROM jsonb_array_elements(terms) LOOP
  num:=num+1;
  IF jsonb_typeof(item) IS DISTINCT FROM 'object' OR NOT (item ?& ARRAY['milestoneId','amountCents','description','final']) OR (SELECT count(*) FROM jsonb_object_keys(item))<>4
  OR jsonb_typeof(item->'milestoneId') IS DISTINCT FROM 'string' OR item->>'milestoneId' !~ '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$'
  OR jsonb_typeof(item->'amountCents') IS DISTINCT FROM 'number' OR item->>'amountCents' !~ '^[1-9][0-9]{0,15}$'
  OR jsonb_typeof(item->'description') IS DISTINCT FROM 'string' OR length(btrim(item->>'description')) NOT BETWEEN 1 AND 500
  OR jsonb_typeof(item->'final') IS DISTINCT FROM 'boolean' OR (item->>'final')::boolean<>(num=jsonb_array_length(terms)) THEN RETURN NULL; END IF;
  mid:=(item->>'milestoneId')::uuid;amount:=(item->>'amountCents')::bigint;
  IF mid=ANY(seen) OR amount>q.total_cents THEN RETURN NULL; END IF;
  seen:=array_append(seen,mid);sum_cents:=sum_cents+amount;
 END LOOP;
 IF sum_cents<>q.total_cents OR EXISTS(SELECT 1 FROM public.securepay_milestones WHERE tenant_id=t AND job_id=j) THEN RETURN NULL; END IF;
 h:=securepay_private.plan_hash(z,t,j,q.customer_id,a,q.quote_digest,q.total_cents,terms);
 INSERT INTO securepay_private.payment_plans(plan_id,tenant_id,job_id,customer_id,owner_id,quote_digest,total_cents,items,plan_digest)
 VALUES(z,t,j,q.customer_id,a,q.quote_digest,q.total_cents,terms,h);
 RETURN h;
EXCEPTION WHEN unique_violation OR invalid_text_representation OR numeric_value_out_of_range THEN RETURN NULL;
END $$;
CREATE FUNCTION securepay_private.payer_plan_view(t uuid,z uuid) RETURNS jsonb
 LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('planId',p.plan_id,'jobId',p.job_id,'quoteDigest',p.quote_digest,'planDigest',p.plan_digest,'currency',p.currency,'totalCents',p.total_cents::text,'items',p.items,'status',p.status)
 FROM securepay_private.payment_plans p WHERE p.tenant_id=t AND p.plan_id=z AND p.customer_id=securepay_private.current_payer(t)
$$;
CREATE FUNCTION securepay_private.accept_payment_plan(t uuid,z uuid,h text,total bigint) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c uuid;p securepay_private.payment_plans%ROWTYPE;q securepay_private.quote_assignments%ROWTYPE;item jsonb;n integer:=0;mid uuid;
BEGIN
 c:=securepay_private.current_payer(t);
 IF c IS NULL OR z IS NULL OR h IS NULL OR total IS NULL THEN RETURN false; END IF;
 SELECT job_id INTO mid FROM securepay_private.payment_plans WHERE plan_id=z AND tenant_id=t AND customer_id=c;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO q FROM securepay_private.quote_assignments WHERE tenant_id=t AND job_id=mid FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO p FROM securepay_private.payment_plans WHERE plan_id=z AND tenant_id=t AND customer_id=c FOR UPDATE;
 IF NOT FOUND OR p.status<>'offered' OR p.plan_digest<>h OR p.total_cents<>total OR p.owner_id<>q.owner_id OR p.customer_id<>q.customer_id OR p.quote_digest<>q.quote_digest OR p.total_cents<>q.total_cents
 OR securepay_private.plan_hash(z,t,p.job_id,c,p.owner_id,p.quote_digest,total,p.items) IS DISTINCT FROM h
 OR NOT EXISTS(SELECT 1 FROM securepay_private.dispute_actors WHERE tenant_id=t AND actor_id=p.owner_id AND role='owner' AND active)
 OR EXISTS(SELECT 1 FROM public.securepay_milestones WHERE tenant_id=t AND job_id=p.job_id) THEN RETURN false; END IF;
 UPDATE securepay_private.payment_plans SET status='accepted',accepted_at=clock_timestamp() WHERE plan_id=z;
 FOR item IN SELECT value FROM jsonb_array_elements(p.items) LOOP
  n:=n+1;mid:=(item->>'milestoneId')::uuid;
  INSERT INTO public.securepay_milestones(id,tenant_id,job_id,amount_cents,is_final,status,payer_customer_id)
  VALUES(mid,t,p.job_id,(item->>'amountCents')::bigint,(item->>'final')::boolean,'planned',c);
  INSERT INTO securepay_private.payment_plan_milestones(tenant_id,plan_id,milestone_id,stage,description) VALUES(t,z,mid,n,item->>'description');
  INSERT INTO securepay_private.work_assignments(tenant_id,milestone_id,owner_id) VALUES(t,mid,p.owner_id);
  INSERT INTO securepay_private.dispute_parties(tenant_id,milestone_id,owner_id) VALUES(t,mid,p.owner_id);
 END LOOP;
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
CREATE FUNCTION securepay_private.withdraw_payment_plan(t uuid,z uuid,a uuid,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE j uuid;
BEGIN
 IF t IS NULL OR z IS NULL OR a IS NULL OR securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-plan-withdraw-v1',t,z,a,expires),expires,sig) IS DISTINCT FROM 'owner' THEN RETURN false; END IF;
 SELECT job_id INTO j FROM securepay_private.payment_plans WHERE tenant_id=t AND plan_id=z AND owner_id=a;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM securepay_private.quote_assignments WHERE tenant_id=t AND job_id=j FOR UPDATE;
 UPDATE securepay_private.payment_plans SET status='withdrawn' WHERE tenant_id=t AND plan_id=z AND owner_id=a AND status='offered';
 RETURN FOUND;
END $$;
-- New plan-linked final work cannot be submitted before preceding stages have
-- a provider-confirmed terminal status and a reconciled zero outstanding balance.
CREATE FUNCTION securepay_private.check_final_milestone() RETURNS trigger
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p uuid;
BEGIN
 IF NEW.status='submitted' AND OLD.status='planned' AND NEW.is_final THEN
  SELECT plan_id INTO p FROM securepay_private.payment_plan_milestones WHERE milestone_id=NEW.id AND tenant_id=NEW.tenant_id;
  IF FOUND AND EXISTS(SELECT 1 FROM securepay_private.payment_plan_milestones l JOIN public.securepay_milestones m ON m.tenant_id=l.tenant_id AND m.id=l.milestone_id
   WHERE l.plan_id=p AND m.id<>NEW.id AND (m.status NOT IN ('released','settled') OR NOT securepay_private.verify_financial_journal(m.tenant_id,m.id))) THEN
   RAISE EXCEPTION 'Prior milestones require confirmed reconciliation' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END $$;
ALTER FUNCTION securepay_private.plan_hash(uuid,uuid,uuid,uuid,uuid,text,bigint,jsonb) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.plan_hash(uuid,uuid,uuid,uuid,uuid,text,bigint,jsonb) FROM PUBLIC;
ALTER FUNCTION securepay_private.offer_payment_plan(uuid,uuid,uuid,uuid,text,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.offer_payment_plan(uuid,uuid,uuid,uuid,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.offer_payment_plan(uuid,uuid,uuid,uuid,text,bigint,text) TO securepay_completion_runtime;
ALTER FUNCTION securepay_private.payer_plan_view(uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.payer_plan_view(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.payer_plan_view(uuid,uuid) TO securepay_payer_runtime;
ALTER FUNCTION securepay_private.accept_payment_plan(uuid,uuid,text,bigint) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.accept_payment_plan(uuid,uuid,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.accept_payment_plan(uuid,uuid,text,bigint) TO securepay_payer_runtime;
ALTER FUNCTION securepay_private.withdraw_payment_plan(uuid,uuid,uuid,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.withdraw_payment_plan(uuid,uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.withdraw_payment_plan(uuid,uuid,uuid,bigint,text) TO securepay_completion_runtime;
ALTER FUNCTION securepay_private.check_final_milestone() OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.check_final_milestone() FROM PUBLIC;
CREATE TRIGGER sp_final_milestone_guard BEFORE UPDATE OF status ON public.securepay_milestones FOR EACH ROW EXECUTE FUNCTION securepay_private.check_final_milestone();
COMMIT;
