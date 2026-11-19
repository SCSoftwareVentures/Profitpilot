-- Sandbox quote source and revision bridge. No mutation of accepted plans.
BEGIN;
CREATE TABLE securepay_private.quote_job_parties(
 tenant_id uuid NOT NULL,job_id uuid NOT NULL,customer_id uuid NOT NULL,owner_id uuid NOT NULL,
 PRIMARY KEY(tenant_id,job_id),
 FOREIGN KEY(tenant_id,customer_id) REFERENCES public.securepay_payer_identities(tenant_id,customer_id),
 FOREIGN KEY(tenant_id,owner_id) REFERENCES securepay_private.dispute_actors(tenant_id,actor_id),
 CHECK(customer_id<>owner_id)
);
CREATE TABLE securepay_private.quote_revisions(
 quote_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,job_id uuid NOT NULL,owner_id uuid NOT NULL,customer_id uuid NOT NULL,
 revision integer NOT NULL CHECK(revision BETWEEN 1 AND 100),
 previous_digest text CHECK(previous_digest ~ '^[a-f0-9]{64}$'),quote_digest text NOT NULL UNIQUE CHECK(quote_digest ~ '^[a-f0-9]{64}$'),
 description text NOT NULL CHECK(length(btrim(description)) BETWEEN 1 AND 4000),
 total_cents bigint NOT NULL CHECK(total_cents BETWEEN 1 AND 9007199254740991),
 currency text NOT NULL DEFAULT 'AUD' CHECK(currency='AUD'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,job_id,revision),FOREIGN KEY(tenant_id,job_id) REFERENCES securepay_private.quote_job_parties(tenant_id,job_id),
 CHECK((revision=1)=(previous_digest IS NULL))
);
ALTER TABLE securepay_private.quote_job_parties OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.quote_job_parties FROM PUBLIC,securepay_completion_runtime,securepay_payer_runtime,securepay_provider_runtime,securepay_reporting_runtime;
CREATE TRIGGER sp_chain_quote_job_parties AFTER INSERT OR UPDATE OR DELETE ON securepay_private.quote_job_parties FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
ALTER TABLE securepay_private.quote_revisions OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.quote_revisions FROM PUBLIC,securepay_completion_runtime,securepay_payer_runtime,securepay_provider_runtime,securepay_reporting_runtime;
CREATE TRIGGER sp_chain_quote_revisions AFTER INSERT OR UPDATE OR DELETE ON securepay_private.quote_revisions FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE FUNCTION securepay_private.publish_quote(q uuid,t uuid,j uuid,a uuid,previous text,description text,total bigint,expires bigint,sig text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE parties securepay_private.quote_job_parties%ROWTYPE; assignment securepay_private.quote_assignments%ROWTYPE;
 prior securepay_private.quote_revisions%ROWTYPE; n integer;h text;
BEGIN
 IF q IS NULL OR t IS NULL OR j IS NULL OR a IS NULL OR description IS NULL OR length(btrim(description)) NOT BETWEEN 1 AND 4000
 OR total IS NULL OR total NOT BETWEEN 1 AND 9007199254740991 OR (previous IS NOT NULL AND previous !~ '^[a-f0-9]{64}$')
 OR securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-quote-publish-v1',q,t,j,a,coalesce(previous,'-'),encode(convert_to(description,'UTF8'),'hex'),total,expires),expires,sig) IS DISTINCT FROM 'owner' THEN RETURN NULL; END IF;
 SELECT * INTO parties FROM securepay_private.quote_job_parties WHERE tenant_id=t AND job_id=j AND owner_id=a FOR UPDATE;
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM public.securepay_payer_identities WHERE tenant_id=t AND customer_id=parties.customer_id AND active) THEN RETURN NULL; END IF;
 SELECT * INTO assignment FROM securepay_private.quote_assignments WHERE tenant_id=t AND job_id=j FOR UPDATE;
 -- Serialize revisions against exact customer acceptance and owner offer.
 IF EXISTS(SELECT 1 FROM securepay_private.payment_plans WHERE tenant_id=t AND job_id=j AND status='accepted')
 OR EXISTS(SELECT 1 FROM public.securepay_milestones WHERE tenant_id=t AND job_id=j) THEN RETURN NULL; END IF;
 SELECT * INTO prior FROM securepay_private.quote_revisions WHERE tenant_id=t AND job_id=j ORDER BY revision DESC LIMIT 1;
 IF FOUND THEN
  IF prior.quote_digest IS DISTINCT FROM previous OR assignment.quote_digest IS DISTINCT FROM previous OR prior.owner_id<>a OR prior.customer_id<>parties.customer_id OR prior.revision>=100 THEN RETURN NULL; END IF;
  n:=prior.revision+1;
 ELSE
  IF previous IS NOT NULL OR assignment.job_id IS NOT NULL THEN RETURN NULL; END IF;
  n:=1;
 END IF;
 h:=encode(public.digest(convert_to(jsonb_build_array('sp-quote-v1',q,t,j,a,parties.customer_id,n,previous,description,total,'AUD')::text,'UTF8'),'sha256'),'hex');
 INSERT INTO securepay_private.quote_revisions(quote_id,tenant_id,job_id,owner_id,customer_id,revision,previous_digest,quote_digest,description,total_cents)
 VALUES(q,t,j,a,parties.customer_id,n,previous,h,description,total);
 UPDATE securepay_private.payment_plans SET status='withdrawn' WHERE tenant_id=t AND job_id=j AND status='offered';
 INSERT INTO securepay_private.quote_assignments(tenant_id,job_id,owner_id,customer_id,quote_digest,total_cents)
 VALUES(t,j,a,parties.customer_id,h,total)
 ON CONFLICT(tenant_id,job_id) DO UPDATE SET quote_digest=EXCLUDED.quote_digest,total_cents=EXCLUDED.total_cents;
 RETURN jsonb_build_object('quoteId',q,'quoteDigest',h,'revision',n,'totalCents',total::text,'description',description);
EXCEPTION WHEN unique_violation THEN RETURN NULL;
END $$;
CREATE FUNCTION securepay_private.owner_quote_view(t uuid,j uuid,a uuid,expires bigint,sig text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE result jsonb;
BEGIN
 IF securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-quote-view-v1',t,j,a,expires),expires,sig) IS DISTINCT FROM 'owner'
 OR NOT EXISTS(SELECT 1 FROM securepay_private.quote_job_parties WHERE tenant_id=t AND job_id=j AND owner_id=a) THEN RETURN NULL; END IF;
 SELECT jsonb_build_object('jobId',j,'quote',(SELECT jsonb_build_object('quoteId',q.quote_id,'quoteDigest',q.quote_digest,'revision',q.revision,'description',q.description,'totalCents',q.total_cents::text) FROM securepay_private.quote_revisions q WHERE q.tenant_id=t AND q.job_id=j ORDER BY q.revision DESC LIMIT 1),
 'plan',(SELECT jsonb_build_object('planId',p.plan_id,'status',p.status,'planDigest',p.plan_digest) FROM securepay_private.payment_plans p WHERE p.tenant_id=t AND p.job_id=j AND p.status<>'withdrawn')) INTO result;
 RETURN result;
END $$;
CREATE OR REPLACE FUNCTION securepay_private.payer_plan_view(t uuid,z uuid) RETURNS jsonb
 LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('planId',p.plan_id,'jobId',p.job_id,'quoteDigest',p.quote_digest,'planDigest',p.plan_digest,'currency',p.currency,'totalCents',p.total_cents::text,'items',p.items,'status',p.status,
 'quote',(SELECT jsonb_build_object('quoteId',q.quote_id,'revision',q.revision,'description',q.description,'totalCents',q.total_cents::text) FROM securepay_private.quote_revisions q WHERE q.tenant_id=p.tenant_id AND q.job_id=p.job_id AND q.quote_digest=p.quote_digest AND q.customer_id=p.customer_id AND q.owner_id=p.owner_id))
 FROM securepay_private.payment_plans p WHERE p.tenant_id=t AND p.plan_id=z AND p.customer_id=securepay_private.current_payer(t)
$$;
ALTER FUNCTION securepay_private.publish_quote(uuid,uuid,uuid,uuid,text,text,bigint,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.publish_quote(uuid,uuid,uuid,uuid,text,text,bigint,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.publish_quote(uuid,uuid,uuid,uuid,text,text,bigint,bigint,text) TO securepay_completion_runtime;
ALTER FUNCTION securepay_private.owner_quote_view(uuid,uuid,uuid,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.owner_quote_view(uuid,uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.owner_quote_view(uuid,uuid,uuid,bigint,text) TO securepay_completion_runtime;
CREATE OR REPLACE FUNCTION securepay_private.offer_payment_plan(z uuid,t uuid,j uuid,a uuid,terms_text text,expires bigint,sig text) RETURNS text
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE q securepay_private.quote_assignments%ROWTYPE;terms jsonb;item jsonb;num integer:=0;sum_cents numeric:=0;seen uuid[]:='{}';mid uuid;amount bigint;h text;
BEGIN
 IF z IS NULL OR t IS NULL OR j IS NULL OR a IS NULL OR terms_text IS NULL OR octet_length(terms_text)>32768
 OR securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-plan-offer-v1',z,t,j,a,encode(convert_to(terms_text,'UTF8'),'hex'),expires),expires,sig) IS DISTINCT FROM 'owner' THEN RETURN NULL; END IF;
 SELECT * INTO q FROM securepay_private.quote_assignments WHERE tenant_id=t AND job_id=j AND owner_id=a FOR UPDATE;
 IF NOT FOUND OR EXISTS(SELECT 1 FROM securepay_private.quote_revisions r WHERE r.tenant_id=t AND r.job_id=j) OR NOT EXISTS(SELECT 1 FROM public.securepay_payer_identities WHERE tenant_id=t AND customer_id=q.customer_id AND active) THEN RETURN NULL; END IF;
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
CREATE FUNCTION securepay_private.offer_payment_plan_bound(z uuid,t uuid,j uuid,a uuid,terms_text text,expected_quote text,expires bigint,sig text) RETURNS text
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE q securepay_private.quote_assignments%ROWTYPE;terms jsonb;item jsonb;num integer:=0;sum_cents numeric:=0;seen uuid[]:='{}';mid uuid;amount bigint;h text;
BEGIN
 IF z IS NULL OR t IS NULL OR j IS NULL OR a IS NULL OR terms_text IS NULL OR octet_length(terms_text)>32768
 OR expected_quote IS NULL OR expected_quote !~ '^[a-f0-9]{64}$'
 OR securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-plan-offer-v2',z,t,j,a,expected_quote,encode(convert_to(terms_text,'UTF8'),'hex'),expires),expires,sig) IS DISTINCT FROM 'owner' THEN RETURN NULL; END IF;
 SELECT * INTO q FROM securepay_private.quote_assignments WHERE tenant_id=t AND job_id=j AND owner_id=a FOR UPDATE;
 IF NOT FOUND OR q.quote_digest IS DISTINCT FROM expected_quote OR NOT EXISTS(SELECT 1 FROM securepay_private.quote_revisions r WHERE r.tenant_id=t AND r.job_id=j AND r.quote_digest=expected_quote) OR NOT EXISTS(SELECT 1 FROM public.securepay_payer_identities WHERE tenant_id=t AND customer_id=q.customer_id AND active) THEN RETURN NULL; END IF;
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
ALTER FUNCTION securepay_private.offer_payment_plan_bound(uuid,uuid,uuid,uuid,text,text,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.offer_payment_plan_bound(uuid,uuid,uuid,uuid,text,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.offer_payment_plan_bound(uuid,uuid,uuid,uuid,text,text,bigint,text) TO securepay_completion_runtime;
COMMIT;
