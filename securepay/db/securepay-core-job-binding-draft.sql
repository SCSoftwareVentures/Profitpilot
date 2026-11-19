-- Synthetic only. Independent privileged provisioning, separate owner confirmation.
BEGIN;
CREATE TABLE securepay_private.core_job_link_orders(
 tenant_id uuid NOT NULL,job_id uuid NOT NULL,contract_id uuid NOT NULL,site_id uuid NOT NULL,baseline_id uuid NOT NULL,
 customer_id uuid NOT NULL,owner_id uuid NOT NULL,review_digest text NOT NULL CHECK(review_digest ~ '^[a-f0-9]{64}$' AND review_digest<>repeat('0',64)),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,job_id),
 FOREIGN KEY(tenant_id,job_id) REFERENCES securepay_private.quote_job_parties(tenant_id,job_id),
 FOREIGN KEY(tenant_id,customer_id) REFERENCES public.securepay_payer_identities(tenant_id,customer_id),
 FOREIGN KEY(tenant_id,owner_id) REFERENCES securepay_private.dispute_actors(tenant_id,actor_id),
 CHECK(customer_id<>owner_id)
);
CREATE TABLE securepay_private.core_job_bindings(
 tenant_id uuid NOT NULL,job_id uuid NOT NULL,contract_id uuid NOT NULL,site_id uuid NOT NULL,baseline_id uuid NOT NULL,
 customer_id uuid NOT NULL,owner_id uuid NOT NULL,review_digest text NOT NULL,
 reference_digest text NOT NULL CHECK(reference_digest ~ '^[a-f0-9]{64}$' AND reference_digest<>repeat('0',64)),
 bound_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,job_id),FOREIGN KEY(tenant_id,job_id) REFERENCES securepay_private.core_job_link_orders(tenant_id,job_id)
);
ALTER TABLE securepay_private.core_job_link_orders OWNER TO securepay_context_owner;
ALTER TABLE securepay_private.core_job_bindings OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.core_job_link_orders,securepay_private.core_job_bindings FROM PUBLIC,securepay_completion_runtime,securepay_payer_runtime,securepay_provider_runtime,securepay_reporting_runtime,securepay_dispute_runtime;
CREATE FUNCTION securepay_private.deny_core_link_mutation() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'Core link history immutable' USING ERRCODE='55000'; END $$;
ALTER FUNCTION securepay_private.deny_core_link_mutation() OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.deny_core_link_mutation() FROM PUBLIC;
CREATE TRIGGER core_order_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON securepay_private.core_job_link_orders FOR EACH STATEMENT EXECUTE FUNCTION securepay_private.deny_core_link_mutation();
CREATE TRIGGER core_binding_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON securepay_private.core_job_bindings FOR EACH STATEMENT EXECUTE FUNCTION securepay_private.deny_core_link_mutation();
CREATE TRIGGER core_order_chain AFTER INSERT ON securepay_private.core_job_link_orders FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE TRIGGER core_binding_chain AFTER INSERT ON securepay_private.core_job_bindings FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
-- Provision only before ANY quote/plan/milestone exists. Serialize with publication
-- using the already existing quote job party row, not a client supplied lock key.
CREATE FUNCTION securepay_private.check_core_link_order() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p securepay_private.quote_job_parties%ROWTYPE;
BEGIN
 SELECT * INTO p FROM securepay_private.quote_job_parties WHERE tenant_id=NEW.tenant_id AND job_id=NEW.job_id FOR UPDATE;
 IF NOT FOUND OR p.customer_id<>NEW.customer_id OR p.owner_id<>NEW.owner_id
 OR NOT EXISTS(SELECT 1 FROM public.securepay_payer_identities WHERE tenant_id=NEW.tenant_id AND customer_id=NEW.customer_id AND active)
 OR NOT EXISTS(SELECT 1 FROM securepay_private.dispute_actors WHERE tenant_id=NEW.tenant_id AND actor_id=NEW.owner_id AND role='owner' AND active)
 OR EXISTS(SELECT 1 FROM securepay_private.quote_assignments WHERE tenant_id=NEW.tenant_id AND job_id=NEW.job_id)
 OR EXISTS(SELECT 1 FROM securepay_private.quote_revisions WHERE tenant_id=NEW.tenant_id AND job_id=NEW.job_id)
 OR EXISTS(SELECT 1 FROM securepay_private.payment_plans WHERE tenant_id=NEW.tenant_id AND job_id=NEW.job_id)
 OR EXISTS(SELECT 1 FROM public.securepay_milestones WHERE tenant_id=NEW.tenant_id AND job_id=NEW.job_id)
 THEN RAISE EXCEPTION 'Core link provisioning denied' USING ERRCODE='42501'; END IF;
 RETURN NEW;
END $$;
ALTER FUNCTION securepay_private.check_core_link_order() OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.check_core_link_order() FROM PUBLIC;
CREATE TRIGGER core_order_validate BEFORE INSERT ON securepay_private.core_job_link_orders FOR EACH ROW EXECUTE FUNCTION securepay_private.check_core_link_order();
CREATE FUNCTION securepay_private.freeze_core_link_parties() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM securepay_private.core_job_link_orders WHERE tenant_id=OLD.tenant_id AND job_id=OLD.job_id)
 THEN RAISE EXCEPTION 'Core link parties immutable' USING ERRCODE='55000'; END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;RETURN NEW;
END $$;
ALTER FUNCTION securepay_private.freeze_core_link_parties() OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.freeze_core_link_parties() FROM PUBLIC;
CREATE TRIGGER core_link_party_freeze BEFORE UPDATE OR DELETE ON securepay_private.quote_job_parties FOR EACH ROW EXECUTE FUNCTION securepay_private.freeze_core_link_parties();
-- The completion service verifies Ed25519 separately. DB independently verifies
-- its scoped owner HMAC, approved order, current participants, and time fences.
CREATE FUNCTION securepay_private.bind_core_job(t uuid,j uuid,a uuid,c uuid,s uuid,b uuid,review text,ref text,ref_exp bigint,exp bigint,sig text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p securepay_private.quote_job_parties%ROWTYPE;o securepay_private.core_job_link_orders%ROWTYPE;v securepay_private.core_job_bindings%ROWTYPE;n bigint;
BEGIN
 IF t IS NULL OR j IS NULL OR a IS NULL OR c IS NULL OR s IS NULL OR b IS NULL OR review IS NULL OR ref IS NULL
 OR review !~ '^[a-f0-9]{64}$' OR review=repeat('0',64) OR ref !~ '^[a-f0-9]{64}$' OR ref=repeat('0',64)
 OR ref_exp IS NULL OR securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-core-job-bind-v1',t,j,a,c,s,b,review,ref,ref_exp,exp),exp,sig) IS DISTINCT FROM 'owner' THEN RETURN NULL; END IF;
 SELECT * INTO p FROM securepay_private.quote_job_parties WHERE tenant_id=t AND job_id=j AND owner_id=a FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO o FROM securepay_private.core_job_link_orders WHERE tenant_id=t AND job_id=j FOR SHARE;
 IF NOT FOUND OR o.owner_id<>a OR o.customer_id<>p.customer_id OR o.contract_id<>c OR o.site_id<>s OR o.baseline_id<>b OR o.review_digest<>review
 OR NOT EXISTS(SELECT 1 FROM public.securepay_payer_identities WHERE tenant_id=t AND customer_id=p.customer_id AND active) THEN RETURN NULL; END IF;
 n:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF ref_exp<=n OR ref_exp>n+125 OR exp<n
 OR securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-core-job-bind-v1',t,j,a,c,s,b,review,ref,ref_exp,exp),exp,sig) IS DISTINCT FROM 'owner' THEN RETURN NULL; END IF;
 SELECT * INTO v FROM securepay_private.core_job_bindings WHERE tenant_id=t AND job_id=j;
 IF NOT FOUND THEN
  IF EXISTS(SELECT 1 FROM securepay_private.quote_assignments WHERE tenant_id=t AND job_id=j)
  OR EXISTS(SELECT 1 FROM securepay_private.quote_revisions WHERE tenant_id=t AND job_id=j)
  OR EXISTS(SELECT 1 FROM securepay_private.payment_plans WHERE tenant_id=t AND job_id=j)
  OR EXISTS(SELECT 1 FROM public.securepay_milestones WHERE tenant_id=t AND job_id=j) THEN RETURN NULL; END IF;
  INSERT INTO securepay_private.core_job_bindings(tenant_id,job_id,contract_id,site_id,baseline_id,customer_id,owner_id,review_digest,reference_digest)
  VALUES(t,j,c,s,b,p.customer_id,a,review,ref) RETURNING * INTO v;
 END IF;
 RETURN jsonb_build_object('jobId',v.job_id,'contractId',v.contract_id,'siteId',v.site_id,'baselineId',v.baseline_id,'reviewDigest',v.review_digest,'referenceDigest',v.reference_digest,'boundAt',v.bound_at);
END $$;
ALTER FUNCTION securepay_private.bind_core_job(uuid,uuid,uuid,uuid,uuid,uuid,text,text,bigint,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.bind_core_job(uuid,uuid,uuid,uuid,uuid,uuid,text,text,bigint,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.bind_core_job(uuid,uuid,uuid,uuid,uuid,uuid,text,text,bigint,bigint,text) TO securepay_completion_runtime;
-- Existing independent standalone sandbox jobs retain backwards compatibility.
-- For provisioned core jobs, both quote revisions and legacy assignments must
-- require an existing exact binding. Runtime roles have no direct table grants.
CREATE FUNCTION securepay_private.require_core_link() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE o securepay_private.core_job_link_orders%ROWTYPE;
BEGIN
 PERFORM 1 FROM securepay_private.quote_job_parties WHERE tenant_id=NEW.tenant_id AND job_id=NEW.job_id FOR UPDATE;
 SELECT * INTO o FROM securepay_private.core_job_link_orders WHERE tenant_id=NEW.tenant_id AND job_id=NEW.job_id;
 IF FOUND AND (o.owner_id<>NEW.owner_id OR o.customer_id<>NEW.customer_id OR NOT EXISTS(
 SELECT 1 FROM securepay_private.core_job_bindings v WHERE v.tenant_id=o.tenant_id AND v.job_id=o.job_id
 AND v.owner_id=o.owner_id AND v.customer_id=o.customer_id AND v.contract_id=o.contract_id AND v.site_id=o.site_id AND v.baseline_id=o.baseline_id AND v.review_digest=o.review_digest))
 THEN RAISE EXCEPTION 'Approved core job binding required' USING ERRCODE='42501'; END IF;
 RETURN NEW;
END $$;
ALTER FUNCTION securepay_private.require_core_link() OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.require_core_link() FROM PUBLIC;
CREATE TRIGGER core_link_quote_gate BEFORE INSERT ON securepay_private.quote_revisions FOR EACH ROW EXECUTE FUNCTION securepay_private.require_core_link();
CREATE TRIGGER core_link_assignment_gate BEFORE INSERT ON securepay_private.quote_assignments FOR EACH ROW EXECUTE FUNCTION securepay_private.require_core_link();
COMMIT;
