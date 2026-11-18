-- Session-attested, atomic review and confirmation for the private payroll workflow.
BEGIN;
DO $check$ BEGIN
 IF private.verify_security_catalog() IS DISTINCT FROM true THEN RAISE EXCEPTION 'Prior security catalog does not verify'; END IF;
END $check$;

CREATE TABLE private.payroll_confirmation_receipts(
 tenant_id uuid NOT NULL,
 allocation_run_id uuid NOT NULL,
 proposal_id uuid NOT NULL,
 reviewer_id uuid NOT NULL,
 evidence_digest text NOT NULL CHECK(evidence_digest ~ '^[a-f0-9]{64}$'),
 session_digest text NOT NULL CHECK(session_digest ~ '^[a-f0-9]{64}$'),
 auth_time bigint NOT NULL CHECK(auth_time>0),
 confirmed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,allocation_run_id),
 UNIQUE(tenant_id,proposal_id),
 FOREIGN KEY(tenant_id,allocation_run_id) REFERENCES public.allocation_runs(tenant_id,id),
 FOREIGN KEY(tenant_id,proposal_id) REFERENCES private.payroll_proposal_reviews(tenant_id,id),
 FOREIGN KEY(tenant_id,reviewer_id) REFERENCES public.tenant_memberships(tenant_id,user_id)
);
REVOKE ALL ON private.payroll_confirmation_receipts FROM PUBLIC,profitpilot_app;
CREATE TRIGGER payroll_confirmation_receipt_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.payroll_confirmation_receipts
 FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();

-- Existing administrator-only legacy fixture/import paths are not expanded.
-- Once a pool enters the new review workflow, every confirmation for that
-- pool must reference its own reviewed, session-attested receipt.
CREATE FUNCTION private.guard_managed_payroll_confirmation()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 IF NEW.status<>'confirmed' THEN RETURN NEW; END IF;
 PERFORM 1 FROM public.payroll_pools WHERE tenant_id=NEW.tenant_id AND id=NEW.payroll_pool_id FOR UPDATE;
 IF EXISTS(SELECT 1 FROM private.payroll_proposal_reviews pr JOIN public.allocation_runs ar
  ON ar.tenant_id=pr.tenant_id AND ar.id=pr.allocation_run_id
  WHERE ar.tenant_id=NEW.tenant_id AND ar.payroll_pool_id=NEW.payroll_pool_id)
 AND NOT EXISTS(
  SELECT 1 FROM private.payroll_confirmation_receipts c JOIN private.payroll_proposal_reviews pr
   ON pr.tenant_id=c.tenant_id AND pr.id=c.proposal_id AND pr.allocation_run_id=c.allocation_run_id AND pr.evidence_digest=c.evidence_digest
  JOIN private.payroll_proposal_decisions d ON d.tenant_id=c.tenant_id AND d.proposal_id=c.proposal_id
   AND d.reviewer_id=c.reviewer_id AND d.decision='reviewed'
  WHERE c.tenant_id=NEW.tenant_id AND c.allocation_run_id=NEW.id AND c.reviewer_id=NEW.reviewer_id
 ) THEN RAISE EXCEPTION 'Managed payroll requires a session-attested confirmation receipt' USING ERRCODE='42501'; END IF;
 RETURN NEW;
END $fn$;
CREATE TRIGGER allocation_runs_managed_confirmation BEFORE INSERT OR UPDATE ON public.allocation_runs
 FOR EACH ROW EXECUTE FUNCTION private.guard_managed_payroll_confirmation();

-- No runtime grants. The trusted service must first verify the JWT, fresh
-- MFA and user intent, then sign this specific action with the server key.
-- A generic session assertion or a signature for another proposal is useless.
CREATE FUNCTION private.confirm_payroll_proposal_attested(
 p_tenant uuid,p_proposal uuid,p_digest text,p_auth bigint,p_iat bigint,p_session text,
 p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS uuid LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; subject text; now_s bigint; secret_value bytea; expected text;
 proposal private.payroll_proposal_reviews%ROWTYPE;
BEGIN
 actor:=private.payroll_review_actor(p_tenant,true);
 subject:=nullif(current_setting('app.tenant_subject',true),'');
 now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF p_proposal IS NULL OR p_digest IS NULL OR p_digest !~ '^[a-f0-9]{64}$'
 OR p_auth IS NULL OR p_auth<=0 OR p_auth<now_s-300 OR p_auth>now_s+5
 OR p_iat IS NULL OR p_iat<now_s-905 OR p_iat>now_s+5 OR p_auth>p_iat+5
 OR p_session IS NULL OR p_session !~ '^[a-f0-9]{64}$'
 OR p_expires IS NULL OR p_expires<now_s OR p_expires>now_s+30
 OR p_nonce IS NULL OR p_nonce !~ '^[a-f0-9]{32}$'
 OR p_key IS NULL OR p_key !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'
 OR p_signature IS NULL OR p_signature !~ '^[a-f0-9]{64}$'
 THEN RAISE EXCEPTION 'Invalid payroll confirmation authority' USING ERRCODE='42501'; END IF;
 SELECT secret INTO secret_value FROM private.tenant_context_keys WHERE key_id=p_key AND active FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Payroll confirmation key unavailable' USING ERRCODE='42501'; END IF;
 expected:=encode(public.hmac(convert_to('profitpilot-payroll-confirm-v1'||E'\n'||p_tenant||E'\n'||p_proposal||E'\n'||p_digest||E'\n'||subject||E'\n'||p_auth||E'\n'||p_iat||E'\n'||p_session||E'\n'||p_expires||E'\n'||p_nonce||E'\n'||p_key,'UTF8'),secret_value,'sha256'),'hex');
 IF expected IS DISTINCT FROM p_signature
 OR EXISTS(SELECT 1 FROM private.identity_session_cutoffs WHERE user_id=actor AND revoked_through>=p_auth)
 OR EXISTS(SELECT 1 FROM private.revoked_identity_sessions WHERE user_id=actor AND session_digest=p_session)
 THEN RAISE EXCEPTION 'Payroll confirmation authority denied' USING ERRCODE='42501'; END IF;
 SELECT * INTO proposal FROM private.payroll_proposal_reviews WHERE tenant_id=p_tenant AND id=p_proposal FOR UPDATE;
 IF NOT FOUND OR proposal.submitted_by=actor OR proposal.evidence_digest IS DISTINCT FROM p_digest THEN
  RAISE EXCEPTION 'Payroll confirmation authority denied' USING ERRCODE='42501'; END IF;
 -- Seat the decision, immutable receipt, existing invariant checks, final
 -- status and chained audit in one transaction. Any failure rolls all back.
 PERFORM private.decide_payroll_proposal(p_tenant,p_proposal,p_digest,'reviewed');
 INSERT INTO private.payroll_confirmation_receipts(tenant_id,allocation_run_id,proposal_id,reviewer_id,evidence_digest,session_digest,auth_time)
 VALUES(p_tenant,proposal.allocation_run_id,p_proposal,actor,p_digest,p_session,p_auth);
 UPDATE public.allocation_runs SET status='confirmed',reviewer_id=actor
 WHERE tenant_id=p_tenant AND id=proposal.allocation_run_id AND status='review' AND reviewer_id IS NULL;
 IF NOT FOUND THEN RAISE EXCEPTION 'Payroll confirmation state changed' USING ERRCODE='23514'; END IF;
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
 VALUES(p_tenant,actor,'payroll_allocation_confirmed','allocation_run',proposal.allocation_run_id,
 jsonb_build_object('proposalId',p_proposal,'evidenceDigest',p_digest));
 RETURN proposal.allocation_run_id;
END $fn$;

-- Protect evidence of newly managed confirmations against subsequent
-- appends and metadata edits. Legacy admin-only records retain prior rules.
CREATE FUNCTION private.guard_confirmed_payroll_evidence()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE t uuid; pool_id uuid; batch_id_value uuid; run_id uuid;
BEGIN
 IF TG_TABLE_NAME='allocation_lines' THEN
  t:=NEW.tenant_id; run_id:=NEW.allocation_run_id;
  SELECT payroll_pool_id INTO pool_id FROM public.allocation_runs WHERE tenant_id=t AND id=run_id FOR UPDATE;
 ELSIF TG_TABLE_NAME='payroll_source_rows' THEN
  t:=NEW.tenant_id; pool_id:=NEW.payroll_pool_id;
  PERFORM 1 FROM public.payroll_pools WHERE tenant_id=t AND id=pool_id FOR UPDATE;
 ELSIF TG_TABLE_NAME='payroll_pools' THEN
  IF TG_OP='INSERT' THEN t:=NEW.tenant_id; batch_id_value:=NEW.batch_id;
   PERFORM 1 FROM public.import_batches WHERE tenant_id=t AND id=batch_id_value FOR UPDATE;
  ELSE t:=OLD.tenant_id; pool_id:=OLD.id; END IF;
 ELSIF TG_TABLE_NAME='raw_import_rows' THEN
  IF TG_OP='INSERT' THEN t:=NEW.tenant_id; batch_id_value:=NEW.batch_id;
  ELSE t:=OLD.tenant_id; batch_id_value:=OLD.batch_id; END IF;
  -- Do not change the invoice staging path.
  IF NOT EXISTS(SELECT 1 FROM public.import_batches WHERE tenant_id=t AND id=batch_id_value AND source_type='payroll')
   AND (TG_OP<>'UPDATE' OR NOT EXISTS(SELECT 1 FROM public.import_batches WHERE tenant_id=NEW.tenant_id AND id=NEW.batch_id AND source_type='payroll')) THEN
   IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW;
  END IF;
  PERFORM 1 FROM public.import_batches WHERE tenant_id=t AND id=batch_id_value FOR UPDATE;
  IF TG_OP='UPDATE' AND ROW(OLD.tenant_id,OLD.batch_id) IS DISTINCT FROM ROW(NEW.tenant_id,NEW.batch_id) THEN
   RAISE EXCEPTION 'Raw payroll evidence cannot be moved' USING ERRCODE='55000'; END IF;
 ELSE
  t:=OLD.tenant_id; batch_id_value:=OLD.id;
 END IF;
 IF EXISTS(SELECT 1 FROM private.payroll_confirmation_receipts c JOIN public.allocation_runs ar
  ON ar.tenant_id=c.tenant_id AND ar.id=c.allocation_run_id
  JOIN public.payroll_pools pp ON pp.tenant_id=ar.tenant_id AND pp.id=ar.payroll_pool_id
  WHERE c.tenant_id=t AND (ar.payroll_pool_id=pool_id OR pp.batch_id=batch_id_value))
 THEN RAISE EXCEPTION 'Confirmed payroll evidence is immutable' USING ERRCODE='55000'; END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $fn$;
CREATE TRIGGER payroll_confirmed_line_guard BEFORE INSERT ON public.allocation_lines
 FOR EACH ROW EXECUTE FUNCTION private.guard_confirmed_payroll_evidence();
CREATE TRIGGER payroll_confirmed_source_guard BEFORE INSERT ON public.payroll_source_rows
 FOR EACH ROW EXECUTE FUNCTION private.guard_confirmed_payroll_evidence();
CREATE TRIGGER payroll_confirmed_pool_guard BEFORE INSERT OR UPDATE OR DELETE ON public.payroll_pools
 FOR EACH ROW EXECUTE FUNCTION private.guard_confirmed_payroll_evidence();
-- Runtime invoice staging remains unchanged: the definer can check the
-- private receipt without giving the runtime role a direct read grant.
ALTER FUNCTION private.guard_confirmed_payroll_evidence() SECURITY DEFINER;
CREATE TRIGGER payroll_confirmed_raw_guard BEFORE INSERT OR UPDATE OR DELETE ON public.raw_import_rows
 FOR EACH ROW EXECUTE FUNCTION private.guard_confirmed_payroll_evidence();
CREATE TRIGGER payroll_confirmed_batch_guard BEFORE UPDATE OR DELETE ON public.import_batches
 FOR EACH ROW EXECUTE FUNCTION private.guard_confirmed_payroll_evidence();

REVOKE ALL ON FUNCTION private.guard_managed_payroll_confirmation(),private.guard_confirmed_payroll_evidence(),
 private.confirm_payroll_proposal_attested(uuid,uuid,text,bigint,bigint,text,bigint,text,text,text) FROM PUBLIC,profitpilot_app;
CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=46),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,46,private.security_catalog_digest());
COMMIT;
