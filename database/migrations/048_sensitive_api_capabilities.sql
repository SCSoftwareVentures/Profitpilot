-- Exact-purpose API capabilities; no underlying relation or raw evidence grants.
BEGIN;
DO $check$ BEGIN
 IF private.verify_security_catalog() IS DISTINCT FROM true THEN RAISE EXCEPTION 'Prior security catalog does not verify'; END IF;
END $check$;

CREATE FUNCTION private.sensitive_api_actor(
 p_tenant uuid,p_target uuid,p_action text,p_scope text,p_auth bigint,p_iat bigint,
 p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS uuid LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; actor_role text; subject text; now_s bigint; key_bytes bytea; expected text;
BEGIN
 IF p_tenant IS NULL OR p_target IS NULL OR private.current_tenant_id() IS DISTINCT FROM p_tenant
 OR private.lock_tenant_available(p_tenant) IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 subject:=nullif(current_setting('app.tenant_subject',true),'');
 SELECT u.id,m.role INTO actor,actor_role FROM public.users u JOIN public.tenant_memberships m ON m.user_id=u.id
 WHERE u.auth_subject=subject AND u.status='active' AND m.tenant_id=p_tenant AND m.status='active' FOR SHARE OF u,m;
 IF NOT FOUND THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 IF p_action IS NULL OR p_action NOT IN ('payroll_submit','payroll_read','account_read','account_correct_email','invoice_disposal_preview')
 OR (p_action='payroll_submit' AND actor_role NOT IN ('owner','admin','analyst'))
 OR (p_action='payroll_read' AND actor_role NOT IN ('owner','admin','reviewer'))
 OR (p_action='invoice_disposal_preview' AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('account_read','account_correct_email') AND p_target<>p_tenant)
 THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF p_scope IS NULL OR p_scope !~ '^[a-f0-9]{64}$'
 OR (p_action='account_correct_email' AND p_scope=repeat('0',64))
 OR (p_action<>'account_correct_email' AND p_scope<>repeat('0',64))
 OR p_auth IS NULL OR p_auth<=0 OR p_auth<now_s-300 OR p_auth>now_s+5
 OR p_iat IS NULL OR p_iat<now_s-905 OR p_iat>now_s+5 OR p_auth>p_iat+5
 OR p_session IS NULL OR p_session !~ '^[a-f0-9]{64}$'
 OR p_expires IS NULL OR p_expires<now_s OR p_expires>now_s+30
 OR p_nonce IS NULL OR p_nonce !~ '^[a-f0-9]{32}$'
 OR p_key IS NULL OR p_key !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$'
 OR p_signature IS NULL OR p_signature !~ '^[a-f0-9]{64}$'
 THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 SELECT secret INTO key_bytes FROM private.tenant_context_keys WHERE key_id=p_key AND active FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 expected:=encode(public.hmac(convert_to('profitpilot-sensitive-api-v1'||E'\n'||p_tenant||E'\n'||p_target||E'\n'||p_action||E'\n'||p_scope||E'\n'||subject||E'\n'||p_auth||E'\n'||p_iat||E'\n'||p_session||E'\n'||p_expires||E'\n'||p_nonce||E'\n'||p_key,'UTF8'),key_bytes,'sha256'),'hex');
 IF expected IS DISTINCT FROM p_signature
 OR EXISTS(SELECT 1 FROM private.identity_session_cutoffs WHERE user_id=actor AND revoked_through>=p_auth)
 OR EXISTS(SELECT 1 FROM private.revoked_identity_sessions WHERE user_id=actor AND session_digest=p_session)
 THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 RETURN actor;
END $fn$;

CREATE FUNCTION private.sensitive_api_fresh(p_auth bigint,p_expires bigint)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 IF floor(extract(epoch FROM clock_timestamp()))::bigint>p_expires
 OR floor(extract(epoch FROM clock_timestamp()))::bigint>p_auth+300 THEN
  RAISE EXCEPTION 'Sensitive operation expired' USING ERRCODE='42501'; END IF;
END $fn$;

-- Aggregate values only. The pending digest must still describe the actual
-- locked source. Reject instead of returning a misleading stale summary.
CREATE FUNCTION private.payroll_api_summary(p_tenant uuid,p_proposal uuid)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE pr private.payroll_proposal_reviews%ROWTYPE; outcome text; result jsonb;
BEGIN
 SELECT * INTO pr FROM private.payroll_proposal_reviews WHERE tenant_id=p_tenant AND id=p_proposal FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Proposal unavailable' USING ERRCODE='42501'; END IF;
 SELECT decision INTO outcome FROM private.payroll_proposal_decisions WHERE tenant_id=p_tenant AND proposal_id=p_proposal;
 IF outcome='reviewed' AND NOT EXISTS(SELECT 1 FROM private.payroll_confirmation_receipts WHERE tenant_id=p_tenant AND proposal_id=p_proposal AND evidence_digest=pr.evidence_digest) THEN
  RETURN jsonb_build_object('proposalId',pr.id,'evidenceDigest',pr.evidence_digest,'status','reviewed_not_confirmed'); END IF;
 IF outcome='rejected' THEN RETURN jsonb_build_object('proposalId',pr.id,'evidenceDigest',pr.evidence_digest,'status','rejected'); END IF;
 IF outcome IS NULL AND private.payroll_review_digest(p_tenant,pr.allocation_run_id) IS DISTINCT FROM pr.evidence_digest THEN
  RAISE EXCEPTION 'Proposal evidence changed' USING ERRCODE='23514'; END IF;
 SELECT jsonb_build_object('proposalId',pr.id,'allocationRunId',r.id,'evidenceDigest',pr.evidence_digest,
  'status',CASE WHEN r.status='confirmed' THEN 'confirmed' WHEN outcome='reviewed' THEN 'reviewed' ELSE 'pending_review' END,
  'currency',p.currency,'periodStart',p.period_start,'periodEnd',p.period_end,
  'total',p.total_amount::text,'direct',r.direct_amount::text,'allocated',r.allocated_amount::text,
  'nonSite',r.non_site_amount::text,'excluded',r.excluded_amount::text,'residual',r.residual_amount::text)
 INTO result FROM public.allocation_runs r JOIN public.payroll_pools p ON p.tenant_id=r.tenant_id AND p.id=r.payroll_pool_id
 WHERE r.tenant_id=p_tenant AND r.id=pr.allocation_run_id;
 IF result IS NULL THEN RAISE EXCEPTION 'Proposal unavailable' USING ERRCODE='42501'; END IF;
 RETURN result;
END $fn$;

CREATE FUNCTION private.api_payroll_review(
 p_tenant uuid,p_target uuid,p_action text,p_scope text,p_auth bigint,p_iat bigint,
 p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE proposal uuid; result jsonb;
BEGIN
 IF p_action IS NULL OR p_action NOT IN ('payroll_submit','payroll_read') THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 PERFORM private.sensitive_api_actor(p_tenant,p_target,p_action,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF p_action='payroll_submit' THEN proposal:=private.submit_payroll_proposal(p_tenant,p_target); ELSE proposal:=p_target; END IF;
 result:=private.payroll_api_summary(p_tenant,proposal);
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 RETURN result;
END $fn$;

CREATE FUNCTION private.api_confirm_payroll(
 p_tenant uuid,p_proposal uuid,p_digest text,p_auth bigint,p_iat bigint,p_session text,
 p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 PERFORM private.confirm_payroll_proposal_attested(p_tenant,p_proposal,p_digest,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 RETURN private.payroll_api_summary(p_tenant,p_proposal);
END $fn$;

-- Self-service only. The server signs the exact issuer-verified email;
-- never accept a target account ID or an arbitrary requested new address.
-- No change to subject, membership, authentication factors, or audit history.
CREATE FUNCTION private.api_account_privacy(
 p_tenant uuid,p_target uuid,p_action text,p_scope text,p_auth bigint,p_iat bigint,
 p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text,p_email text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; result jsonb;
BEGIN
 IF p_action IS NULL OR p_action NOT IN ('account_read','account_correct_email') THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 -- Acquire identity write lock before the read/actor helper to avoid lock
 -- upgrades with concurrent self-corrections. Signed tenant context first.
 IF private.current_tenant_id() IS DISTINCT FROM p_tenant OR private.lock_tenant_available(p_tenant) IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 IF p_action='account_correct_email' THEN
  PERFORM 1 FROM public.users WHERE auth_subject=nullif(current_setting('app.tenant_subject',true),'') FOR UPDATE;
 END IF;
 actor:=private.sensitive_api_actor(p_tenant,p_target,p_action,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF p_action='account_correct_email' THEN
  IF p_email IS NULL OR char_length(p_email) NOT BETWEEN 3 AND 254 OR p_email !~ '^[^[:space:]@[:cntrl:]]+@[^[:space:]@[:cntrl:]]+$'
  OR encode(public.digest(convert_to(p_email,'UTF8'),'sha256'),'hex') IS DISTINCT FROM p_scope
  THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
  -- Record-bound and single-use within its signed session/nonce.
  IF EXISTS(SELECT 1 FROM private.account_correction_nonces WHERE user_id=actor AND (auth_time>=p_auth OR issued_at>p_iat)) THEN
   RAISE EXCEPTION 'New issuer authentication required' USING ERRCODE='42501'; END IF;
  INSERT INTO private.account_correction_nonces(user_id,nonce,auth_time,issued_at) VALUES(actor,p_nonce,p_auth,p_iat);
  UPDATE public.users SET email=p_email WHERE id=actor AND email IS DISTINCT FROM p_email;
 ELSE
  IF p_email IS NOT NULL THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 END IF;
 SELECT jsonb_build_object('accountId',u.id,'email',u.email,'accountStatus',u.status,
   'tenantId',m.tenant_id,'role',m.role,'membershipStatus',m.status,'membershipGrantedAt',m.granted_at)
 INTO result FROM public.users u JOIN public.tenant_memberships m ON m.user_id=u.id
 WHERE u.id=actor AND m.tenant_id=p_tenant;
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
 VALUES(p_tenant,actor,CASE p_action WHEN 'account_read' THEN 'privacy_account_access' ELSE 'privacy_account_email_corrected' END,
 'account',actor,jsonb_build_object('scope','own_account'));
 RETURN result;
END $fn$;

CREATE TABLE private.account_correction_nonces(
 user_id uuid NOT NULL REFERENCES public.users(id),
 nonce text NOT NULL CHECK(nonce ~ '^[a-f0-9]{32}$'),
 auth_time bigint NOT NULL CHECK(auth_time>0),
 issued_at bigint NOT NULL CHECK(issued_at>=auth_time-5),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(user_id,nonce)
);
CREATE INDEX account_correction_auth_idx ON private.account_correction_nonces(user_id,auth_time DESC,issued_at DESC);
REVOKE ALL ON private.account_correction_nonces FROM PUBLIC,profitpilot_app;
-- Replay prevention is only needed for the maximum 30-second proof lifetime.
-- A trusted maintenance administrator may periodically erase old nonces.
CREATE FUNCTION private.purge_account_correction_nonces()
RETURNS bigint LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE removed bigint;
BEGIN
 DELETE FROM private.account_correction_nonces WHERE recorded_at<clock_timestamp()-interval '1 day';
 GET DIAGNOSTICS removed=ROW_COUNT; RETURN removed;
END $fn$;

-- Operation-specific temporary authority: an approved order enables one
-- disposal of the exact eligible invoice staging record, never a DB role.
CREATE FUNCTION private.api_invoice_disposal_preview(
 p_tenant uuid,p_batch uuid,p_action text,p_scope text,p_auth bigint,p_iat bigint,
 p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE result text;
BEGIN
 IF p_action IS DISTINCT FROM 'invoice_disposal_preview' THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 PERFORM private.sensitive_api_actor(p_tenant,p_batch,p_action,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 result:=private.invoice_disposal_work_scope(p_tenant,p_batch);
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 RETURN result;
END $fn$;

CREATE FUNCTION private.api_invoice_disposal_step(
 p_tenant uuid,p_order uuid,p_batch uuid,p_scope text,p_step text,p_auth bigint,p_iat bigint,
 p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE removed integer;
BEGIN
 IF p_step IS NULL OR p_step NOT IN ('request','approve','reject','consume') THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 PERFORM private.security_work_actor(p_tenant,p_order,'privacy_disposal',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF private.invoice_disposal_work_scope(p_tenant,p_batch) IS DISTINCT FROM p_scope THEN
  RAISE EXCEPTION 'Disposal scope changed' USING ERRCODE='42501'; END IF;
 IF p_step='consume' THEN
  removed:=private.execute_attested_invoice_disposal(p_tenant,p_order,p_batch,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 ELSE
  PERFORM private.record_security_work(p_tenant,p_order,'privacy_disposal',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 END IF;
 RETURN jsonb_build_object('orderId',p_order,'batchId',p_batch,'step',p_step,'removedRows',removed);
END $fn$;

REVOKE ALL ON FUNCTION private.sensitive_api_actor(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text),
 private.sensitive_api_fresh(bigint,bigint),private.payroll_api_summary(uuid,uuid),
 private.purge_account_correction_nonces(),
 private.api_payroll_review(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text),
 private.api_confirm_payroll(uuid,uuid,text,bigint,bigint,text,bigint,text,text,text),
 private.api_account_privacy(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,text),
 private.api_invoice_disposal_preview(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text),
 private.api_invoice_disposal_step(uuid,uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION
 private.api_payroll_review(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text),
 private.api_confirm_payroll(uuid,uuid,text,bigint,bigint,text,bigint,text,text,text),
 private.api_account_privacy(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,text),
 private.api_invoice_disposal_preview(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text),
 private.api_invoice_disposal_step(uuid,uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text) TO profitpilot_app;
CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=48),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,48,private.security_catalog_digest());
COMMIT;
