-- Private, provisional payroll review ledger. No runtime grant or final confirmation.
BEGIN;
DO $check$ BEGIN
 IF private.verify_security_catalog() IS DISTINCT FROM true THEN RAISE EXCEPTION 'Prior security catalog does not verify'; END IF;
END $check$;

CREATE TABLE private.payroll_proposal_reviews(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id uuid NOT NULL,
 allocation_run_id uuid NOT NULL,
 evidence_digest text NOT NULL CHECK(length(evidence_digest)=64 AND evidence_digest ~ '^[a-f0-9]+$'),
 submitted_by uuid NOT NULL,
 submitted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(tenant_id,id),
 UNIQUE(tenant_id,allocation_run_id,evidence_digest),
 FOREIGN KEY(tenant_id,allocation_run_id) REFERENCES public.allocation_runs(tenant_id,id),
 FOREIGN KEY(tenant_id,submitted_by) REFERENCES public.tenant_memberships(tenant_id,user_id)
);
CREATE TABLE private.payroll_proposal_decisions(
 tenant_id uuid NOT NULL,
 proposal_id uuid NOT NULL,
 reviewer_id uuid NOT NULL,
 decision text NOT NULL CHECK(decision IN ('reviewed','rejected')),
 decided_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,proposal_id),
 FOREIGN KEY(tenant_id,proposal_id) REFERENCES private.payroll_proposal_reviews(tenant_id,id),
 FOREIGN KEY(tenant_id,reviewer_id) REFERENCES public.tenant_memberships(tenant_id,user_id)
);
REVOKE ALL ON private.payroll_proposal_reviews,private.payroll_proposal_decisions FROM PUBLIC,profitpilot_app;
CREATE TRIGGER payroll_proposal_reviews_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.payroll_proposal_reviews
 FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE TRIGGER payroll_proposal_decisions_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.payroll_proposal_decisions
 FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();

-- Caller must use a fresh signed tenant context. Only a trusted internal
-- service may invoke these functions; they remain unavailable to API roles.
CREATE FUNCTION private.payroll_review_actor(p_tenant uuid,p_review boolean)
RETURNS uuid LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE actor uuid;
BEGIN
 IF p_review IS NULL OR p_tenant IS NULL OR private.current_tenant_id() IS DISTINCT FROM p_tenant
 OR private.lock_tenant_available(p_tenant) IS DISTINCT FROM true THEN
  RAISE EXCEPTION 'Payroll review authority denied' USING ERRCODE='42501';
 END IF;
 SELECT u.id INTO actor FROM public.users u JOIN public.tenant_memberships m ON m.user_id=u.id
 WHERE u.auth_subject=nullif(current_setting('app.tenant_subject',true),'') AND u.status='active'
 AND m.tenant_id=p_tenant AND m.status='active'
 AND (m.role IN ('owner','admin') OR (p_review AND m.role='reviewer') OR (NOT p_review AND m.role='analyst'))
 FOR SHARE OF u,m;
 IF NOT FOUND THEN RAISE EXCEPTION 'Payroll review authority denied' USING ERRCODE='42501'; END IF;
 RETURN actor;
END $fn$;

-- Bind the actual database evidence, not an untrusted client-supplied digest.
-- All reads use the scoped tenant; lock parent rows against concurrent edits.
CREATE FUNCTION private.payroll_review_digest(p_tenant uuid,p_run uuid)
RETURNS text LANGUAGE plpgsql SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE r public.allocation_runs%ROWTYPE; p public.payroll_pools%ROWTYPE; b public.import_batches%ROWTYPE;
 source_count bigint; line_count bigint; source_total numeric; summary record; source_digest text; line_digest text;
BEGIN
 IF p_tenant IS NULL OR p_run IS NULL OR private.current_tenant_id() IS DISTINCT FROM p_tenant THEN
  RAISE EXCEPTION 'Payroll review authority denied' USING ERRCODE='42501'; END IF;
 SELECT pp.* INTO p FROM public.allocation_runs ar JOIN public.payroll_pools pp
 ON pp.tenant_id=ar.tenant_id AND pp.id=ar.payroll_pool_id
 WHERE ar.tenant_id=p_tenant AND ar.id=p_run;
 IF NOT FOUND THEN RAISE EXCEPTION 'Payroll proposal unavailable' USING ERRCODE='22023'; END IF;
 SELECT * INTO b FROM public.import_batches WHERE tenant_id=p_tenant AND id=p.batch_id FOR UPDATE;
 IF NOT FOUND OR b.source_type<>'payroll' OR b.status<>'accepted' OR btrim(b.permission_ref)=''
 OR b.file_sha256 !~ '^[a-f0-9]{64}$' THEN
  RAISE EXCEPTION 'Payroll source is not accepted' USING ERRCODE='23514'; END IF;
 SELECT * INTO p FROM public.payroll_pools WHERE tenant_id=p_tenant AND id=p.id AND batch_id=b.id FOR UPDATE;
 IF NOT FOUND OR p.period_start IS DISTINCT FROM b.source_period_start OR p.period_end IS DISTINCT FROM b.source_period_end THEN
  RAISE EXCEPTION 'Payroll pool source period mismatch' USING ERRCODE='23514'; END IF;
 SELECT * INTO r FROM public.allocation_runs WHERE tenant_id=p_tenant AND id=p_run AND payroll_pool_id=p.id FOR UPDATE;
 IF NOT FOUND OR r.status<>'review' OR r.reviewer_id IS NOT NULL OR r.residual_amount<>0 THEN
  RAISE EXCEPTION 'Only complete unconfirmed review runs are eligible' USING ERRCODE='23514'; END IF;
 IF EXISTS(SELECT 1 FROM private.import_disposal_controls WHERE tenant_id=p_tenant AND batch_id=b.id AND hold_active)
 OR EXISTS(SELECT 1 FROM private.import_disposal_tombstones WHERE tenant_id=p_tenant AND batch_id=b.id) THEN
  RAISE EXCEPTION 'Payroll source unavailable' USING ERRCODE='23514'; END IF;

 SELECT count(*),coalesce(sum(amount),0) INTO source_count,source_total
 FROM public.payroll_source_rows WHERE tenant_id=p_tenant AND payroll_pool_id=p.id;
 SELECT count(*) INTO line_count FROM public.allocation_lines WHERE tenant_id=p_tenant AND allocation_run_id=r.id;
 IF source_count NOT BETWEEN 1 AND 10000 OR line_count>50000 OR source_total<>p.total_amount
 OR source_count<>(SELECT count(*) FROM public.raw_import_rows WHERE tenant_id=p_tenant AND batch_id=b.id)
 OR source_count<>(SELECT count(DISTINCT raw_import_row_id) FROM public.payroll_source_rows WHERE tenant_id=p_tenant AND payroll_pool_id=p.id)
 OR EXISTS(SELECT 1 FROM public.payroll_pools WHERE tenant_id=p_tenant AND batch_id=b.id AND id<>p.id) THEN
  RAISE EXCEPTION 'Payroll evidence does not reconcile or exceeds capacity' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.raw_import_rows WHERE tenant_id=p_tenant AND batch_id=b.id FOR SHARE;
 IF EXISTS(
  SELECT 1 FROM public.payroll_source_rows s JOIN public.raw_import_rows raw ON raw.tenant_id=s.tenant_id AND raw.id=s.raw_import_row_id
  LEFT JOIN (SELECT payroll_source_row_id,sum(amount) amount FROM public.allocation_lines
   WHERE tenant_id=p_tenant AND allocation_run_id=r.id GROUP BY payroll_source_row_id) a ON a.payroll_source_row_id=s.id
  WHERE s.tenant_id=p_tenant AND s.payroll_pool_id=p.id
  AND (s.currency<>p.currency OR raw.batch_id<>b.id OR coalesce(a.amount,0)<>s.amount
   OR raw.payload IS DISTINCT FROM jsonb_build_object('source_row_key',s.source_row_key,'amount',s.amount::text,'currency',s.currency::text)
   OR s.row_sha256<>encode(public.digest(convert_to(s.source_row_key||E'\n'||s.amount::text||E'\n'||s.currency::text,'UTF8'),'sha256'),'hex'))
 ) OR EXISTS(
  SELECT 1 FROM public.allocation_lines l LEFT JOIN public.payroll_source_rows s
   ON s.tenant_id=l.tenant_id AND s.id=l.payroll_source_row_id AND s.payroll_pool_id=p.id
  WHERE l.tenant_id=p_tenant AND l.allocation_run_id=r.id
   AND (s.id IS NULL OR l.amount<=0 OR l.bucket_type='unallocated'
    OR l.source_ref IS NULL OR NOT private.disposal_reference_valid(l.source_ref)
    OR (l.bucket_type IN ('direct','approved_allocated')) IS DISTINCT FROM (l.site_id IS NOT NULL))
 ) OR EXISTS(
  SELECT 1 FROM public.allocation_lines WHERE tenant_id=p_tenant AND allocation_run_id=r.id
  GROUP BY payroll_source_row_id,bucket_type,site_id HAVING count(*)>1
 ) THEN RAISE EXCEPTION 'Payroll row lineage or allocation evidence invalid' USING ERRCODE='23514'; END IF;
 SELECT coalesce(sum(amount) FILTER(WHERE bucket_type='direct'),0) direct,
  coalesce(sum(amount) FILTER(WHERE bucket_type='approved_allocated'),0) allocated,
  coalesce(sum(amount) FILTER(WHERE bucket_type='non_site'),0) non_site,
  coalesce(sum(amount) FILTER(WHERE bucket_type='excluded'),0) excluded
 INTO summary FROM public.allocation_lines WHERE tenant_id=p_tenant AND allocation_run_id=r.id;
 IF ROW(summary.direct,summary.allocated,summary.non_site,summary.excluded)
 IS DISTINCT FROM ROW(r.direct_amount,r.allocated_amount,r.non_site_amount,r.excluded_amount) THEN
  RAISE EXCEPTION 'Payroll allocation summary mismatch' USING ERRCODE='23514'; END IF;
 SELECT encode(public.digest(convert_to(coalesce(jsonb_agg(jsonb_build_array(s.id,s.raw_import_row_id,s.row_sha256,s.amount::text,s.currency) ORDER BY s.id),'[]'::jsonb)::text,'UTF8'),'sha256'),'hex')
 INTO source_digest FROM public.payroll_source_rows s WHERE s.tenant_id=p_tenant AND s.payroll_pool_id=p.id;
 SELECT encode(public.digest(convert_to(coalesce(jsonb_agg(jsonb_build_array(l.id,l.payroll_source_row_id,l.site_id,l.bucket_type,l.amount::text,l.source_ref) ORDER BY l.id),'[]'::jsonb)::text,'UTF8'),'sha256'),'hex')
 INTO line_digest FROM public.allocation_lines l WHERE l.tenant_id=p_tenant AND l.allocation_run_id=r.id;
 RETURN encode(public.digest(convert_to(jsonb_build_array('payroll-db-review-v1',p_tenant,r.id,r.method_version,p.id,p.period_start,p.period_end,p.currency,p.total_amount::text,p.source_ref,b.id,b.file_sha256,b.permission_ref,source_digest,line_digest)::text,'UTF8'),'sha256'),'hex');
END $fn$;

CREATE FUNCTION private.submit_payroll_proposal(p_tenant uuid,p_run uuid)
RETURNS uuid LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; d text; proposal uuid;
BEGIN
 actor:=private.payroll_review_actor(p_tenant,false);
 d:=private.payroll_review_digest(p_tenant,p_run);
 INSERT INTO private.payroll_proposal_reviews(tenant_id,allocation_run_id,evidence_digest,submitted_by)
 VALUES(p_tenant,p_run,d,actor) ON CONFLICT(tenant_id,allocation_run_id,evidence_digest) DO NOTHING
 RETURNING id INTO proposal;
 IF proposal IS NULL THEN
  SELECT id INTO proposal FROM private.payroll_proposal_reviews WHERE tenant_id=p_tenant AND allocation_run_id=p_run AND evidence_digest=d;
 ELSE
  INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
  VALUES(p_tenant,actor,'payroll_proposal_submitted','payroll_proposal',proposal,jsonb_build_object('evidenceDigest',d));
 END IF;
 RETURN proposal;
END $fn$;

CREATE FUNCTION private.decide_payroll_proposal(p_tenant uuid,p_proposal uuid,p_digest text,p_decision text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; proposal private.payroll_proposal_reviews%ROWTYPE; actual text;
BEGIN
 actor:=private.payroll_review_actor(p_tenant,true);
 IF p_proposal IS NULL OR p_decision IS NULL OR p_decision NOT IN ('reviewed','rejected')
 OR p_digest IS NULL OR length(p_digest)<>64 OR p_digest !~ '^[a-f0-9]+$' THEN
  RAISE EXCEPTION 'Invalid payroll review decision' USING ERRCODE='22023'; END IF;
 SELECT * INTO proposal FROM private.payroll_proposal_reviews WHERE tenant_id=p_tenant AND id=p_proposal FOR UPDATE;
 IF NOT FOUND OR proposal.submitted_by=actor THEN RAISE EXCEPTION 'Payroll review authority denied' USING ERRCODE='42501'; END IF;
 IF proposal.evidence_digest IS DISTINCT FROM p_digest THEN RAISE EXCEPTION 'Payroll proposal digest mismatch' USING ERRCODE='23514'; END IF;
 IF EXISTS(SELECT 1 FROM private.payroll_proposal_decisions WHERE tenant_id=p_tenant AND proposal_id=p_proposal) THEN
  RAISE EXCEPTION 'Payroll proposal already decided' USING ERRCODE='23505'; END IF;
 IF p_decision='reviewed' THEN
  actual:=private.payroll_review_digest(p_tenant,proposal.allocation_run_id);
  IF actual IS DISTINCT FROM p_digest THEN RAISE EXCEPTION 'Payroll proposal evidence changed' USING ERRCODE='23514'; END IF;
 END IF;
 INSERT INTO private.payroll_proposal_decisions(tenant_id,proposal_id,reviewer_id,decision)
 VALUES(p_tenant,p_proposal,actor,p_decision);
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
 VALUES(p_tenant,actor,'payroll_proposal_decided','payroll_proposal',p_proposal,jsonb_build_object('decision',p_decision,'evidenceDigest',p_digest));
 -- Deliberately never updates allocation_runs.status or authorises payment.
END $fn$;
REVOKE ALL ON FUNCTION private.payroll_review_actor(uuid,boolean),private.payroll_review_digest(uuid,uuid),
 private.submit_payroll_proposal(uuid,uuid),private.decide_payroll_proposal(uuid,uuid,text,text) FROM PUBLIC,profitpilot_app;

CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=45),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,45,private.security_catalog_digest());
COMMIT;
 THEN
  RAISE EXCEPTION 'Payroll source is not accepted' USING ERRCODE='23514'; END IF;
 SELECT * INTO p FROM public.payroll_pools WHERE tenant_id=p_tenant AND id=p.id AND batch_id=b.id FOR UPDATE;
 IF NOT FOUND OR p.period_start IS DISTINCT FROM b.source_period_start OR p.period_end IS DISTINCT FROM b.source_period_end THEN
  RAISE EXCEPTION 'Payroll pool source period mismatch' USING ERRCODE='23514'; END IF;
 SELECT * INTO r FROM public.allocation_runs WHERE tenant_id=p_tenant AND id=p_run AND payroll_pool_id=p.id FOR UPDATE;
 IF NOT FOUND OR r.status<>'review' OR r.reviewer_id IS NOT NULL OR r.residual_amount<>0 THEN
  RAISE EXCEPTION 'Only complete unconfirmed review runs are eligible' USING ERRCODE='23514'; END IF;
 IF EXISTS(SELECT 1 FROM private.import_disposal_controls WHERE tenant_id=p_tenant AND batch_id=b.id AND hold_active)
 OR EXISTS(SELECT 1 FROM private.import_disposal_tombstones WHERE tenant_id=p_tenant AND batch_id=b.id) THEN
  RAISE EXCEPTION 'Payroll source unavailable' USING ERRCODE='23514'; END IF;

 SELECT count(*),coalesce(sum(amount),0) INTO source_count,source_total
 FROM public.payroll_source_rows WHERE tenant_id=p_tenant AND payroll_pool_id=p.id;
 SELECT count(*) INTO line_count FROM public.allocation_lines WHERE tenant_id=p_tenant AND allocation_run_id=r.id;
 IF source_count NOT BETWEEN 1 AND 10000 OR line_count>50000 OR source_total<>p.total_amount
 OR source_count<>(SELECT count(*) FROM public.raw_import_rows WHERE tenant_id=p_tenant AND batch_id=b.id)
 OR source_count<>(SELECT count(DISTINCT raw_import_row_id) FROM public.payroll_source_rows WHERE tenant_id=p_tenant AND payroll_pool_id=p.id)
 OR EXISTS(SELECT 1 FROM public.payroll_pools WHERE tenant_id=p_tenant AND batch_id=b.id AND id<>p.id) THEN
  RAISE EXCEPTION 'Payroll evidence does not reconcile or exceeds capacity' USING ERRCODE='23514'; END IF;
 PERFORM 1 FROM public.raw_import_rows WHERE tenant_id=p_tenant AND batch_id=b.id FOR SHARE;
 IF EXISTS(
  SELECT 1 FROM public.payroll_source_rows s JOIN public.raw_import_rows raw ON raw.tenant_id=s.tenant_id AND raw.id=s.raw_import_row_id
  LEFT JOIN (SELECT payroll_source_row_id,sum(amount) amount FROM public.allocation_lines
   WHERE tenant_id=p_tenant AND allocation_run_id=r.id GROUP BY payroll_source_row_id) a ON a.payroll_source_row_id=s.id
  WHERE s.tenant_id=p_tenant AND s.payroll_pool_id=p.id
  AND (s.currency<>p.currency OR raw.batch_id<>b.id OR coalesce(a.amount,0)<>s.amount
   OR raw.payload IS DISTINCT FROM jsonb_build_object('source_row_key',s.source_row_key,'amount',s.amount::text,'currency',s.currency::text)
   OR s.row_sha256<>encode(public.digest(convert_to(s.source_row_key||E'\n'||s.amount::text||E'\n'||s.currency::text,'UTF8'),'sha256'),'hex'))
 ) OR EXISTS(
  SELECT 1 FROM public.allocation_lines l LEFT JOIN public.payroll_source_rows s
   ON s.tenant_id=l.tenant_id AND s.id=l.payroll_source_row_id AND s.payroll_pool_id=p.id
  WHERE l.tenant_id=p_tenant AND l.allocation_run_id=r.id
   AND (s.id IS NULL OR l.amount<=0 OR l.bucket_type='unallocated'
    OR l.source_ref IS NULL OR NOT private.disposal_reference_valid(l.source_ref)
    OR (l.bucket_type IN ('direct','approved_allocated')) IS DISTINCT FROM (l.site_id IS NOT NULL))
 ) OR EXISTS(
  SELECT 1 FROM public.allocation_lines WHERE tenant_id=p_tenant AND allocation_run_id=r.id
  GROUP BY payroll_source_row_id,bucket_type,site_id HAVING count(*)>1
 ) THEN RAISE EXCEPTION 'Payroll row lineage or allocation evidence invalid' USING ERRCODE='23514'; END IF;
 SELECT coalesce(sum(amount) FILTER(WHERE bucket_type='direct'),0) direct,
  coalesce(sum(amount) FILTER(WHERE bucket_type='approved_allocated'),0) allocated,
  coalesce(sum(amount) FILTER(WHERE bucket_type='non_site'),0) non_site,
  coalesce(sum(amount) FILTER(WHERE bucket_type='excluded'),0) excluded
 INTO summary FROM public.allocation_lines WHERE tenant_id=p_tenant AND allocation_run_id=r.id;
 IF ROW(summary.direct,summary.allocated,summary.non_site,summary.excluded)
 IS DISTINCT FROM ROW(r.direct_amount,r.allocated_amount,r.non_site_amount,r.excluded_amount) THEN
  RAISE EXCEPTION 'Payroll allocation summary mismatch' USING ERRCODE='23514'; END IF;
 SELECT encode(public.digest(convert_to(coalesce(jsonb_agg(jsonb_build_array(s.id,s.raw_import_row_id,s.row_sha256,s.amount::text,s.currency) ORDER BY s.id),'[]'::jsonb)::text,'UTF8'),'sha256'),'hex')
 INTO source_digest FROM public.payroll_source_rows s WHERE s.tenant_id=p_tenant AND s.payroll_pool_id=p.id;
 SELECT encode(public.digest(convert_to(coalesce(jsonb_agg(jsonb_build_array(l.id,l.payroll_source_row_id,l.site_id,l.bucket_type,l.amount::text,l.source_ref) ORDER BY l.id),'[]'::jsonb)::text,'UTF8'),'sha256'),'hex')
 INTO line_digest FROM public.allocation_lines l WHERE l.tenant_id=p_tenant AND l.allocation_run_id=r.id;
 RETURN encode(public.digest(convert_to(jsonb_build_array('payroll-db-review-v1',p_tenant,r.id,r.method_version,p.id,p.period_start,p.period_end,p.currency,p.total_amount::text,p.source_ref,b.id,b.file_sha256,b.permission_ref,source_digest,line_digest)::text,'UTF8'),'sha256'),'hex');
END $fn$;

CREATE FUNCTION private.submit_payroll_proposal(p_tenant uuid,p_run uuid)
RETURNS uuid LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; d text; proposal uuid;
BEGIN
 actor:=private.payroll_review_actor(p_tenant,false);
 d:=private.payroll_review_digest(p_tenant,p_run);
 INSERT INTO private.payroll_proposal_reviews(tenant_id,allocation_run_id,evidence_digest,submitted_by)
 VALUES(p_tenant,p_run,d,actor) ON CONFLICT(tenant_id,allocation_run_id,evidence_digest) DO NOTHING
 RETURNING id INTO proposal;
 IF proposal IS NULL THEN
  SELECT id INTO proposal FROM private.payroll_proposal_reviews WHERE tenant_id=p_tenant AND allocation_run_id=p_run AND evidence_digest=d;
 ELSE
  INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
  VALUES(p_tenant,actor,'payroll_proposal_submitted','payroll_proposal',proposal,jsonb_build_object('evidenceDigest',d));
 END IF;
 RETURN proposal;
END $fn$;

CREATE FUNCTION private.decide_payroll_proposal(p_tenant uuid,p_proposal uuid,p_digest text,p_decision text)
RETURNS void LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; proposal private.payroll_proposal_reviews%ROWTYPE; actual text;
BEGIN
 actor:=private.payroll_review_actor(p_tenant,true);
 IF p_proposal IS NULL OR p_decision IS NULL OR p_decision NOT IN ('reviewed','rejected')
 OR p_digest IS NULL OR length(p_digest)<>64 OR p_digest !~ '^[a-f0-9]+$' THEN
  RAISE EXCEPTION 'Invalid payroll review decision' USING ERRCODE='22023'; END IF;
 SELECT * INTO proposal FROM private.payroll_proposal_reviews WHERE tenant_id=p_tenant AND id=p_proposal FOR UPDATE;
 IF NOT FOUND OR proposal.submitted_by=actor THEN RAISE EXCEPTION 'Payroll review authority denied' USING ERRCODE='42501'; END IF;
 IF proposal.evidence_digest IS DISTINCT FROM p_digest THEN RAISE EXCEPTION 'Payroll proposal digest mismatch' USING ERRCODE='23514'; END IF;
 IF EXISTS(SELECT 1 FROM private.payroll_proposal_decisions WHERE tenant_id=p_tenant AND proposal_id=p_proposal) THEN
  RAISE EXCEPTION 'Payroll proposal already decided' USING ERRCODE='23505'; END IF;
 IF p_decision='reviewed' THEN
  actual:=private.payroll_review_digest(p_tenant,proposal.allocation_run_id);
  IF actual IS DISTINCT FROM p_digest THEN RAISE EXCEPTION 'Payroll proposal evidence changed' USING ERRCODE='23514'; END IF;
 END IF;
 INSERT INTO private.payroll_proposal_decisions(tenant_id,proposal_id,reviewer_id,decision)
 VALUES(p_tenant,p_proposal,actor,p_decision);
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
 VALUES(p_tenant,actor,'payroll_proposal_decided','payroll_proposal',p_proposal,jsonb_build_object('decision',p_decision,'evidenceDigest',p_digest));
 -- Deliberately never updates allocation_runs.status or authorises payment.
END $fn$;
REVOKE ALL ON FUNCTION private.payroll_review_actor(uuid,boolean),private.payroll_review_digest(uuid,uuid),
 private.submit_payroll_proposal(uuid,uuid),private.decide_payroll_proposal(uuid,uuid,text,text) FROM PUBLIC,profitpilot_app;

CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=45),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,45,private.security_catalog_digest());
COMMIT;
