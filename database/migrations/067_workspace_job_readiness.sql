-- Repository-level job lifecycle with versioned readiness checks.
BEGIN;
DO $check$ BEGIN
 IF private.verify_security_catalog() IS DISTINCT FROM true THEN RAISE EXCEPTION 'Prior catalog does not verify'; END IF;
END $check$;
CREATE OR REPLACE FUNCTION private.sensitive_api_actor(
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
 IF p_action IS NULL OR p_action NOT IN ('payroll_submit','payroll_read','account_read','account_correct_email','invoice_disposal_preview','privacy_case_request','privacy_case_status','privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','payroll_correction_status','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status','workspace_job_write','workspace_job_read')
 OR (p_action IN ('privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status','workspace_job_write','workspace_job_read') AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('payroll_correction_preview','payroll_correction_status') AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse') AND actor_role NOT IN ('owner','admin'))
 OR (p_action='payroll_submit' AND actor_role NOT IN ('owner','admin','analyst'))
 OR (p_action='payroll_read' AND actor_role NOT IN ('owner','admin','reviewer'))
 OR (p_action='invoice_disposal_preview' AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('account_read','account_correct_email') AND p_target<>p_tenant)
 THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF p_scope IS NULL OR p_scope !~ '^[a-f0-9]{64}$'
 OR (p_action IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status','workspace_job_write','workspace_job_read') AND p_scope=repeat('0',64))
 OR (p_action NOT IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status','workspace_job_write','workspace_job_read') AND p_scope<>repeat('0',64))
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









CREATE OR REPLACE FUNCTION private.api_workspace_create(
 p_tenant uuid,p_id uuid,p_action text,p_scope text,p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text,
 p_kind text,p_parent uuid,p_related uuid,p_label text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; parent_row private.workspace_records%ROWTYPE; related_row private.workspace_records%ROWTYPE;
BEGIN
 IF p_action IS DISTINCT FROM 'workspace_create' OR p_kind IS NULL OR p_kind NOT IN ('business','customer','site','contract','contract_site')
 OR p_scope IS DISTINCT FROM encode(public.digest(convert_to('workspace-create-v1'||E'\n'||p_kind||E'\n'||coalesce(p_parent::text,'')||E'\n'||coalesce(p_related::text,'')||E'\n'||coalesce(p_label,''),'UTF8'),'sha256'),'hex')
 THEN RAISE EXCEPTION 'Workspace creation denied' USING ERRCODE='42501'; END IF;
 actor:=private.sensitive_api_actor(p_tenant,p_id,p_action,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 PERFORM pg_advisory_xact_lock(hashtextextended('profitpilot-workspace:'||p_tenant::text,0));
 IF (SELECT count(*) FROM private.workspace_records WHERE tenant_id=p_tenant)>=2000 THEN RAISE EXCEPTION 'Workspace capacity exceeded' USING ERRCODE='54000'; END IF;
 IF p_kind='contract_site' THEN
  IF p_label IS NOT NULL THEN RAISE EXCEPTION 'Unexpected label' USING ERRCODE='23514'; END IF;
 ELSE
  IF p_label IS NULL OR p_label !~ '^[A-Za-z][A-Za-z0-9 .&_-]{0,79}$' OR btrim(p_label)<>p_label OR NOT private.import_reference_safe(p_label,80,false)
  THEN RAISE EXCEPTION 'Use a bounded organization alias' USING ERRCODE='23514'; END IF;
 END IF;
 IF p_parent IS NOT NULL THEN
  SELECT * INTO parent_row FROM private.workspace_records WHERE tenant_id=p_tenant AND id=p_parent;
  IF NOT FOUND THEN RAISE EXCEPTION 'Workspace parent unavailable' USING ERRCODE='42501'; END IF;
 END IF;
 IF p_related IS NOT NULL THEN
  SELECT * INTO related_row FROM private.workspace_records WHERE tenant_id=p_tenant AND id=p_related;
  IF NOT FOUND THEN RAISE EXCEPTION 'Related workspace record unavailable' USING ERRCODE='42501'; END IF;
 END IF;
 CASE p_kind
 WHEN 'business' THEN
  IF p_parent IS NOT NULL OR p_related IS NOT NULL THEN RAISE EXCEPTION 'Invalid business scope' USING ERRCODE='23514'; END IF;
  INSERT INTO public.businesses(id,tenant_id,name) VALUES(p_id,p_tenant,p_label);
 WHEN 'customer','site' THEN
  IF parent_row.kind IS DISTINCT FROM 'business' OR p_related IS NOT NULL THEN RAISE EXCEPTION 'Invalid business parent' USING ERRCODE='23514'; END IF;
  IF p_kind='site' THEN INSERT INTO public.sites(id,tenant_id,business_id,name,status) VALUES(p_id,p_tenant,p_parent,p_label,'active'); END IF;
 WHEN 'contract' THEN
  IF parent_row.kind IS DISTINCT FROM 'business' OR related_row.kind IS DISTINCT FROM 'customer' OR related_row.parent_id IS DISTINCT FROM p_parent
  THEN RAISE EXCEPTION 'Contract customer must belong to business' USING ERRCODE='23514'; END IF;
  INSERT INTO public.contracts(id,tenant_id,business_id,customer_name,status) VALUES(p_id,p_tenant,p_parent,related_row.label,'active');
 WHEN 'contract_site' THEN
  IF parent_row.kind IS DISTINCT FROM 'contract' OR related_row.kind IS DISTINCT FROM 'site' OR parent_row.parent_id IS DISTINCT FROM related_row.parent_id
  THEN RAISE EXCEPTION 'Site and contract must share business' USING ERRCODE='23514'; END IF;
  IF EXISTS(SELECT 1 FROM private.workspace_version_orders o JOIN private.security_work_orders w ON w.tenant_id=o.tenant_id AND w.id=o.order_id
  LEFT JOIN private.security_work_decisions d ON d.tenant_id=o.tenant_id AND d.order_id=o.order_id
  LEFT JOIN private.workspace_version_receipts r ON r.tenant_id=o.tenant_id AND r.order_id=o.order_id
  WHERE o.tenant_id=p_tenant AND o.contract_id=p_parent AND
   (r.order_id IS NOT NULL OR (d.order_id IS NULL AND w.requested_at+interval '24 hours'>clock_timestamp()) OR (d.decision='approved' AND d.expires_at>clock_timestamp())))
  THEN RAISE EXCEPTION 'Contract site scope is frozen during baseline review or after approval' USING ERRCODE='23514'; END IF;
 END CASE;
 INSERT INTO private.workspace_records(tenant_id,id,kind,parent_id,related_id,label,actor_id) VALUES(p_tenant,p_id,p_kind,p_parent,p_related,p_label,actor);
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id) VALUES(p_tenant,actor,'workspace_record_created',p_kind,p_id);
 RETURN jsonb_build_object('id',p_id,'kind',p_kind,'parentId',p_parent,'relatedId',p_related,'label',p_label);
END $fn$;


CREATE TABLE private.workspace_jobs(
 tenant_id uuid NOT NULL,job_id uuid NOT NULL,contract_id uuid NOT NULL,site_id uuid NOT NULL,baseline_id uuid NOT NULL REFERENCES public.contract_versions(id),
 service_date date NOT NULL,creation_evidence text NOT NULL CHECK(creation_evidence ~ '^[a-f0-9]{64}$' AND creation_evidence<>repeat('0',64)),
 created_by uuid NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,job_id),FOREIGN KEY(tenant_id,contract_id) REFERENCES public.contracts(tenant_id,id),
 FOREIGN KEY(tenant_id,site_id) REFERENCES public.sites(tenant_id,id),FOREIGN KEY(tenant_id,created_by) REFERENCES public.tenant_memberships(tenant_id,user_id),
 CHECK(isfinite(service_date))
);
CREATE TABLE private.workspace_job_events(
 tenant_id uuid NOT NULL,job_id uuid NOT NULL,event_id uuid NOT NULL,event_no integer NOT NULL CHECK(event_no BETWEEN 1 AND 200),
 kind text NOT NULL CHECK(kind IN ('check','start','complete','cancel')),
 check_id text,check_status text,evidence_digest text NOT NULL CHECK(evidence_digest ~ '^[a-f0-9]{64}$' AND evidence_digest<>repeat('0',64)),
 actor_id uuid NOT NULL,recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,event_id),UNIQUE(tenant_id,job_id,event_no),
 FOREIGN KEY(tenant_id,job_id) REFERENCES private.workspace_jobs(tenant_id,job_id),
 FOREIGN KEY(tenant_id,actor_id) REFERENCES public.tenant_memberships(tenant_id,user_id),
 CHECK((kind='check' AND check_id IN ('customer','site','scope','service_date','price','currency','access','materials','skills','permissions','completion_evidence') AND check_status IN ('satisfied','missing','conflicting','unverified','not_applicable')
 AND check_id IS NOT NULL AND check_status IS NOT NULL) OR (kind<>'check' AND check_id IS NULL AND check_status IS NULL)),
 CHECK(check_status IS DISTINCT FROM 'not_applicable' OR check_id IN ('access','materials','skills','permissions','completion_evidence'))
);
REVOKE ALL ON private.workspace_jobs,private.workspace_job_events FROM PUBLIC,profitpilot_app;
CREATE TRIGGER workspace_jobs_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.workspace_jobs FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE TRIGGER workspace_job_events_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.workspace_job_events FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();

CREATE FUNCTION private.workspace_job_summary(p_tenant uuid,p_job uuid)
RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path=pg_catalog AS $fn$
DECLARE result jsonb; check_values jsonb; resolved integer; state text;
BEGIN
 SELECT jsonb_build_object('jobId',j.job_id,'contractId',j.contract_id,'siteId',j.site_id,'baselineId',j.baseline_id,'serviceDate',j.service_date,
 'baselinePrice',v.price::text,'currency',v.currency,'taxBasis',v.tax_basis,'createdAt',j.created_at)
 INTO result FROM private.workspace_jobs j JOIN public.contract_versions v ON v.tenant_id=j.tenant_id AND v.contract_id=j.contract_id AND v.id=j.baseline_id
 WHERE j.tenant_id=p_tenant AND j.job_id=p_job;
 IF result IS NULL THEN RAISE EXCEPTION 'Job unavailable' USING ERRCODE='42501'; END IF;
 WITH latest AS (SELECT DISTINCT ON(check_id) check_id,check_status,evidence_digest FROM private.workspace_job_events WHERE tenant_id=p_tenant AND job_id=p_job AND kind='check' ORDER BY check_id,event_no DESC)
 SELECT coalesce(jsonb_object_agg(check_id,jsonb_build_object('status',check_status,'evidenceDigest',evidence_digest)),'{}'::jsonb),
 count(*) FILTER(WHERE check_status IN ('satisfied','not_applicable'))::integer INTO check_values,resolved FROM latest;
 SELECT kind INTO state FROM private.workspace_job_events WHERE tenant_id=p_tenant AND job_id=p_job AND kind<>'check' ORDER BY event_no DESC LIMIT 1;
 RETURN result||jsonb_build_object('status',CASE state WHEN 'start' THEN 'in_progress' WHEN 'complete' THEN 'completed' WHEN 'cancel' THEN 'cancelled' ELSE 'planned' END,
 'templateId','commercial-cleaning-job-readiness','templateVersion','1.0.0','checks',check_values,
 'resolvedRequiredChecks',resolved,'totalRequiredChecks',11,'readinessStatus',CASE WHEN resolved=11 THEN 'ready' ELSE 'not_ready' END,
 'customerAcceptanceVerified',false,'safetyCertified',false);
END $fn$;

CREATE FUNCTION private.api_workspace_job_write(
 p_tenant uuid,p_job uuid,p_action text,p_scope text,p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text,
 p_operation text,p_values text[])
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE actor uuid; contract uuid; site uuid; day date; baseline uuid; job private.workspace_jobs%ROWTYPE; e_id uuid; next_no integer; result jsonb;
BEGIN
 IF p_action IS DISTINCT FROM 'workspace_job_write' OR p_operation IS NULL OR p_operation NOT IN ('create','check','start','complete','cancel')
 OR array_ndims(p_values) IS DISTINCT FROM 1 OR cardinality(p_values)<>7 OR array_lower(p_values,1)<>1 OR octet_length(array_to_string(p_values,'',''))>500
 OR p_values[7] IS NULL OR p_values[7] !~ '^[a-f0-9]{64}$' OR p_values[7]=repeat('0',64)
 OR p_scope IS DISTINCT FROM encode(public.digest(convert_to('workspace-job-v1'||E'\n'||p_operation||E'\n'||array_to_string(p_values,E'\n',''),'UTF8'),'sha256'),'hex')
 THEN RAISE EXCEPTION 'Job action denied' USING ERRCODE='42501'; END IF;
 actor:=private.sensitive_api_actor(p_tenant,p_job,p_action,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF p_operation='create' THEN
  IF p_values[1] IS NULL OR p_values[2] IS NULL OR p_values[3] IS NULL OR p_values[3] !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'
  OR p_values[4] IS NOT NULL OR p_values[5] IS NOT NULL OR p_values[6] IS NOT NULL THEN RAISE EXCEPTION 'Invalid job setup' USING ERRCODE='23514'; END IF;
  contract:=p_values[1]::uuid;site:=p_values[2]::uuid;day:=p_values[3]::date;
  IF contract::text<>p_values[1] OR site::text<>p_values[2] OR day::text<>p_values[3] THEN RAISE EXCEPTION 'Noncanonical job setup' USING ERRCODE='23514'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('profitpilot-workspace:'||p_tenant::text,0));
  IF (SELECT count(*) FROM private.workspace_jobs WHERE tenant_id=p_tenant)>=2000 THEN RAISE EXCEPTION 'Job capacity reached' USING ERRCODE='54000'; END IF;
  IF NOT EXISTS(SELECT 1 FROM private.workspace_records WHERE tenant_id=p_tenant AND kind='contract_site' AND parent_id=contract AND related_id=site)
  OR NOT EXISTS(SELECT 1 FROM public.sites WHERE tenant_id=p_tenant AND id=site AND status='active')
  OR NOT EXISTS(SELECT 1 FROM public.contracts WHERE tenant_id=p_tenant AND id=contract AND status='active')
  THEN RAISE EXCEPTION 'Job assignment unavailable' USING ERRCODE='42501'; END IF;
  SELECT v.id INTO baseline FROM public.contract_versions v JOIN private.workspace_version_receipts r ON r.tenant_id=v.tenant_id AND r.version_id=v.id
  WHERE v.tenant_id=p_tenant AND v.contract_id=contract AND v.effective_from<=day AND v.effective_to>=day;
  IF NOT FOUND THEN RAISE EXCEPTION 'Approved baseline missing for job date' USING ERRCODE='23514'; END IF;
  INSERT INTO private.workspace_jobs(tenant_id,job_id,contract_id,site_id,baseline_id,service_date,creation_evidence,created_by)
  VALUES(p_tenant,p_job,contract,site,baseline,day,p_values[7],actor);
 ELSE
  IF p_values[1] IS NOT NULL OR p_values[2] IS NOT NULL OR p_values[3] IS NOT NULL OR p_values[4] IS NULL THEN RAISE EXCEPTION 'Invalid job event' USING ERRCODE='23514'; END IF;
  e_id:=p_values[4]::uuid;
  IF e_id::text<>p_values[4] THEN RAISE EXCEPTION 'Noncanonical event ID' USING ERRCODE='23514'; END IF;
  SELECT * INTO job FROM private.workspace_jobs WHERE tenant_id=p_tenant AND job_id=p_job FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Job unavailable' USING ERRCODE='42501'; END IF;
  result:=private.workspace_job_summary(p_tenant,p_job);
  IF p_operation='check' THEN
   IF result->>'status'<>'planned' OR p_values[5] IS NULL OR p_values[5] NOT IN ('customer','site','scope','service_date','price','currency','access','materials','skills','permissions','completion_evidence')
   OR p_values[6] IS NULL OR p_values[6] NOT IN ('satisfied','missing','unverified','conflicting','not_applicable')
   OR (p_values[6]='not_applicable' AND p_values[5] NOT IN ('access','materials','skills','permissions','completion_evidence'))
   THEN RAISE EXCEPTION 'Readiness check unavailable' USING ERRCODE='23514'; END IF;
  ELSE
   IF p_values[5] IS NOT NULL OR p_values[6] IS NOT NULL
   OR (p_operation='start' AND (result->>'status'<>'planned' OR result->>'readinessStatus'<>'ready'))
   OR (p_operation='complete' AND result->>'status'<>'in_progress')
   OR (p_operation='cancel' AND result->>'status' NOT IN ('planned','in_progress'))
   THEN RAISE EXCEPTION 'Job transition denied' USING ERRCODE='23514'; END IF;
  END IF;
  SELECT coalesce(max(event_no),0)+1 INTO next_no FROM private.workspace_job_events WHERE tenant_id=p_tenant AND job_id=p_job;
  IF next_no>200 THEN RAISE EXCEPTION 'Job event capacity reached' USING ERRCODE='54000'; END IF;
  INSERT INTO private.workspace_job_events(tenant_id,job_id,event_id,event_no,kind,check_id,check_status,evidence_digest,actor_id)
  VALUES(p_tenant,p_job,e_id,next_no,p_operation,p_values[5],p_values[6],p_values[7],actor);
 END IF;
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id)
 VALUES(p_tenant,actor,'workspace_job_'||p_operation,'job',p_job);
 RETURN private.workspace_job_summary(p_tenant,p_job);
END $fn$;

CREATE FUNCTION private.api_workspace_job_read(
 p_tenant uuid,p_target uuid,p_action text,p_scope text,p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text,
 p_mode text,p_cursor uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE result jsonb; items jsonb; count_rows integer; next_cursor uuid;
BEGIN
 IF p_action IS DISTINCT FROM 'workspace_job_read' OR p_mode IS NULL OR p_mode NOT IN ('list','status')
 OR (p_mode='list' AND p_target IS DISTINCT FROM p_tenant) OR (p_mode='status' AND p_cursor IS NOT NULL)
 OR p_scope IS DISTINCT FROM encode(public.digest(convert_to('workspace-job-read-v1'||E'\n'||p_mode||E'\n'||coalesce(p_cursor::text,''),'UTF8'),'sha256'),'hex')
 THEN RAISE EXCEPTION 'Job read denied' USING ERRCODE='42501'; END IF;
 PERFORM private.sensitive_api_actor(p_tenant,p_target,p_action,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF p_mode='status' THEN result:=private.workspace_job_summary(p_tenant,p_target);
 ELSE
  WITH page AS (SELECT job_id FROM private.workspace_jobs WHERE tenant_id=p_tenant AND (p_cursor IS NULL OR job_id>p_cursor) ORDER BY job_id LIMIT 51),
  numbered AS (SELECT job_id,row_number() OVER(ORDER BY job_id) n FROM page)
  SELECT count(*)::integer,coalesce(jsonb_agg(private.workspace_job_summary(p_tenant,job_id) ORDER BY job_id) FILTER(WHERE n<=50),'[]'::jsonb),
  (array_agg(job_id ORDER BY job_id) FILTER(WHERE n<=50))[50] INTO count_rows,items,next_cursor FROM numbered;
  result:=jsonb_build_object('items',items,'nextCursor',CASE WHEN count_rows>50 THEN next_cursor ELSE NULL END);
 END IF;
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 RETURN result;
END $fn$;
REVOKE ALL ON FUNCTION private.workspace_job_summary(uuid,uuid) FROM PUBLIC,profitpilot_app;
REVOKE ALL ON FUNCTION private.api_workspace_job_write(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,text,text[]),
 private.api_workspace_job_read(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,text,uuid) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.api_workspace_job_write(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,text,text[]),
 private.api_workspace_job_read(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,text,uuid) TO profitpilot_app;
CREATE OR REPLACE FUNCTION private.sensitive_recovery_fingerprint()
RETURNS text LANGUAGE plpgsql STABLE SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE total bigint; result text;
BEGIN
 WITH entries AS (
  SELECT * FROM (
  SELECT 'account_email'::text AS kind,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') AS hash FROM (SELECT id,email FROM public.users LIMIT 100001) x
  UNION ALL SELECT 'security_work_orders'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.security_work_orders LIMIT 100001) x
  UNION ALL SELECT 'security_work_decisions'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.security_work_decisions LIMIT 100001) x
  UNION ALL SELECT 'security_work_consumptions'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.security_work_consumptions LIMIT 100001) x
  UNION ALL SELECT 'account_correction_nonces'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.account_correction_nonces LIMIT 100001) x
  UNION ALL SELECT 'privacy_rights_cases'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_rights_cases LIMIT 100001) x
  UNION ALL SELECT 'privacy_rights_acknowledgements'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_rights_acknowledgements LIMIT 100001) x
  UNION ALL SELECT 'privacy_rights_outcomes'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_rights_outcomes LIMIT 100001) x
  UNION ALL SELECT 'payroll_proposal_reviews'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.payroll_proposal_reviews LIMIT 100001) x
  UNION ALL SELECT 'payroll_proposal_decisions'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.payroll_proposal_decisions LIMIT 100001) x
  UNION ALL SELECT 'payroll_confirmation_receipts'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.payroll_confirmation_receipts LIMIT 100001) x
  UNION ALL SELECT 'payroll_correction_reservations'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.payroll_correction_reservations LIMIT 100001) x
  UNION ALL SELECT 'payroll_supersessions'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.payroll_supersessions LIMIT 100001) x
  UNION ALL SELECT 'financial_retention_reviews'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.financial_retention_reviews LIMIT 100001) x
  UNION ALL SELECT 'financial_retention_holds'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.financial_retention_holds LIMIT 100001) x
  UNION ALL SELECT 'financial_backup_plans'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.financial_backup_plans LIMIT 100001) x
  UNION ALL SELECT 'privacy_delivery_authorizations'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_delivery_authorizations LIMIT 100001) x
  UNION ALL SELECT 'privacy_delivery_requests'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_delivery_requests LIMIT 100001) x
  UNION ALL SELECT 'privacy_receipt_evidence'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_receipt_evidence LIMIT 100001) x
  UNION ALL SELECT 'privacy_receipt_requests'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_receipt_requests LIMIT 100001) x
  UNION ALL SELECT 'privacy_dispatch_reservations'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_dispatch_reservations LIMIT 100001) x
  UNION ALL SELECT 'privacy_dispatch_burns'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_dispatch_burns LIMIT 100001) x
  UNION ALL SELECT 'privacy_dispatch_revocations'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_dispatch_revocations LIMIT 100001) x
  UNION ALL SELECT 'privacy_case_key_versions'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_case_key_versions LIMIT 100001) x
  UNION ALL SELECT 'privacy_compromised_keys'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.privacy_compromised_keys LIMIT 100001) x
  UNION ALL SELECT 'payroll_intake_receipts'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.payroll_intake_receipts LIMIT 100001) x
  UNION ALL SELECT 'payroll_intake_requests'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.payroll_intake_requests LIMIT 100001) x
  UNION ALL SELECT 'payroll_allocation_builds'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.payroll_allocation_builds LIMIT 100001) x
  UNION ALL SELECT 'workspace_records'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.workspace_records LIMIT 100001) x
  UNION ALL SELECT 'workspace_version_orders'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.workspace_version_orders LIMIT 100001) x
  UNION ALL SELECT 'workspace_version_receipts'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.workspace_version_receipts LIMIT 100001) x
  UNION ALL SELECT 'workspace_jobs'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.workspace_jobs LIMIT 100001) x
  UNION ALL SELECT 'workspace_job_events'::text,public.digest(convert_to(to_jsonb(x)::text,'UTF8'),'sha256') FROM (SELECT * FROM private.workspace_job_events LIMIT 100001) x
  ) all_entries LIMIT 100001
 ), hashes AS (SELECT kind,encode(hash,'hex') AS h FROM entries)
 SELECT count(*),CASE WHEN count(*)<=100000 THEN encode(public.digest(convert_to('profitpilot-sensitive-recovery-v14:'||coalesce(string_agg(kind||':'||h,',' ORDER BY kind COLLATE "C",h COLLATE "C"),''),'UTF8'),'sha256'),'hex') END
 INTO total,result FROM hashes;
 IF total>100000 OR result IS NULL THEN RAISE EXCEPTION 'Sensitive recovery inventory exceeds reviewed capacity' USING ERRCODE='54000'; END IF;
 RETURN result;
END $fn$;

REVOKE ALL ON FUNCTION private.sensitive_recovery_fingerprint() FROM PUBLIC,profitpilot_app;
CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=67),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,67,private.security_catalog_digest());
COMMIT;
