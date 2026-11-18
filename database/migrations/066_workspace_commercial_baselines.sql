-- Managed workspace setup and independently reviewed commercial baselines.
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
 IF p_action IS NULL OR p_action NOT IN ('payroll_submit','payroll_read','account_read','account_correct_email','invoice_disposal_preview','privacy_case_request','privacy_case_status','privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','payroll_correction_status','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status')
 OR (p_action IN ('privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status') AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('payroll_correction_preview','payroll_correction_status') AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('privacy_case_intake','privacy_case_acknowledge','privacy_case_resolve','privacy_case_refuse') AND actor_role NOT IN ('owner','admin'))
 OR (p_action='payroll_submit' AND actor_role NOT IN ('owner','admin','analyst'))
 OR (p_action='payroll_read' AND actor_role NOT IN ('owner','admin','reviewer'))
 OR (p_action='invoice_disposal_preview' AND actor_role NOT IN ('owner','admin'))
 OR (p_action IN ('account_read','account_correct_email') AND p_target<>p_tenant)
 THEN RAISE EXCEPTION 'Sensitive operation denied' USING ERRCODE='42501'; END IF;
 now_s:=floor(extract(epoch FROM clock_timestamp()))::bigint;
 IF p_scope IS NULL OR p_scope !~ '^[a-f0-9]{64}$'
 OR (p_action IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status') AND p_scope=repeat('0',64))
 OR (p_action NOT IN ('account_correct_email','privacy_case_request','privacy_case_intake','privacy_case_resolve','privacy_case_refuse','payroll_correction_preview','privacy_delivery_preview','privacy_delivery_status','privacy_receipt_preview','privacy_receipt_status','privacy_dispatch_reserve','privacy_dispatch_burn','privacy_dispatch_revoke','privacy_dispatch_status','privacy_key_revoke','payroll_intake_preview','payroll_intake_status','payroll_allocation_build','payroll_allocation_status','workspace_create','workspace_read','workspace_version_status') AND p_scope<>repeat('0',64))
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









CREATE TABLE private.workspace_records(
 tenant_id uuid NOT NULL REFERENCES public.tenants(id),id uuid NOT NULL,
 kind text NOT NULL CHECK(kind IN ('business','customer','site','contract','contract_site')),
 parent_id uuid,related_id uuid,label text,
 actor_id uuid NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,id),FOREIGN KEY(tenant_id,parent_id) REFERENCES private.workspace_records(tenant_id,id),
 FOREIGN KEY(tenant_id,related_id) REFERENCES private.workspace_records(tenant_id,id),
 FOREIGN KEY(tenant_id,actor_id) REFERENCES public.tenant_memberships(tenant_id,user_id),
 CHECK((kind='business' AND parent_id IS NULL AND related_id IS NULL AND label IS NOT NULL) OR
 (kind IN ('customer','site') AND parent_id IS NOT NULL AND related_id IS NULL AND label IS NOT NULL) OR
 (kind='contract' AND parent_id IS NOT NULL AND related_id IS NOT NULL AND label IS NOT NULL) OR
 (kind='contract_site' AND parent_id IS NOT NULL AND related_id IS NOT NULL AND label IS NULL))
);
CREATE UNIQUE INDEX workspace_assignment_once ON private.workspace_records(tenant_id,parent_id,related_id) WHERE kind='contract_site';
CREATE INDEX workspace_records_kind_idx ON private.workspace_records(tenant_id,kind,id);
CREATE TABLE private.workspace_version_orders(
 tenant_id uuid NOT NULL,order_id uuid NOT NULL,contract_id uuid NOT NULL,version_id uuid NOT NULL,
 starts date NOT NULL,ends date NOT NULL,price numeric(14,2) NOT NULL,
 tax_basis text NOT NULL,billing_basis text NOT NULL,evidence_digest text NOT NULL,scope_digest text NOT NULL,
 PRIMARY KEY(tenant_id,order_id),UNIQUE(tenant_id,version_id),
 FOREIGN KEY(tenant_id,order_id) REFERENCES private.security_work_orders(tenant_id,id),
 FOREIGN KEY(tenant_id,contract_id) REFERENCES public.contracts(tenant_id,id),
 CHECK(ends>=starts AND ends-starts<=366 AND isfinite(starts) AND isfinite(ends)),
 CHECK(price>=0 AND tax_basis IN ('gst_inclusive','gst_exclusive','no_gst') AND billing_basis IN ('monthly','weekly','fixed_period','per_service')),
 CHECK(evidence_digest ~ '^[a-f0-9]{64}$' AND evidence_digest<>repeat('0',64)),
 CHECK(scope_digest ~ '^[a-f0-9]{64}$' AND scope_digest<>repeat('0',64))
);
CREATE TABLE private.workspace_version_receipts(
 tenant_id uuid NOT NULL,order_id uuid NOT NULL,version_id uuid NOT NULL REFERENCES public.contract_versions(id),recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,order_id),UNIQUE(tenant_id,version_id),
 FOREIGN KEY(tenant_id,order_id) REFERENCES private.workspace_version_orders(tenant_id,order_id),
 FOREIGN KEY(tenant_id,order_id) REFERENCES private.security_work_consumptions(tenant_id,order_id)
);
REVOKE ALL ON private.workspace_records,private.workspace_version_orders,private.workspace_version_receipts FROM PUBLIC,profitpilot_app;
CREATE TRIGGER workspace_records_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.workspace_records FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE TRIGGER workspace_version_orders_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.workspace_version_orders FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();
CREATE TRIGGER workspace_version_receipts_immutable BEFORE UPDATE OR DELETE OR TRUNCATE ON private.workspace_version_receipts FOR EACH STATEMENT EXECUTE FUNCTION private.deny_audit_mutation();

CREATE FUNCTION private.api_workspace_create(
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
  IF EXISTS(SELECT 1 FROM private.workspace_version_receipts r JOIN private.workspace_version_orders o USING(tenant_id,order_id) WHERE o.tenant_id=p_tenant AND o.contract_id=p_parent)
  THEN RAISE EXCEPTION 'Approved contract site scope is frozen' USING ERRCODE='23514'; END IF;
 END CASE;
 INSERT INTO private.workspace_records(tenant_id,id,kind,parent_id,related_id,label,actor_id) VALUES(p_tenant,p_id,p_kind,p_parent,p_related,p_label,actor);
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id) VALUES(p_tenant,actor,'workspace_record_created',p_kind,p_id);
 RETURN jsonb_build_object('id',p_id,'kind',p_kind,'parentId',p_parent,'relatedId',p_related,'label',p_label);
END $fn$;

CREATE FUNCTION private.api_workspace_read(
 p_tenant uuid,p_target uuid,p_action text,p_scope text,p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text,
 p_kind text,p_cursor uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE items jsonb; count_rows integer; next_cursor uuid;
BEGIN
 IF p_target IS DISTINCT FROM p_tenant OR p_action IS DISTINCT FROM 'workspace_read' OR p_kind IS NULL OR p_kind NOT IN ('business','customer','site','contract','contract_site')
 OR p_scope IS DISTINCT FROM encode(public.digest(convert_to('workspace-read-v1'||E'\n'||p_kind||E'\n'||coalesce(p_cursor::text,''),'UTF8'),'sha256'),'hex')
 THEN RAISE EXCEPTION 'Workspace read denied' USING ERRCODE='42501'; END IF;
 PERFORM private.sensitive_api_actor(p_tenant,p_target,p_action,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 WITH page AS (SELECT id,kind,parent_id,related_id,label FROM private.workspace_records WHERE tenant_id=p_tenant AND kind=p_kind AND (p_cursor IS NULL OR id>p_cursor) ORDER BY id LIMIT 51),
 numbered AS (SELECT *,row_number() OVER(ORDER BY id) n FROM page)
 SELECT count(*)::integer,coalesce(jsonb_agg(jsonb_build_object('id',id,'kind',kind,'parentId',parent_id,'relatedId',related_id,'label',label) ORDER BY id) FILTER(WHERE n<=50),'[]'::jsonb),
 (array_agg(id ORDER BY id) FILTER(WHERE n<=50))[50] INTO count_rows,items,next_cursor FROM numbered;
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 RETURN jsonb_build_object('items',items,'nextCursor',CASE WHEN count_rows>50 THEN next_cursor ELSE NULL END);
END $fn$;

CREATE FUNCTION private.workspace_version_summary(p_tenant uuid,p_contract uuid,p_order uuid)
RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
DECLARE result jsonb;
BEGIN
 SELECT jsonb_build_object('orderId',o.order_id,'contractId',o.contract_id,'versionId',o.version_id,'periodStart',o.starts,'periodEnd',o.ends,'price',o.price::text,'currency','AUD','taxBasis',o.tax_basis,'billingBasis',o.billing_basis,'evidenceDigest',o.evidence_digest,'scopeDigest',o.scope_digest,
 'status',CASE WHEN r.order_id IS NOT NULL THEN 'approved_baseline' WHEN d.decision='rejected' THEN 'rejected' WHEN d.expires_at<=clock_timestamp() OR (d.order_id IS NULL AND w.requested_at+interval '24 hours'<=clock_timestamp()) THEN 'expired' WHEN d.decision='approved' THEN 'approved_pending_record' ELSE 'requested' END)
 INTO result FROM private.workspace_version_orders o JOIN private.security_work_orders w ON w.tenant_id=o.tenant_id AND w.id=o.order_id
 LEFT JOIN private.security_work_decisions d ON d.tenant_id=o.tenant_id AND d.order_id=o.order_id
 LEFT JOIN private.workspace_version_receipts r ON r.tenant_id=o.tenant_id AND r.order_id=o.order_id
 WHERE o.tenant_id=p_tenant AND o.contract_id=p_contract AND o.order_id=p_order;
 IF result IS NULL THEN RAISE EXCEPTION 'Contract baseline unavailable' USING ERRCODE='42501'; END IF;
 RETURN result;
END $fn$;

CREATE FUNCTION private.api_workspace_version_step(
 p_tenant uuid,p_contract uuid,p_order uuid,p_version uuid,p_start text,p_end text,p_price text,p_tax text,p_billing text,p_evidence text,p_scope text,p_step text,
 p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog SET timezone='UTC' AS $fn$
DECLARE actor uuid; q private.workspace_version_orders%ROWTYPE; start_day date; end_day date; version_no_value integer; reviewer uuid;
BEGIN
 actor:=private.security_work_actor(p_tenant,p_order,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF p_version IS NULL OR p_contract IS NULL OR p_start IS NULL OR p_end IS NULL OR p_start !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' OR p_end !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$'
 OR p_price IS NULL OR p_price !~ '^(0|[1-9][0-9]{0,11})[.][0-9]{2}$' OR p_tax IS NULL OR p_tax NOT IN ('gst_inclusive','gst_exclusive','no_gst')
 OR p_billing IS NULL OR p_billing NOT IN ('monthly','weekly','fixed_period','per_service') OR p_evidence IS NULL OR p_evidence !~ '^[a-f0-9]{64}$' OR p_evidence=repeat('0',64)
 OR p_scope IS DISTINCT FROM encode(public.digest(convert_to('workspace-version-v1'||E'\n'||p_contract||E'\n'||p_version||E'\n'||p_start||E'\n'||p_end||E'\n'||p_price||E'\n'||p_tax||E'\n'||p_billing||E'\n'||p_evidence,'UTF8'),'sha256'),'hex')
 THEN RAISE EXCEPTION 'Contract baseline rejected' USING ERRCODE='42501'; END IF;
 start_day:=p_start::date;end_day:=p_end::date;
 IF start_day::text<>p_start OR end_day::text<>p_end OR end_day<start_day OR end_day-start_day>366 THEN RAISE EXCEPTION 'Invalid effective period' USING ERRCODE='23514'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('profitpilot-workspace:'||p_tenant::text,0));
 PERFORM 1 FROM private.workspace_records WHERE tenant_id=p_tenant AND id=p_contract AND kind='contract';
 IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM private.workspace_records WHERE tenant_id=p_tenant AND kind='contract_site' AND parent_id=p_contract) THEN RAISE EXCEPTION 'Contract or explicit site scope unavailable' USING ERRCODE='42501'; END IF;
 IF p_step<>'request' THEN
  SELECT * INTO q FROM private.workspace_version_orders WHERE tenant_id=p_tenant AND order_id=p_order AND contract_id=p_contract AND version_id=p_version AND scope_digest=p_scope;
  IF NOT FOUND THEN RAISE EXCEPTION 'Contract baseline request unavailable' USING ERRCODE='42501'; END IF;
 END IF;
 IF p_step<>'reject' AND EXISTS(SELECT 1 FROM public.contract_versions WHERE tenant_id=p_tenant AND contract_id=p_contract AND effective_from<=end_day AND (effective_to IS NULL OR effective_to>=start_day))
 THEN RAISE EXCEPTION 'Effective period overlaps existing baseline' USING ERRCODE='23514'; END IF;
 IF p_step='request' AND (SELECT count(*) FROM private.workspace_version_orders WHERE tenant_id=p_tenant AND contract_id=p_contract)>=100 THEN RAISE EXCEPTION 'Baseline order capacity reached' USING ERRCODE='54000'; END IF;
 PERFORM private.record_security_work(p_tenant,p_order,'privileged_operation',p_scope,p_step,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 IF p_step='request' THEN
  INSERT INTO private.workspace_version_orders(tenant_id,order_id,contract_id,version_id,starts,ends,price,tax_basis,billing_basis,evidence_digest,scope_digest)
  VALUES(p_tenant,p_order,p_contract,p_version,start_day,end_day,p_price::numeric,p_tax,p_billing,p_evidence,p_scope);
 ELSIF p_step='consume' THEN
  SELECT decided_by INTO reviewer FROM private.security_work_decisions WHERE tenant_id=p_tenant AND order_id=p_order;
  SELECT coalesce(max(version_no),0)+1 INTO version_no_value FROM public.contract_versions WHERE tenant_id=p_tenant AND contract_id=p_contract;
  INSERT INTO public.contract_versions(id,tenant_id,contract_id,version_no,effective_from,effective_to,price,currency,tax_basis,billing_basis,scope,source_ref,approved_by,approved_at)
  VALUES(p_version,p_tenant,p_contract,version_no_value,start_day,end_day,p_price::numeric,'AUD',p_tax,p_billing,jsonb_build_object('evidenceDigest',p_evidence,'scopeIncomplete',true),'reviewed-workspace-baseline-v1',reviewer,clock_timestamp());
  INSERT INTO private.workspace_version_receipts(tenant_id,order_id,version_id) VALUES(p_tenant,p_order,p_version);
  INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id) VALUES(p_tenant,actor,'commercial_baseline_recorded','contract_version',p_version);
 END IF;
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);
 RETURN private.workspace_version_summary(p_tenant,p_contract,p_order);
END $fn$;
CREATE FUNCTION private.api_workspace_version_status(
 p_tenant uuid,p_order uuid,p_action text,p_scope text,p_auth bigint,p_iat bigint,p_session text,p_expires bigint,p_nonce text,p_key text,p_signature text,p_contract uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE result jsonb;
BEGIN
 IF p_action IS DISTINCT FROM 'workspace_version_status' OR p_scope IS DISTINCT FROM encode(public.digest(convert_to('workspace-version-status-v1'||E'\n'||p_contract,'UTF8'),'sha256'),'hex') THEN RAISE EXCEPTION 'Baseline status denied' USING ERRCODE='42501'; END IF;
 PERFORM private.sensitive_api_actor(p_tenant,p_order,p_action,p_scope,p_auth,p_iat,p_session,p_expires,p_nonce,p_key,p_signature);
 result:=private.workspace_version_summary(p_tenant,p_contract,p_order);
 PERFORM private.sensitive_api_fresh(p_auth,p_expires);RETURN result;
END $fn$;

-- Keep existing synthetic fixtures compatible; managed contracts require an
-- explicit recorded site assignment. No additional table grants.
CREATE FUNCTION private.workspace_contract_site_allowed(p_tenant uuid,p_contract uuid,p_site uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce(private.current_tenant_id()=p_tenant,false) AND
 (NOT EXISTS(SELECT 1 FROM private.workspace_records WHERE tenant_id=p_tenant AND kind='contract' AND id=p_contract)
 OR EXISTS(SELECT 1 FROM private.workspace_records WHERE tenant_id=p_tenant AND kind='contract_site' AND parent_id=p_contract AND related_id=p_site))
$fn$;
CREATE FUNCTION private.guard_workspace_match()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 IF NEW.decision='confirmed' AND EXISTS(SELECT 1 FROM private.workspace_records WHERE tenant_id=NEW.tenant_id AND id=NEW.contract_id AND kind='contract')
 AND NOT EXISTS(SELECT 1 FROM private.workspace_records WHERE tenant_id=NEW.tenant_id AND kind='contract_site' AND parent_id=NEW.contract_id AND related_id=NEW.site_id)
 THEN RAISE EXCEPTION 'Managed contract site not assigned' USING ERRCODE='23514'; END IF;
 RETURN NEW;
END $fn$;
CREATE TRIGGER workspace_match_site_guard BEFORE INSERT OR UPDATE ON public.match_reviews FOR EACH ROW EXECUTE FUNCTION private.guard_workspace_match();
CREATE FUNCTION private.guard_workspace_version()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
BEGIN
 IF EXISTS(SELECT 1 FROM private.workspace_version_receipts WHERE tenant_id=OLD.tenant_id AND version_id=OLD.id)
 THEN RAISE EXCEPTION 'Approved commercial baseline is immutable' USING ERRCODE='55000'; END IF;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW;
END $fn$;
CREATE TRIGGER workspace_version_guard BEFORE UPDATE OR DELETE ON public.contract_versions FOR EACH ROW EXECUTE FUNCTION private.guard_workspace_version();
REVOKE ALL ON FUNCTION private.guard_workspace_match(),private.guard_workspace_version(),private.workspace_version_summary(uuid,uuid,uuid) FROM PUBLIC,profitpilot_app;
REVOKE ALL ON FUNCTION private.api_workspace_create(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,text,uuid,uuid,text),
 private.api_workspace_read(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,text,uuid),
 private.api_workspace_version_step(uuid,uuid,uuid,uuid,text,text,text,text,text,text,text,text,bigint,bigint,text,bigint,text,text,text),
 private.api_workspace_version_status(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,uuid),
 private.workspace_contract_site_allowed(uuid,uuid,uuid) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.api_workspace_create(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,text,uuid,uuid,text),
 private.api_workspace_read(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,text,uuid),
 private.api_workspace_version_step(uuid,uuid,uuid,uuid,text,text,text,text,text,text,text,text,bigint,bigint,text,bigint,text,text,text),
 private.api_workspace_version_status(uuid,uuid,text,text,bigint,bigint,text,bigint,text,text,text,uuid),
 private.workspace_contract_site_allowed(uuid,uuid,uuid) TO profitpilot_app;
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
  ) all_entries LIMIT 100001
 ), hashes AS (SELECT kind,encode(hash,'hex') AS h FROM entries)
 SELECT count(*),CASE WHEN count(*)<=100000 THEN encode(public.digest(convert_to('profitpilot-sensitive-recovery-v13:'||coalesce(string_agg(kind||':'||h,',' ORDER BY kind COLLATE "C",h COLLATE "C"),''),'UTF8'),'sha256'),'hex') END
 INTO total,result FROM hashes;
 IF total>100000 OR result IS NULL THEN RAISE EXCEPTION 'Sensitive recovery inventory exceeds reviewed capacity' USING ERRCODE='54000'; END IF;
 RETURN result;
END $fn$;

REVOKE ALL ON FUNCTION private.sensitive_recovery_fingerprint() FROM PUBLIC,profitpilot_app;
CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=66),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,66,private.security_catalog_digest());
COMMIT;
