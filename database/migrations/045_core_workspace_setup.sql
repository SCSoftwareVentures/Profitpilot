-- Synthetic core-record onboarding: strict authorization, atomic creation,
-- immutable audit receipt, exact decimal draft and no financial approval.
BEGIN;
DO $check$ BEGIN
 IF NOT private.verify_security_catalog() THEN RAISE EXCEPTION 'Prior security catalog does not verify'; END IF;
END $check$;
CREATE UNIQUE INDEX core_workspace_receipt_key ON public.audit_events(tenant_id,(metadata->>'setupId'))
 WHERE action='core_workspace_created' AND object_type='contract';

CREATE FUNCTION private.create_core_workspace(p_tenant uuid,p_setup uuid,p_data jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $fn$
DECLARE actor uuid; receipt public.audit_events%ROWTYPE; request_hash text;
 business_id uuid; site_id uuid; new_contract_id uuid; version_id uuid; effective_date date; label text;
BEGIN
 IF p_tenant IS NULL OR private.current_tenant_id() IS DISTINCT FROM p_tenant
 OR NOT private.lock_tenant_available(p_tenant) THEN
  RAISE EXCEPTION 'Workspace authority denied' USING ERRCODE='42501';
 END IF;
 SELECT u.id INTO actor FROM public.users u JOIN public.tenant_memberships m ON m.user_id=u.id
 WHERE u.auth_subject=nullif(current_setting('app.tenant_subject',true),'') AND u.status='active'
 AND m.tenant_id=p_tenant AND m.status='active' AND m.role IN ('owner','admin')
 FOR SHARE OF u,m;
 IF actor IS NULL THEN RAISE EXCEPTION 'Workspace authority denied' USING ERRCODE='42501'; END IF;
 IF p_setup IS NULL OR p_setup::text !~ '^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$'
 OR p_data IS NULL OR jsonb_typeof(p_data)<>'object' OR octet_length(p_data::text)>2048
 THEN RAISE EXCEPTION 'Invalid workspace setup' USING ERRCODE='22023'; END IF;
 IF (SELECT count(*) FROM jsonb_object_keys(p_data))<>8
 OR NOT (p_data ?& ARRAY['businessName','siteName','customerName','effectiveFrom','price','currency','taxBasis','billingBasis'])
 OR EXISTS(SELECT 1 FROM jsonb_each(p_data) WHERE jsonb_typeof(value)<>'string')
 THEN RAISE EXCEPTION 'Invalid workspace fields' USING ERRCODE='22023'; END IF;
 FOREACH label IN ARRAY ARRAY[p_data->>'businessName',p_data->>'siteName',p_data->>'customerName'] LOOP
  IF label !~ '^[A-Za-z0-9][A-Za-z0-9 .&''()-]{0,119}$' OR label<>btrim(label)
  THEN RAISE EXCEPTION 'Invalid workspace label' USING ERRCODE='22023'; END IF;
 END LOOP;
 IF p_data->>'effectiveFrom' !~ '^20[0-9]{2}-[0-9]{2}-[0-9]{2}$'
 OR p_data->>'price' !~ '^(0|[1-9][0-9]{0,11})[.][0-9]{2}$'
 OR p_data->>'currency'<>'AUD' OR p_data->>'billingBasis'<>'monthly'
 OR p_data->>'taxBasis' NOT IN ('gst_inclusive','gst_exclusive','no_gst','unknown')
 THEN RAISE EXCEPTION 'Invalid draft contract basis' USING ERRCODE='22023'; END IF;
 effective_date:=(p_data->>'effectiveFrom')::date;
 IF to_char(effective_date,'YYYY-MM-DD')<>p_data->>'effectiveFrom' THEN
  RAISE EXCEPTION 'Invalid effective date' USING ERRCODE='22023';
 END IF;
 request_hash:=encode(public.digest(convert_to('profitpilot-workspace-v1:'||p_data::text,'UTF8'),'sha256'),'hex');
 PERFORM pg_advisory_xact_lock(hashtextextended('profitpilot-workspace-v1:'||p_tenant::text||':'||p_setup::text,0));
 SELECT * INTO receipt FROM public.audit_events WHERE tenant_id=p_tenant AND metadata->>'setupId'=p_setup::text
  AND action='core_workspace_created' AND object_type='contract';
 IF FOUND THEN
  IF receipt.actor_user_id IS DISTINCT FROM actor OR receipt.metadata->>'requestHash' IS DISTINCT FROM request_hash THEN
   RAISE EXCEPTION 'Conflicting workspace request' USING ERRCODE='23505';
  END IF;
  RETURN jsonb_build_object('businessId',receipt.metadata->>'businessId','siteId',receipt.metadata->>'siteId',
   'setupId',p_setup,'contractId',receipt.object_id,'versionId',receipt.metadata->>'versionId','idempotent',true);
 END IF;
 business_id:=gen_random_uuid();site_id:=gen_random_uuid();new_contract_id:=gen_random_uuid();version_id:=gen_random_uuid();
 INSERT INTO public.businesses(id,tenant_id,name) VALUES(business_id,p_tenant,p_data->>'businessName');
 INSERT INTO public.sites(id,tenant_id,business_id,name) VALUES(site_id,p_tenant,business_id,p_data->>'siteName');
 INSERT INTO public.contracts(id,tenant_id,business_id,customer_name) VALUES(new_contract_id,p_tenant,business_id,p_data->>'customerName');
 INSERT INTO public.contract_versions(id,tenant_id,contract_id,version_no,effective_from,price,currency,tax_basis,billing_basis)
 VALUES(version_id,p_tenant,new_contract_id,1,effective_date,(p_data->>'price')::numeric(14,2),'AUD',p_data->>'taxBasis','monthly');
 INSERT INTO public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
 VALUES(p_tenant,actor,'core_workspace_created','contract',new_contract_id,
  jsonb_build_object('setupId',p_setup,'businessId',business_id,'siteId',site_id,'versionId',version_id,'requestHash',request_hash));
 RETURN jsonb_build_object('businessId',business_id,'siteId',site_id,'setupId',p_setup,'contractId',new_contract_id,'versionId',version_id,'idempotent',false);
END $fn$;
REVOKE ALL ON FUNCTION private.create_core_workspace(uuid,uuid,jsonb) FROM PUBLIC,profitpilot_app;
GRANT EXECUTE ON FUNCTION private.create_core_workspace(uuid,uuid,jsonb) TO profitpilot_app;

CREATE OR REPLACE FUNCTION private.verify_security_catalog()
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $fn$
 SELECT coalesce((SELECT digest=private.security_catalog_digest() FROM private.security_catalog_baseline WHERE revision=45),false)
$fn$;
INSERT INTO private.security_catalog_baseline(singleton,revision,digest) VALUES(true,45,private.security_catalog_digest());
COMMIT;
