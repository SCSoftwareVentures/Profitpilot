-- All synthetic, rolled back. Run as migration administrator, not app.
BEGIN;
DO $test$
DECLARE t uuid:=gen_random_uuid(); other_t uuid:=gen_random_uuid(); a uuid:=gen_random_uuid(); v uuid:=gen_random_uuid();
 reader uuid:=gen_random_uuid(); b uuid:=gen_random_uuid(); raw uuid:=gen_random_uuid(); p uuid:=gen_random_uuid();
 s uuid:=gen_random_uuid(); r uuid:=gen_random_uuid(); biz uuid:=gen_random_uuid(); site uuid:=gen_random_uuid();
 proposal uuid; d text; who text; role_name text; expiry text; nonce text; k text; secret_value bytea; sig text;
BEGIN
 INSERT INTO public.tenants(id,legal_name) VALUES(t,'Synthetic payroll review'),(other_t,'Synthetic other');
 INSERT INTO public.users(id,auth_subject,email) VALUES(a,'ci-payroll-owner-'||a,'synthetic@example.invalid'),
 (v,'ci-payroll-reviewer-'||v,'synthetic@example.invalid'),(reader,'ci-payroll-reader-'||reader,'synthetic@example.invalid');
 INSERT INTO public.tenant_memberships(tenant_id,user_id,role) VALUES(t,a,'owner'),(t,v,'reviewer'),(t,reader,'read_only'),(other_t,v,'reviewer');
 INSERT INTO public.businesses(id,tenant_id,name) VALUES(biz,t,'Synthetic business');
 INSERT INTO public.sites(id,tenant_id,business_id,name) VALUES(site,t,biz,'Synthetic site');
 INSERT INTO public.import_batches(id,tenant_id,source_type,source_period_start,source_period_end,permission_ref,status,file_sha256,file_name,created_by)
 VALUES(b,t,'payroll','2026-11-01','2026-11-14','Synthetic authority','accepted',encode(public.digest(b::text,'sha256'),'hex'),'synthetic.csv',a);
 INSERT INTO public.raw_import_rows(id,tenant_id,batch_id,row_number,payload) VALUES(raw,t,b,1,'{"source_row_key":"row-a","amount":"0.30","currency":"AUD"}');
 INSERT INTO public.payroll_pools(id,tenant_id,batch_id,period_start,period_end,total_amount,currency,source_ref)
 VALUES(p,t,b,'2026-11-01','2026-11-14',0.30,'AUD','source-a');
 INSERT INTO public.payroll_source_rows(id,tenant_id,payroll_pool_id,raw_import_row_id,source_row_key,row_sha256,amount,currency)
 VALUES(s,t,p,raw,'row-a',encode(public.digest('row-a'||E'\n'||'0.30'||E'\n'||'AUD','sha256'),'hex'),0.30,'AUD');
 INSERT INTO public.allocation_runs(id,tenant_id,payroll_pool_id,method_version,status,direct_amount,residual_amount)
 VALUES(r,t,p,'synthetic-v1','review',0.30,0);
 INSERT INTO public.allocation_lines(tenant_id,allocation_run_id,site_id,bucket_type,amount,source_ref,payroll_source_row_id)
 VALUES(t,r,site,'direct',0.30,'evidence-a',s);

 IF has_function_privilege('profitpilot_app','private.submit_payroll_proposal(uuid,uuid)','EXECUTE')
 OR has_function_privilege('profitpilot_app','private.decide_payroll_proposal(uuid,uuid,text,text)','EXECUTE')
 OR has_any_column_privilege('profitpilot_app','private.payroll_proposal_reviews','SELECT,INSERT,UPDATE,REFERENCES')
 OR has_any_column_privilege('profitpilot_app','private.payroll_proposal_decisions','SELECT,INSERT,UPDATE,REFERENCES') THEN
  RAISE EXCEPTION 'Payroll review exposed to runtime';
 END IF;
 SELECT key_id,secret INTO k,secret_value FROM private.tenant_context_keys WHERE active ORDER BY key_id LIMIT 1;
 IF k IS NULL THEN RAISE EXCEPTION 'No CI signing key'; END IF;

 -- Bind short-lived signed contexts to each synthetic actor.
 FOREACH role_name IN ARRAY ARRAY['owner','read_only','reviewer'] LOOP
  who:=CASE role_name WHEN 'owner' THEN 'ci-payroll-owner-'||a WHEN 'reviewer' THEN 'ci-payroll-reviewer-'||v ELSE 'ci-payroll-reader-'||reader END;
  expiry:=(floor(extract(epoch FROM clock_timestamp()))::bigint+30)::text;
  nonce:=encode(public.gen_random_bytes(16),'hex');
  sig:=encode(public.hmac(convert_to(t::text||E'\n'||who||E'\n'||expiry||E'\n'||nonce||E'\n'||k,'UTF8'),secret_value,'sha256'),'hex');
  PERFORM set_config('app.tenant_id',t::text,true),set_config('app.tenant_subject',who,true),
   set_config('app.tenant_expires',expiry,true),set_config('app.tenant_nonce',nonce,true),
   set_config('app.tenant_key_id',k,true),set_config('app.tenant_signature',sig,true);
  IF role_name='owner' THEN
   proposal:=private.submit_payroll_proposal(t,r);
   IF private.submit_payroll_proposal(t,r) IS DISTINCT FROM proposal THEN RAISE EXCEPTION 'Replay not idempotent'; END IF;
   SELECT evidence_digest INTO d FROM private.payroll_proposal_reviews WHERE id=proposal AND tenant_id=t;
   BEGIN PERFORM private.decide_payroll_proposal(t,proposal,d,'reviewed'); RAISE EXCEPTION 'Self-review allowed'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
  ELSIF role_name='read_only' THEN
   BEGIN PERFORM private.submit_payroll_proposal(t,r); RAISE EXCEPTION 'Reader submitted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
   BEGIN PERFORM private.decide_payroll_proposal(t,proposal,d,'reviewed'); RAISE EXCEPTION 'Reader reviewed'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
  ELSE
   BEGIN PERFORM private.decide_payroll_proposal(other_t,proposal,d,'reviewed'); RAISE EXCEPTION 'Cross-tenant decision allowed'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
   BEGIN PERFORM private.decide_payroll_proposal(t,proposal,repeat('f',64),'reviewed'); RAISE EXCEPTION 'Incorrect digest accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
   -- Source metadata change invalidates reviewed acceptance, then restore for success.
   UPDATE public.payroll_pools SET source_ref='source-changed' WHERE id=p;
   BEGIN PERFORM private.decide_payroll_proposal(t,proposal,d,'reviewed'); RAISE EXCEPTION 'Stale digest accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
   UPDATE public.payroll_pools SET source_ref='source-a' WHERE id=p;
   PERFORM private.decide_payroll_proposal(t,proposal,d,'reviewed');
   BEGIN PERFORM private.decide_payroll_proposal(t,proposal,d,'rejected'); RAISE EXCEPTION 'Duplicate decision allowed'; EXCEPTION WHEN unique_violation THEN NULL; END;
  END IF;
 END LOOP;
 IF NOT EXISTS(SELECT 1 FROM private.payroll_proposal_decisions WHERE tenant_id=t AND proposal_id=proposal AND reviewer_id=v AND decision='reviewed')
 OR NOT EXISTS(SELECT 1 FROM public.allocation_runs WHERE tenant_id=t AND id=r AND status='review' AND reviewer_id IS NULL)
 OR (SELECT count(*) FROM public.audit_events WHERE tenant_id=t AND object_id=proposal)<>2
 OR private.verify_audit_chain(t) IS DISTINCT FROM true THEN RAISE EXCEPTION 'Review ledger or audit invariant failed'; END IF;
 BEGIN UPDATE private.payroll_proposal_decisions SET decision='rejected' WHERE proposal_id=proposal;
  RAISE EXCEPTION 'Review history mutable'; EXCEPTION WHEN object_not_in_prerequisite_state THEN NULL; END;
 RAISE NOTICE 'Payroll review isolation, replay, role, digest, audit and immutability checks passed';
END $test$;
ROLLBACK;
