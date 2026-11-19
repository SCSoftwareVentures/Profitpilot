-- Sandbox completion revision history, dispute linkage and authorized retention.
BEGIN;
ALTER TABLE securepay_private.work_completion DROP CONSTRAINT work_completion_tenant_id_milestone_id_key,
 DROP CONSTRAINT work_completion_status_check,
 ADD CONSTRAINT work_completion_status_check CHECK(status IN ('draft','submitted','approved','rejected')),
 ADD COLUMN rejected_at timestamptz, ADD COLUMN rejection_reason text,
 ADD CONSTRAINT sp_rejection_pair CHECK((status='rejected')=(rejected_at IS NOT NULL AND rejection_reason IS NOT NULL));
CREATE UNIQUE INDEX sp_active_completion ON securepay_private.work_completion(tenant_id,milestone_id) WHERE status<>'rejected';
ALTER TABLE securepay_private.work_photos ALTER COLUMN content DROP NOT NULL,ADD COLUMN purged_at timestamptz,
 ADD CONSTRAINT sp_work_purge_pair CHECK((content IS NULL)=(purged_at IS NOT NULL));
CREATE OR REPLACE FUNCTION securepay_private.start_work_completion(z uuid,t uuid,m uuid,a uuid,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE x public.securepay_milestones%ROWTYPE;
BEGIN
 IF z IS NULL OR t IS NULL OR m IS NULL OR a IS NULL OR securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-work-start-v1',z,t,m,a,expires),expires,sig) IS DISTINCT FROM 'owner' THEN RETURN false; END IF;
 SELECT * INTO x FROM public.securepay_milestones WHERE tenant_id=t AND id=m FOR UPDATE;
 IF NOT FOUND OR x.status<>'planned' OR x.payer_customer_id IS NULL OR a=x.payer_customer_id OR NOT EXISTS(SELECT 1 FROM securepay_private.work_assignments WHERE tenant_id=t AND milestone_id=m AND owner_id=a) THEN RETURN false; END IF;
 IF (SELECT count(*) FROM securepay_private.work_completion WHERE tenant_id=t AND milestone_id=m)>=5 THEN RETURN false; END IF;
 INSERT INTO securepay_private.work_completion(completion_id,tenant_id,milestone_id,owner_id,customer_id,amount_cents) VALUES(z,t,m,a,x.payer_customer_id,x.amount_cents);
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
CREATE OR REPLACE FUNCTION securepay_private.payer_work_photo(t uuid,m uuid,p uuid) RETURNS TABLE(digest text,content bytea)
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c uuid;w securepay_private.work_completion%ROWTYPE;photo securepay_private.work_photos%ROWTYPE;k bytea;plain bytea;
BEGIN
 c:=securepay_private.current_payer(t);
 IF c IS NULL THEN RETURN; END IF;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=m AND payer_customer_id=c FOR UPDATE;
 IF NOT FOUND THEN RETURN; END IF;
 SELECT * INTO w FROM securepay_private.work_completion WHERE tenant_id=t AND milestone_id=m AND customer_id=c AND status IN ('submitted','approved','rejected') AND EXISTS(SELECT 1 FROM securepay_private.work_photos q WHERE q.completion_id=work_completion.completion_id AND q.photo_id=p) FOR UPDATE;
 IF NOT FOUND THEN RETURN; END IF;
 SELECT * INTO photo FROM securepay_private.work_photos WHERE photo_id=p AND completion_id=w.completion_id AND tenant_id=t;
 IF NOT FOUND OR photo.purged_at IS NOT NULL THEN RETURN; END IF;
 SELECT secret INTO k FROM securepay_private.evidence_keys WHERE key_id=photo.key_id AND read_enabled;
 IF k IS NULL THEN RAISE EXCEPTION 'Evidence unavailable'; END IF;
 plain:=public.pgp_sym_decrypt_bytea(photo.content,encode(k,'hex'));
 IF octet_length(plain)<>photo.plaintext_size OR encode(public.digest(plain,'sha256'),'hex')<>photo.digest THEN RAISE EXCEPTION 'Evidence integrity failure'; END IF;
 INSERT INTO securepay_private.work_photo_views(tenant_id,completion_id,photo_id,customer_id) VALUES(t,w.completion_id,p,c) ON CONFLICT DO NOTHING;
 RETURN QUERY SELECT photo.digest,plain;
END $$;
CREATE OR REPLACE FUNCTION securepay_private.payer_completion_view(t uuid,m uuid) RETURNS jsonb
 LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT jsonb_build_object('completionId',w.completion_id,'manifestDigest',w.manifest_digest,'comments',w.comments,'version',x.version::text,'amountCents',w.amount_cents::text,'status',w.status,
 'photos',(SELECT coalesce(jsonb_agg(jsonb_build_object('photoId',p.photo_id,'digest',p.digest) ORDER BY p.photo_id),'[]'::jsonb) FROM securepay_private.work_photos p WHERE p.completion_id=w.completion_id))
 FROM securepay_private.work_completion w JOIN public.securepay_milestones x ON x.tenant_id=w.tenant_id AND x.id=w.milestone_id
 WHERE w.tenant_id=t AND w.milestone_id=m AND w.customer_id=securepay_private.current_payer(t) AND x.payer_customer_id=w.customer_id AND w.status IN ('submitted','approved','rejected')
 ORDER BY (w.status<>'rejected') DESC,w.rejected_at DESC NULLS LAST LIMIT 1
$$;
CREATE FUNCTION securepay_private.reject_work_completion(t uuid,m uuid,z uuid,manifest text,ver bigint,reason text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c uuid;x public.securepay_milestones%ROWTYPE;w securepay_private.work_completion%ROWTYPE;
BEGIN
 c:=securepay_private.current_payer(t);
 IF c IS NULL OR z IS NULL OR manifest IS NULL OR ver IS NULL OR reason IS NULL OR length(btrim(reason)) NOT BETWEEN 10 AND 2000 THEN RETURN false; END IF;
 SELECT * INTO x FROM public.securepay_milestones WHERE tenant_id=t AND id=m FOR UPDATE;
 IF NOT FOUND OR x.status<>'submitted' OR x.payer_customer_id IS DISTINCT FROM c OR x.version<>ver THEN RETURN false; END IF;
 SELECT * INTO w FROM securepay_private.work_completion WHERE completion_id=z AND tenant_id=t AND milestone_id=m AND customer_id=c AND status='submitted' FOR UPDATE;
 IF NOT FOUND OR w.manifest_digest<>manifest OR securepay_private.work_manifest(z) IS DISTINCT FROM manifest
 OR NOT EXISTS(SELECT 1 FROM securepay_private.work_photos WHERE completion_id=z)
 OR EXISTS(SELECT 1 FROM securepay_private.work_photos p WHERE p.completion_id=z AND NOT EXISTS(SELECT 1 FROM securepay_private.work_photo_views v WHERE v.completion_id=z AND v.photo_id=p.photo_id AND v.customer_id=c)) THEN RETURN false; END IF;
 UPDATE securepay_private.work_completion SET status='rejected',rejected_at=clock_timestamp(),rejection_reason=reason WHERE completion_id=z;
 UPDATE public.securepay_milestones SET status='planned',version=version+1,updated_at=clock_timestamp() WHERE tenant_id=t AND id=m;
 RETURN true;
END $$;
CREATE TABLE securepay_private.work_dispute_links(
 case_id uuid NOT NULL REFERENCES securepay_private.dispute_cases(case_id),
 completion_id uuid NOT NULL REFERENCES securepay_private.work_completion(completion_id),
 tenant_id uuid NOT NULL,manifest_digest text NOT NULL,
 PRIMARY KEY(case_id,completion_id)
);
ALTER TABLE securepay_private.work_dispute_links OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.work_dispute_links FROM PUBLIC;
CREATE TRIGGER sp_chain_work_dispute_links AFTER INSERT ON securepay_private.work_dispute_links FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE FUNCTION securepay_private.link_work_dispute() RETURNS trigger
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 INSERT INTO securepay_private.work_dispute_links(case_id,completion_id,tenant_id,manifest_digest)
 SELECT NEW.case_id,w.completion_id,w.tenant_id,w.manifest_digest FROM securepay_private.work_completion w
 WHERE w.tenant_id=NEW.tenant_id AND w.milestone_id=NEW.milestone_id AND w.customer_id=NEW.customer_id AND w.manifest_digest IS NOT NULL;
 RETURN NEW;
END $$;
ALTER FUNCTION securepay_private.link_work_dispute() OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.link_work_dispute() FROM PUBLIC;
CREATE TRIGGER sp_link_work_dispute AFTER INSERT ON securepay_private.dispute_cases FOR EACH ROW EXECUTE FUNCTION securepay_private.link_work_dispute();
CREATE FUNCTION securepay_private.payer_open_work_dispute(t uuid,m uuid,d uuid,e uuid,level text,reason text,manifest text,ver bigint) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c uuid;x public.securepay_milestones%ROWTYPE;w securepay_private.work_completion%ROWTYPE;a uuid;
BEGIN
 c:=securepay_private.current_payer(t);
 IF c IS NULL OR d IS NULL OR e IS NULL OR level IS NULL OR level NOT IN ('minor','moderate','serious')
 OR reason IS NULL OR length(btrim(reason)) NOT BETWEEN 10 AND 2000 OR manifest IS NULL OR ver IS NULL THEN RETURN false; END IF;
 SELECT * INTO x FROM public.securepay_milestones WHERE tenant_id=t AND id=m FOR UPDATE;
 IF NOT FOUND OR x.payer_customer_id IS DISTINCT FROM c OR x.version<>ver OR x.status NOT IN ('planned','submitted','approved','release_pending') THEN RETURN false; END IF;
 PERFORM 1 FROM securepay_private.provider_funding WHERE tenant_id=t AND milestone_id=m AND status IN ('funded','held') FOR UPDATE;
 IF NOT FOUND OR EXISTS(SELECT 1 FROM public.securepay_release_requests WHERE tenant_id=t AND milestone_id=m AND status IN ('submitted','confirmed','failed')) THEN RETURN false; END IF;
 SELECT * INTO w FROM securepay_private.work_completion WHERE tenant_id=t AND milestone_id=m AND customer_id=c AND manifest_digest=manifest AND status IN ('submitted','approved','rejected') FOR UPDATE;
 IF NOT FOUND OR securepay_private.work_manifest(w.completion_id) IS DISTINCT FROM manifest THEN RETURN false; END IF;
 IF EXISTS(SELECT 1 FROM securepay_private.work_completion q WHERE q.tenant_id=t AND q.milestone_id=m AND q.status IN ('submitted','approved') AND q.completion_id<>w.completion_id) THEN RETURN false; END IF;
 SELECT owner_id INTO a FROM securepay_private.work_assignments WHERE tenant_id=t AND milestone_id=m;
 IF a IS NULL OR a=c OR a<>w.owner_id OR NOT EXISTS(SELECT 1 FROM securepay_private.dispute_actors WHERE tenant_id=t AND actor_id=a AND role='owner' AND active) THEN RETURN false; END IF;
 INSERT INTO securepay_private.dispute_cases(case_id,tenant_id,milestone_id,customer_id,owner_id,severity,status,customer_evidence) VALUES(d,t,m,c,a,level,'open',true);
 INSERT INTO securepay_private.dispute_events(event_id,case_id,actor_id,action,details,evidence_digest) VALUES(e,d,c,'open_work',reason,manifest);
 UPDATE public.securepay_release_requests SET status='failed' WHERE tenant_id=t AND milestone_id=m AND status='pending';
 DELETE FROM public.securepay_release_proofs WHERE tenant_id=t AND milestone_id=m AND consumed_at IS NULL;
 UPDATE public.securepay_milestones SET status='disputed',version=version+1,updated_at=clock_timestamp() WHERE tenant_id=t AND id=m;
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
CREATE TABLE securepay_private.work_retention_policy(
 tenant_id uuid NOT NULL,milestone_id uuid NOT NULL,retain_until timestamptz NOT NULL,legal_hold boolean NOT NULL DEFAULT true,
 reason text NOT NULL CHECK(length(btrim(reason)) BETWEEN 10 AND 1000),PRIMARY KEY(tenant_id,milestone_id),
 FOREIGN KEY(tenant_id,milestone_id) REFERENCES public.securepay_milestones(tenant_id,id)
);
ALTER TABLE securepay_private.work_retention_policy OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.work_retention_policy FROM PUBLIC;
CREATE TRIGGER sp_chain_work_retention AFTER INSERT OR UPDATE OR DELETE ON securepay_private.work_retention_policy FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE FUNCTION securepay_private.purge_work_evidence(batch_size integer) RETURNS integer
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE x public.securepay_milestones%ROWTYPE;n integer:=0;changed integer;
BEGIN
 IF batch_size IS NULL OR batch_size NOT BETWEEN 1 AND 100 THEN RETURN 0; END IF;
 FOR x IN SELECT m.* FROM public.securepay_milestones m JOIN securepay_private.work_retention_policy p ON p.tenant_id=m.tenant_id AND p.milestone_id=m.id
 WHERE m.status IN ('released','settled') AND NOT p.legal_hold AND p.retain_until<=clock_timestamp()
 AND EXISTS(SELECT 1 FROM securepay_private.work_photos q JOIN securepay_private.work_completion w ON w.completion_id=q.completion_id WHERE w.tenant_id=m.tenant_id AND w.milestone_id=m.id AND q.purged_at IS NULL)
 ORDER BY p.retain_until,m.id LIMIT batch_size FOR UPDATE OF m SKIP LOCKED LOOP
  PERFORM 1 FROM securepay_private.work_retention_policy p WHERE p.tenant_id=x.tenant_id AND p.milestone_id=x.id AND NOT p.legal_hold AND p.retain_until<=clock_timestamp() FOR UPDATE;
  IF NOT FOUND OR EXISTS(SELECT 1 FROM securepay_private.provider_reconciliation r WHERE r.tenant_id=x.tenant_id AND r.milestone_id=x.id AND r.resolved_at IS NULL)
  OR EXISTS(SELECT 1 FROM securepay_private.dispute_cases d WHERE d.tenant_id=x.tenant_id AND d.milestone_id=x.id AND (d.status<>'settled' OR EXISTS(SELECT 1 FROM securepay_private.settlement_leg_conflicts r WHERE r.case_id=d.case_id AND r.resolved_at IS NULL) OR EXISTS(SELECT 1 FROM securepay_private.evidence_retention_policy p WHERE p.case_id=d.case_id AND (p.legal_hold OR p.retain_until>clock_timestamp())))) THEN CONTINUE; END IF;
  -- Lock case and policy before removal; no purge if case policy is absent.
  PERFORM 1 FROM securepay_private.dispute_cases d WHERE d.tenant_id=x.tenant_id AND d.milestone_id=x.id FOR UPDATE;
  IF FOUND THEN
   PERFORM 1 FROM securepay_private.evidence_retention_policy p JOIN securepay_private.dispute_cases d ON d.case_id=p.case_id WHERE d.tenant_id=x.tenant_id AND d.milestone_id=x.id AND NOT p.legal_hold AND p.retain_until<=clock_timestamp() FOR UPDATE OF p;
   IF NOT FOUND THEN CONTINUE; END IF;
  END IF;
  UPDATE securepay_private.work_photos q SET content=NULL,purged_at=clock_timestamp() FROM securepay_private.work_completion w WHERE q.completion_id=w.completion_id AND w.tenant_id=x.tenant_id AND w.milestone_id=x.id AND q.purged_at IS NULL;
  GET DIAGNOSTICS changed=ROW_COUNT;n:=n+changed;
 END LOOP;
 RETURN n;
END $$;
ALTER FUNCTION securepay_private.reject_work_completion(uuid,uuid,uuid,text,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.reject_work_completion(uuid,uuid,uuid,text,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.reject_work_completion(uuid,uuid,uuid,text,bigint,text) TO securepay_payer_runtime;
ALTER FUNCTION securepay_private.payer_open_work_dispute(uuid,uuid,uuid,uuid,text,text,text,bigint) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.payer_open_work_dispute(uuid,uuid,uuid,uuid,text,text,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.payer_open_work_dispute(uuid,uuid,uuid,uuid,text,text,text,bigint) TO securepay_payer_runtime;
ALTER FUNCTION securepay_private.purge_work_evidence(integer) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.purge_work_evidence(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.purge_work_evidence(integer) TO securepay_retention_runtime;
-- Assigned owner can resume a draft and read previous rejection reasons.
CREATE FUNCTION securepay_private.owner_work_status(t uuid,m uuid,a uuid,expires bigint,sig text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE result jsonb;
BEGIN
 IF t IS NULL OR m IS NULL OR a IS NULL OR securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-work-status-v1',t,m,a,expires),expires,sig) IS DISTINCT FROM 'owner'
 OR NOT EXISTS(SELECT 1 FROM securepay_private.work_assignments WHERE tenant_id=t AND milestone_id=m AND owner_id=a) THEN RETURN NULL; END IF;
 SELECT jsonb_build_object('milestoneId',x.id,'status',x.status,'amountCents',x.amount_cents::text,
 'current',(SELECT jsonb_build_object('completionId',w.completion_id,'status',w.status,'photoCount',(SELECT count(*) FROM securepay_private.work_photos p WHERE p.completion_id=w.completion_id)) FROM securepay_private.work_completion w WHERE w.tenant_id=t AND w.milestone_id=m AND w.status<>'rejected'),
 'rejections',(SELECT coalesce(jsonb_agg(jsonb_build_object('completionId',w.completion_id,'reason',w.rejection_reason,'rejectedAt',w.rejected_at) ORDER BY w.rejected_at),'[]'::jsonb) FROM securepay_private.work_completion w WHERE w.tenant_id=t AND w.milestone_id=m AND w.status='rejected')) INTO result
 FROM public.securepay_milestones x WHERE x.tenant_id=t AND x.id=m;
 RETURN result;
END $$;
ALTER FUNCTION securepay_private.owner_work_status(uuid,uuid,uuid,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.owner_work_status(uuid,uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.owner_work_status(uuid,uuid,uuid,bigint,text) TO securepay_completion_runtime;
CREATE FUNCTION securepay_private.dispute_work_evidence(t uuid,m uuid,d uuid,a uuid,p uuid,expires bigint,sig text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c securepay_private.dispute_cases%ROWTYPE;role_name text;photo securepay_private.work_photos%ROWTYPE;k bytea;plain bytea;items jsonb;
BEGIN
 role_name:=securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-linked-work-v1',t,m,d,a,coalesce(p::text,'-'),expires),expires,sig);
 IF role_name IS NULL OR t IS NULL OR m IS NULL OR d IS NULL OR a IS NULL THEN RETURN NULL; END IF;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=m FOR UPDATE;
 IF NOT FOUND THEN RETURN NULL; END IF;
 SELECT * INTO c FROM securepay_private.dispute_cases WHERE tenant_id=t AND milestone_id=m AND case_id=d FOR UPDATE;
 IF NOT FOUND OR NOT ((role_name='customer' AND a=c.customer_id) OR (role_name='owner' AND a=c.owner_id) OR (role_name='reviewer' AND EXISTS(SELECT 1 FROM securepay_private.dispute_photo_reviewers WHERE case_id=d AND tenant_id=t AND reviewer_id=a))) THEN RETURN NULL; END IF;
 IF p IS NULL THEN
  SELECT coalesce(jsonb_agg(jsonb_build_object('completionId',w.completion_id,'manifestDigest',l.manifest_digest,'comments',w.comments,'status',w.status,'rejectionReason',w.rejection_reason,
   'photos',(SELECT coalesce(jsonb_agg(jsonb_build_object('photoId',q.photo_id,'digest',q.digest,'purged',q.purged_at IS NOT NULL) ORDER BY q.photo_id),'[]'::jsonb) FROM securepay_private.work_photos q WHERE q.completion_id=w.completion_id)) ORDER BY w.completion_id),'[]'::jsonb) INTO items
  FROM securepay_private.work_dispute_links l JOIN securepay_private.work_completion w ON w.completion_id=l.completion_id WHERE l.case_id=d AND l.tenant_id=t;
  RETURN jsonb_build_object('completions',items);
 END IF;
 SELECT q.* INTO photo FROM securepay_private.work_photos q JOIN securepay_private.work_dispute_links l ON l.completion_id=q.completion_id WHERE l.case_id=d AND l.tenant_id=t AND q.photo_id=p AND q.tenant_id=t;
 IF NOT FOUND OR photo.purged_at IS NOT NULL THEN RETURN NULL; END IF;
 SELECT secret INTO k FROM securepay_private.evidence_keys WHERE key_id=photo.key_id AND read_enabled;
 IF k IS NULL THEN RAISE EXCEPTION 'Evidence unavailable'; END IF;
 plain:=public.pgp_sym_decrypt_bytea(photo.content,encode(k,'hex'));
 IF octet_length(plain)<>photo.plaintext_size OR encode(public.digest(plain,'sha256'),'hex')<>photo.digest THEN RAISE EXCEPTION 'Evidence integrity failure'; END IF;
 PERFORM securepay_private.append_audit_chain(t,'work_photos','READ',encode(public.digest(convert_to(concat_ws(':',p,d,a,photo.digest),'UTF8'),'sha256'),'hex'));
 RETURN jsonb_build_object('photoId',p,'digest',photo.digest,'content',replace(encode(plain,'base64'),chr(10),''));
END $$;
ALTER FUNCTION securepay_private.dispute_work_evidence(uuid,uuid,uuid,uuid,uuid,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.dispute_work_evidence(uuid,uuid,uuid,uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.dispute_work_evidence(uuid,uuid,uuid,uuid,uuid,bigint,text) TO securepay_dispute_runtime;

COMMIT;
