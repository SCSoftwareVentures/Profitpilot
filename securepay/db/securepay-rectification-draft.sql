-- Sandbox rectification, evidence storage and deadline escalation. No money moves.
BEGIN;
CREATE ROLE securepay_escalation_runtime NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
GRANT USAGE ON SCHEMA securepay_private TO securepay_escalation_runtime;
CREATE TABLE securepay_private.dispute_holidays(day date PRIMARY KEY);
ALTER TABLE securepay_private.dispute_holidays OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.dispute_holidays FROM PUBLIC;
-- Melbourne-local weekdays, excluding explicitly provisioned holidays.
-- Due at 17:00 on the Nth following business day; never count the opening date.
CREATE FUNCTION securepay_private.business_deadline(start_at timestamptz,n integer) RETURNS timestamptz
 LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE d date; remaining integer:=n;
BEGIN
 IF start_at IS NULL OR n IS NULL OR n NOT BETWEEN 1 AND 10 THEN RETURN NULL; END IF;
 d:=(start_at AT TIME ZONE 'Australia/Melbourne')::date;
 WHILE remaining>0 LOOP
  d:=d+1;
  IF extract(isodow FROM d)<=5 AND NOT EXISTS(SELECT 1 FROM securepay_private.dispute_holidays WHERE day=d) THEN remaining:=remaining-1; END IF;
 END LOOP;
 RETURN (d+time '17:00') AT TIME ZONE 'Australia/Melbourne';
END $$;
ALTER FUNCTION securepay_private.business_deadline(timestamptz,integer) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.business_deadline(timestamptz,integer) FROM PUBLIC;

ALTER TABLE securepay_private.dispute_cases
 ADD COLUMN response_due_at timestamptz,
 ADD COLUMN owner_responded_at timestamptz,
 ADD COLUMN response_escalated_at timestamptz,
 ADD COLUMN repair_phase text NOT NULL DEFAULT 'none' CHECK(repair_phase IN ('none','proposed','active','submitted','accepted','escalated')),
 ADD COLUMN repair_due_at timestamptz,
 ADD COLUMN repair_started_at timestamptz,
 ADD COLUMN repair_review_due_at timestamptz,
 ADD COLUMN repair_photo_id uuid;
CREATE TABLE securepay_private.dispute_deadline_events(
 case_id uuid NOT NULL REFERENCES securepay_private.dispute_cases(case_id),
 kind text NOT NULL CHECK(kind IN ('owner_response_overdue','repair_overdue','repair_review_overdue')),
 due_at timestamptz NOT NULL, recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(case_id,kind,due_at)
);
ALTER TABLE securepay_private.dispute_deadline_events OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.dispute_deadline_events FROM PUBLIC;
CREATE FUNCTION securepay_private.initialize_case_deadline() RETURNS trigger
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  NEW.response_due_at:=securepay_private.business_deadline(NEW.created_at,CASE NEW.severity WHEN 'minor' THEN 2 WHEN 'moderate' THEN 3 ELSE 1 END);
 ELSIF NEW.owner_evidence AND NOT OLD.owner_evidence THEN
  NEW.owner_responded_at:=clock_timestamp();
  IF NEW.owner_responded_at>NEW.response_due_at AND NEW.response_escalated_at IS NULL THEN
   NEW.response_escalated_at:=clock_timestamp();
   INSERT INTO securepay_private.dispute_deadline_events(case_id,kind,due_at) VALUES(NEW.case_id,'owner_response_overdue',NEW.response_due_at) ON CONFLICT DO NOTHING;
  END IF;
 END IF;
 RETURN NEW;
END $$;
ALTER FUNCTION securepay_private.initialize_case_deadline() OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.initialize_case_deadline() FROM PUBLIC;
UPDATE securepay_private.dispute_cases SET response_due_at=securepay_private.business_deadline(created_at,CASE severity WHEN 'minor' THEN 2 WHEN 'moderate' THEN 3 ELSE 1 END);
ALTER TABLE securepay_private.dispute_cases ALTER COLUMN response_due_at SET NOT NULL;
CREATE TRIGGER sp_dispute_deadlines BEFORE INSERT OR UPDATE OF owner_evidence ON securepay_private.dispute_cases FOR EACH ROW EXECUTE FUNCTION securepay_private.initialize_case_deadline();

-- Bounded sandbox photo store: exact SHA-256 content binding and no runtime table grants.
-- Header checks are not a complete image decoder, malware scanner or EXIF scrubber.
CREATE TABLE securepay_private.dispute_photos(
 photo_id uuid PRIMARY KEY,case_id uuid NOT NULL REFERENCES securepay_private.dispute_cases(case_id),
 actor_id uuid NOT NULL,media_type text NOT NULL CHECK(media_type IN ('image/jpeg','image/png')),
 digest text NOT NULL CHECK(digest ~ '^[a-f0-9]{64}$'),content bytea NOT NULL CHECK(octet_length(content) BETWEEN 8 AND 2097152),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(case_id,actor_id,digest)
);
ALTER TABLE securepay_private.dispute_photos OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.dispute_photos FROM PUBLIC,securepay_dispute_runtime,securepay_payer_runtime,securepay_provider_runtime,securepay_settlement_runtime;
ALTER TABLE securepay_private.dispute_cases ADD FOREIGN KEY(repair_photo_id) REFERENCES securepay_private.dispute_photos(photo_id);
CREATE FUNCTION securepay_private.store_dispute_photo(p uuid,t uuid,m uuid,d uuid,a uuid,mime text,digest text,blob bytea,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c securepay_private.dispute_cases%ROWTYPE; role_name text;
BEGIN
 IF p IS NULL OR t IS NULL OR m IS NULL OR d IS NULL OR a IS NULL OR mime IS NULL OR mime NOT IN ('image/jpeg','image/png')
 OR digest IS NULL OR digest !~ '^[a-f0-9]{64}$' OR blob IS NULL OR octet_length(blob) NOT BETWEEN 8 AND 2097152
 OR encode(public.digest(blob,'sha256'),'hex')<>digest THEN RETURN false; END IF;
 IF (mime='image/png' AND substring(blob FROM 1 FOR 8)<>decode('89504e470d0a1a0a','hex'))
 OR (mime='image/jpeg' AND (substring(blob FROM 1 FOR 3)<>decode('ffd8ff','hex') OR substring(blob FROM octet_length(blob)-1 FOR 2)<>decode('ffd9','hex'))) THEN RETURN false; END IF;
 role_name:=securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-photo-v1',p,t,m,d,a,mime,digest,expires),expires,sig);
 IF role_name IS NULL OR role_name NOT IN ('owner','customer') THEN RETURN false; END IF;
 SELECT * INTO c FROM securepay_private.dispute_cases WHERE case_id=d AND tenant_id=t AND milestone_id=m AND status IN ('open','appealed') FOR UPDATE;
 IF NOT FOUND OR (role_name='owner' AND a<>c.owner_id) OR (role_name='customer' AND a<>c.customer_id) THEN RETURN false; END IF;
 IF (SELECT count(*) FROM securepay_private.dispute_photos WHERE case_id=d)>=12 THEN RETURN false; END IF;
 INSERT INTO securepay_private.dispute_photos(photo_id,case_id,actor_id,media_type,digest,content) VALUES(p,d,a,mime,digest,blob);
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
ALTER FUNCTION securepay_private.store_dispute_photo(uuid,uuid,uuid,uuid,uuid,text,text,bytea,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.store_dispute_photo(uuid,uuid,uuid,uuid,uuid,text,text,bytea,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.store_dispute_photo(uuid,uuid,uuid,uuid,uuid,text,text,bytea,bigint,text) TO securepay_dispute_runtime;

CREATE FUNCTION securepay_private.repair_action(e uuid,t uuid,m uuid,d uuid,a uuid,op text,details text,due bigint,photo uuid,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c securepay_private.dispute_cases%ROWTYPE; role_name text; now_at timestamptz:=clock_timestamp(); photo_digest text;
BEGIN
 IF e IS NULL OR t IS NULL OR m IS NULL OR d IS NULL OR a IS NULL OR op IS NULL OR details IS NULL OR length(btrim(details))=0 OR length(details)>4000 THEN RETURN false; END IF;
 role_name:=securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-repair-v1',e,t,m,d,a,op,encode(convert_to(details,'UTF8'),'hex'),coalesce(due::text,'-'),coalesce(photo::text,'-'),expires),expires,sig);
 IF role_name IS NULL OR role_name NOT IN ('owner','customer','reviewer') THEN RETURN false; END IF;
 PERFORM 1 FROM public.securepay_milestones WHERE tenant_id=t AND id=m AND status='disputed' FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO c FROM securepay_private.dispute_cases WHERE case_id=d AND tenant_id=t AND milestone_id=m AND status='open' FOR UPDATE;
 IF NOT FOUND OR (role_name='owner' AND a<>c.owner_id) OR (role_name='customer' AND a<>c.customer_id)
 OR (role_name='reviewer' AND a IN (c.owner_id,c.customer_id)) THEN RETURN false; END IF;
 now_at:=clock_timestamp();
 IF op IN ('propose','reviewer_plan') THEN
  IF due IS NULL OR due<=extract(epoch FROM now_at) OR due>extract(epoch FROM now_at+interval '90 days') OR photo IS NOT NULL THEN RETURN false; END IF;
  IF op='propose' AND role_name='owner' AND c.severity<>'serious' AND c.repair_phase='none' THEN
   UPDATE securepay_private.dispute_cases SET repair_phase='proposed',repair_due_at=to_timestamp(due) WHERE case_id=d;
  ELSIF op='reviewer_plan' AND role_name='reviewer' AND c.repair_phase IN ('none','proposed') THEN
   UPDATE securepay_private.dispute_cases SET repair_phase='active',repair_due_at=to_timestamp(due),repair_started_at=now_at WHERE case_id=d;
  ELSE RETURN false; END IF;
 ELSIF op='accept_plan' THEN
  IF role_name<>'customer' OR c.repair_phase<>'proposed' OR c.repair_due_at<=now_at OR due IS NOT NULL OR photo IS NOT NULL THEN RETURN false; END IF;
  UPDATE securepay_private.dispute_cases SET repair_phase='active',repair_started_at=now_at WHERE case_id=d;
 ELSIF op='submit_repair' THEN
  IF role_name<>'owner' OR c.repair_phase<>'active' OR due IS NOT NULL OR photo IS NULL THEN RETURN false; END IF;
  SELECT digest INTO photo_digest FROM securepay_private.dispute_photos WHERE photo_id=photo AND case_id=d AND actor_id=a AND created_at>=c.repair_started_at;
  IF NOT FOUND THEN RETURN false; END IF;
  IF c.repair_due_at<=now_at THEN
   INSERT INTO securepay_private.dispute_deadline_events(case_id,kind,due_at) VALUES(d,'repair_overdue',c.repair_due_at) ON CONFLICT DO NOTHING;
   UPDATE securepay_private.dispute_cases SET repair_phase='escalated',repair_photo_id=photo,owner_evidence=true WHERE case_id=d;
  ELSE
   UPDATE securepay_private.dispute_cases SET repair_phase='submitted',repair_photo_id=photo,owner_evidence=true,repair_review_due_at=securepay_private.business_deadline(now_at,2) WHERE case_id=d;
  END IF;
 ELSIF op='accept_repair' THEN
  IF role_name<>'customer' OR c.repair_phase<>'submitted' OR c.repair_review_due_at<=now_at OR photo IS DISTINCT FROM c.repair_photo_id OR due IS NOT NULL THEN RETURN false; END IF;
  UPDATE securepay_private.dispute_cases SET repair_phase='accepted' WHERE case_id=d;
 ELSIF op='escalate' THEN
  IF c.repair_phase NOT IN ('proposed','active','submitted') OR due IS NOT NULL OR photo IS NOT NULL THEN RETURN false; END IF;
  UPDATE securepay_private.dispute_cases SET repair_phase='escalated' WHERE case_id=d;
 ELSE RETURN false; END IF;
 INSERT INTO securepay_private.dispute_events(event_id,case_id,actor_id,action,details,evidence_digest) VALUES(e,d,a,'repair_'||op,details,photo_digest);
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;
ALTER FUNCTION securepay_private.repair_action(uuid,uuid,uuid,uuid,uuid,text,text,bigint,uuid,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.repair_action(uuid,uuid,uuid,uuid,uuid,text,text,bigint,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.repair_action(uuid,uuid,uuid,uuid,uuid,text,text,bigint,uuid,bigint,text) TO securepay_dispute_runtime;

CREATE OR REPLACE FUNCTION securepay_private.dispute_action(e uuid,t uuid,m uuid,d uuid,a uuid,op text,details text,digest text,payout bigint,refund bigint,expires bigint,sig text) RETURNS boolean
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE role_name text; milestone public.securepay_milestones%ROWTYPE; c securepay_private.dispute_cases%ROWTYPE; owner uuid;
BEGIN
 IF e IS NULL OR t IS NULL OR m IS NULL OR d IS NULL OR a IS NULL OR op IS NULL OR details IS NULL
 OR length(details)>4000 OR (digest IS NOT NULL AND digest !~ '^[a-f0-9]{64}$') THEN RETURN false; END IF;
 role_name:=securepay_private.dispute_actor_valid(t,a,concat_ws(':','sp-dispute-v1',e,t,m,d,a,op,encode(convert_to(details,'UTF8'),'hex'),coalesce(digest,'-'),coalesce(payout::text,'-'),coalesce(refund::text,'-'),expires),expires,sig);
 IF role_name IS NULL OR role_name='settlement' THEN RETURN false; END IF;
 SELECT * INTO milestone FROM public.securepay_milestones WHERE tenant_id=t AND id=m FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 PERFORM 1 FROM securepay_private.provider_funding WHERE tenant_id=t AND milestone_id=m AND status IN ('funded','held') FOR UPDATE;
 IF NOT FOUND THEN RETURN false; END IF;
 IF op='open' THEN
  IF role_name<>'customer' OR a IS DISTINCT FROM milestone.payer_customer_id OR details NOT IN ('minor','moderate','serious') OR digest IS NULL
  OR payout IS NOT NULL OR refund IS NOT NULL OR milestone.status NOT IN ('submitted','approved','release_pending')
  OR EXISTS(SELECT 1 FROM public.securepay_release_requests WHERE tenant_id=t AND milestone_id=m AND status IN ('submitted','confirmed','failed')) THEN RETURN false; END IF;
  SELECT owner_id INTO owner FROM securepay_private.dispute_parties WHERE tenant_id=t AND milestone_id=m;
  IF owner IS NULL OR owner=a OR NOT EXISTS(SELECT 1 FROM securepay_private.dispute_actors WHERE tenant_id=t AND actor_id=owner AND role='owner' AND active) THEN RETURN false; END IF;
  INSERT INTO securepay_private.dispute_cases(case_id,tenant_id,milestone_id,customer_id,owner_id,severity,status,customer_evidence)
  VALUES(d,t,m,a,owner,details,'open',true);
  UPDATE public.securepay_release_requests SET status='failed' WHERE tenant_id=t AND milestone_id=m AND status='pending';
  DELETE FROM public.securepay_release_proofs WHERE tenant_id=t AND milestone_id=m AND consumed_at IS NULL;
  UPDATE public.securepay_milestones SET status='disputed',version=version+1,updated_at=clock_timestamp() WHERE id=m;
 ELSE
  SELECT * INTO c FROM securepay_private.dispute_cases WHERE case_id=d AND tenant_id=t AND milestone_id=m FOR UPDATE;
  IF NOT FOUND OR milestone.status<>'disputed' THEN RETURN false; END IF;
  IF op='evidence' THEN
   IF c.status NOT IN ('open','appealed') OR digest IS NULL OR length(btrim(details))=0 OR payout IS NOT NULL OR refund IS NOT NULL THEN RETURN false; END IF;
   IF role_name='customer' AND a=c.customer_id THEN UPDATE securepay_private.dispute_cases SET customer_evidence=true,customer_appeal_evidence=customer_appeal_evidence OR c.status='appealed' WHERE case_id=d;
   ELSIF role_name='owner' AND a=c.owner_id THEN UPDATE securepay_private.dispute_cases SET owner_evidence=true,owner_appeal_evidence=owner_appeal_evidence OR c.status='appealed' WHERE case_id=d;
   ELSE RETURN false; END IF;
  ELSIF op IN ('decide','finalize') THEN
   IF role_name<>'reviewer' OR a IN (c.owner_id,c.customer_id) OR NOT c.customer_evidence OR NOT c.owner_evidence
   OR length(btrim(details))<10 OR digest IS NULL OR payout IS NULL OR refund IS NULL OR payout<0 OR refund<0
   OR payout::numeric+refund::numeric<>milestone.amount_cents THEN RETURN false; END IF;
   IF op='decide' AND c.status='open' AND c.repair_phase IN ('none','escalated','accepted')
    AND (c.repair_phase<>'accepted' OR (payout=milestone.amount_cents AND refund=0)) THEN
    UPDATE securepay_private.dispute_cases SET status='decided',first_reviewer=a,payout_cents=payout,refund_cents=refund WHERE case_id=d;
   ELSIF op='finalize' AND c.status IN ('decided','appealed') AND a IS DISTINCT FROM c.first_reviewer
    AND ((c.status='appealed' AND c.customer_appeal_evidence AND c.owner_appeal_evidence) OR (c.status='decided' AND c.customer_ack AND c.owner_ack))
    AND (c.status='appealed' OR (payout=c.payout_cents AND refund=c.refund_cents)) THEN
    UPDATE securepay_private.dispute_cases SET status='final',final_reviewer=a,payout_cents=payout,refund_cents=refund WHERE case_id=d;
   ELSE RETURN false; END IF;
  ELSIF op IN ('ack','appeal') THEN
   IF c.status<>'decided' OR payout IS NOT NULL OR refund IS NOT NULL OR length(btrim(details))=0
   OR NOT ((role_name='customer' AND a=c.customer_id) OR (role_name='owner' AND a=c.owner_id)) THEN RETURN false; END IF;
   IF op='appeal' THEN
    IF digest IS NULL THEN RETURN false; END IF;
    UPDATE securepay_private.dispute_cases SET status='appealed',customer_appeal_evidence=(a=c.customer_id),owner_appeal_evidence=(a=c.owner_id) WHERE case_id=d;
   ELSIF a=c.customer_id THEN UPDATE securepay_private.dispute_cases SET customer_ack=true WHERE case_id=d;
   ELSE UPDATE securepay_private.dispute_cases SET owner_ack=true WHERE case_id=d; END IF;
  ELSE RETURN false; END IF;
 END IF;
 INSERT INTO securepay_private.dispute_events(event_id,case_id,actor_id,action,details,evidence_digest,payout_cents,refund_cents)
 VALUES(e,d,a,op,details,digest,payout,refund);
 RETURN true;
EXCEPTION WHEN unique_violation THEN RETURN false;
END $$;

-- Escalation never changes a payout, refund, funding status or milestone state.
CREATE FUNCTION securepay_private.scan_dispute_deadlines(batch_size integer) RETURNS integer
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c securepay_private.dispute_cases%ROWTYPE; total integer:=0; now_at timestamptz:=clock_timestamp();
BEGIN
 IF batch_size IS NULL OR batch_size NOT BETWEEN 1 AND 100 THEN RETURN 0; END IF;
 FOR c IN SELECT * FROM securepay_private.dispute_cases q WHERE q.status='open' AND
 ((q.owner_responded_at IS NULL AND q.response_escalated_at IS NULL AND q.response_due_at<=now_at)
 OR (q.repair_phase IN ('proposed','active') AND q.repair_due_at<=now_at)
 OR (q.repair_phase='submitted' AND q.repair_review_due_at<=now_at))
 ORDER BY q.created_at LIMIT batch_size FOR UPDATE SKIP LOCKED LOOP
  IF c.owner_responded_at IS NULL AND c.response_escalated_at IS NULL AND c.response_due_at<=now_at THEN
   INSERT INTO securepay_private.dispute_deadline_events(case_id,kind,due_at) VALUES(c.case_id,'owner_response_overdue',c.response_due_at) ON CONFLICT DO NOTHING;
   UPDATE securepay_private.dispute_cases SET response_escalated_at=now_at WHERE case_id=c.case_id;
  END IF;
  IF c.repair_phase IN ('proposed','active') AND c.repair_due_at<=now_at THEN
   INSERT INTO securepay_private.dispute_deadline_events(case_id,kind,due_at) VALUES(c.case_id,'repair_overdue',c.repair_due_at) ON CONFLICT DO NOTHING;
   UPDATE securepay_private.dispute_cases SET repair_phase='escalated' WHERE case_id=c.case_id;
  ELSIF c.repair_phase='submitted' AND c.repair_review_due_at<=now_at THEN
   INSERT INTO securepay_private.dispute_deadline_events(case_id,kind,due_at) VALUES(c.case_id,'repair_review_overdue',c.repair_review_due_at) ON CONFLICT DO NOTHING;
   UPDATE securepay_private.dispute_cases SET repair_phase='escalated' WHERE case_id=c.case_id;
  END IF;
  total:=total+1;
 END LOOP;
 RETURN total;
END $$;
ALTER FUNCTION securepay_private.scan_dispute_deadlines(integer) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.scan_dispute_deadlines(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.scan_dispute_deadlines(integer) TO securepay_escalation_runtime;
COMMIT;
