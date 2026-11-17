-- Preserve account-wide revocation evidence across repeated incidents and restores.
BEGIN;
CREATE TABLE private.account_session_revocation_receipts(
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 user_id uuid NOT NULL REFERENCES public.users(id) ON DELETE RESTRICT,
 revoked_through_epoch bigint NOT NULL CHECK(revoked_through_epoch>=0),
 UNIQUE(user_id,revoked_through_epoch)
);
ALTER TABLE private.account_session_revocation_receipts OWNER TO profitpilot_context_owner;
REVOKE ALL ON private.account_session_revocation_receipts FROM PUBLIC,profitpilot_app;
-- Backfill the current watermark, without inventing earlier events.
INSERT INTO private.account_session_revocation_receipts(user_id,revoked_through_epoch)
 SELECT user_id,revoked_through_epoch FROM private.account_session_revocations;

CREATE FUNCTION private.guard_account_session_watermark() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Session revocation watermark must be retained' USING ERRCODE='55000'; END IF;
 IF NEW.user_id IS DISTINCT FROM OLD.user_id OR NEW.revoked_through_epoch<OLD.revoked_through_epoch THEN
  RAISE EXCEPTION 'Session revocation watermark cannot regress' USING ERRCODE='55000';
 END IF;
 RETURN NEW;
END
$fn$;
ALTER FUNCTION private.guard_account_session_watermark() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.guard_account_session_watermark() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER account_session_watermark_guard BEFORE UPDATE OR DELETE ON private.account_session_revocations
 FOR EACH ROW EXECUTE FUNCTION private.guard_account_session_watermark();

CREATE FUNCTION private.record_account_session_revocation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
BEGIN
 INSERT INTO private.account_session_revocation_receipts(user_id,revoked_through_epoch)
 VALUES(NEW.user_id,NEW.revoked_through_epoch) ON CONFLICT(user_id,revoked_through_epoch) DO NOTHING;
 RETURN NEW;
END
$fn$;
ALTER FUNCTION private.record_account_session_revocation() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.record_account_session_revocation() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER account_session_revocation_evidence AFTER INSERT OR UPDATE ON private.account_session_revocations
 FOR EACH ROW EXECUTE FUNCTION private.record_account_session_revocation();

CREATE FUNCTION private.guard_account_session_revocation_receipt() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $fn$
BEGIN
 RAISE EXCEPTION 'Session revocation receipts are immutable' USING ERRCODE='55000';
END
$fn$;
ALTER FUNCTION private.guard_account_session_revocation_receipt() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.guard_account_session_revocation_receipt() FROM PUBLIC,profitpilot_app;
CREATE TRIGGER account_session_revocation_receipt_guard BEFORE UPDATE OR DELETE OR TRUNCATE ON private.account_session_revocation_receipts
 FOR EACH STATEMENT EXECUTE FUNCTION private.guard_account_session_revocation_receipt();

ALTER FUNCTION private.privacy_restore_state() RENAME TO privacy_restore_state_before_session_revocation;
CREATE FUNCTION private.privacy_restore_state() RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,public,private AS $fn$
 SELECT jsonb_build_object(
  'markers',s.state->'markers'||COALESCE((
   SELECT jsonb_agg(jsonb_build_object('kind','account_session_revocation','id',r.id,'userId',r.user_id,
    'at',r.revoked_through_epoch::text) ORDER BY r.id)
   FROM private.account_session_revocation_receipts r
  ),'[]'::jsonb),
  'violations',s.state->'violations'||COALESCE((
   SELECT jsonb_agg(jsonb_build_object('kind',v.kind,'id',v.id) ORDER BY v.kind,v.id)
   FROM (
    SELECT 'session_revocation_watermark_mismatch'::text AS kind,COALESCE(w.user_id,r.user_id) AS id
    FROM private.account_session_revocations w
    FULL JOIN (SELECT user_id,max(revoked_through_epoch) AS max_epoch FROM private.account_session_revocation_receipts GROUP BY user_id) r
     ON w.user_id=r.user_id
    WHERE w.revoked_through_epoch IS DISTINCT FROM r.max_epoch
    UNION ALL
    SELECT 'revoked_session_reinstated',w.user_id
    FROM private.account_session_revocations w JOIN public.users u ON u.id=w.user_id
    WHERE EXISTS(SELECT 1 FROM private.auth_sessions a WHERE a.subject=u.auth_subject
     AND a.revoked_at IS NULL AND a.issued_at<=to_timestamp(w.revoked_through_epoch))
   ) v
  ),'[]'::jsonb))
 FROM (SELECT private.privacy_restore_state_before_session_revocation() AS state) s
$fn$;
ALTER FUNCTION private.privacy_restore_state() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.privacy_restore_state(),private.privacy_restore_state_before_session_revocation() FROM PUBLIC,profitpilot_app;
COMMIT;
