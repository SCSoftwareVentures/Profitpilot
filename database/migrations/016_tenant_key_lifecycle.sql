-- Administrative key lifecycle evidence. Application role cannot see or modify it.
BEGIN;
CREATE TABLE private.tenant_key_rotation_events (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  key_id text NOT NULL,
  event_type text NOT NULL CHECK (event_type IN ('staged','revoked')),
  actor_name text NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON private.tenant_key_rotation_events FROM PUBLIC, profitpilot_app;

CREATE FUNCTION private.guard_tenant_key_lifecycle()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
  -- Never recycle a key ID, rewrite key material, or reactivate a revoked key.
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'Tenant signing key history cannot be deleted';
  ELSIF TG_OP='UPDATE' THEN
    IF NEW.key_id IS DISTINCT FROM OLD.key_id OR NEW.secret IS DISTINCT FROM OLD.secret
       OR (NOT OLD.active AND NEW.active) THEN
      RAISE EXCEPTION 'Tenant signing keys are immutable; stage a new key ID';
    END IF;
    IF OLD.active AND NOT NEW.active THEN
      INSERT INTO private.tenant_key_rotation_events(key_id,event_type,actor_name)
        VALUES(NEW.key_id,'revoked',session_user);
    END IF;
  ELSE
    IF NOT NEW.active OR NEW.key_id !~ '^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$' THEN
      RAISE EXCEPTION 'New tenant signing keys must have a valid unique ID and be active';
    END IF;
    INSERT INTO private.tenant_key_rotation_events(key_id,event_type,actor_name)
      VALUES(NEW.key_id,'staged',session_user);
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION private.guard_tenant_key_lifecycle() FROM PUBLIC, profitpilot_app;
CREATE TRIGGER tenant_key_lifecycle_guard
BEFORE INSERT OR UPDATE OR DELETE ON private.tenant_context_keys
FOR EACH ROW EXECUTE FUNCTION private.guard_tenant_key_lifecycle();
COMMIT;
