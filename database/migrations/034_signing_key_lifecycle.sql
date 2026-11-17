-- Retain non-secret key tombstones and prevent key identifier/material reuse.
BEGIN;
ALTER TABLE private.tenant_context_keys ADD COLUMN key_fingerprint bytea;
ALTER TABLE private.tenant_context_keys ADD COLUMN registered_at timestamptz NOT NULL DEFAULT clock_timestamp();
ALTER TABLE private.tenant_context_keys ADD COLUMN revoked_at timestamptz;
UPDATE private.tenant_context_keys SET key_fingerprint=public.digest(secret,'sha256');
ALTER TABLE private.tenant_context_keys ALTER COLUMN key_fingerprint SET NOT NULL;
ALTER TABLE private.tenant_context_keys ADD CONSTRAINT tenant_key_material_unique UNIQUE(key_fingerprint);
ALTER TABLE private.tenant_context_keys ALTER COLUMN secret DROP NOT NULL;
UPDATE private.tenant_context_keys SET secret=NULL,revoked_at=clock_timestamp() WHERE NOT active;
ALTER TABLE private.tenant_context_keys ADD CONSTRAINT tenant_key_lifecycle_consistent CHECK(
 (active AND secret IS NOT NULL AND revoked_at IS NULL) OR
 (NOT active AND secret IS NULL AND revoked_at IS NOT NULL));
ALTER TABLE private.tenant_context_keys ADD CONSTRAINT tenant_key_fingerprint_size CHECK(octet_length(key_fingerprint)=32);
CREATE FUNCTION private.guard_tenant_context_key_lifecycle()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,private AS $fn$
BEGIN
 IF TG_OP='DELETE' THEN
  RAISE EXCEPTION 'Signing key identifiers must retain revocation tombstones' USING ERRCODE='55000';
 END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.key_id IS NULL OR NEW.key_id !~ '^[A-Za-z0-9._-]{1,128}$' OR NEW.active IS DISTINCT FROM true
   OR NEW.secret IS NULL OR octet_length(NEW.secret)<32 OR octet_length(NEW.secret)>128 THEN
   RAISE EXCEPTION 'Invalid new signing key' USING ERRCODE='22023';
  END IF;
  NEW.key_fingerprint:=public.digest(NEW.secret,'sha256');
  NEW.registered_at:=clock_timestamp();NEW.revoked_at:=NULL;
  RETURN NEW;
 END IF;
 IF NEW.key_id IS DISTINCT FROM OLD.key_id OR NEW.key_fingerprint IS DISTINCT FROM OLD.key_fingerprint
  OR NEW.registered_at IS DISTINCT FROM OLD.registered_at OR NEW.revoked_at IS DISTINCT FROM OLD.revoked_at
  OR NEW.secret IS DISTINCT FROM OLD.secret OR NOT OLD.active OR NEW.active IS DISTINCT FROM false THEN
  RAISE EXCEPTION 'Signing keys may only transition once from active to revoked' USING ERRCODE='55000';
 END IF;
 NEW.secret:=NULL;NEW.revoked_at:=clock_timestamp();
 RETURN NEW;
END
$fn$;
ALTER FUNCTION private.guard_tenant_context_key_lifecycle() OWNER TO profitpilot_context_owner;
REVOKE ALL ON FUNCTION private.guard_tenant_context_key_lifecycle() FROM PUBLIC;
CREATE TRIGGER tenant_key_lifecycle_guard BEFORE INSERT OR UPDATE OR DELETE ON private.tenant_context_keys
 FOR EACH ROW EXECUTE FUNCTION private.guard_tenant_context_key_lifecycle();
COMMIT;
