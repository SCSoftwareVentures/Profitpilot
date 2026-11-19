-- Read-only payer view; never expose internal receipts or private keys.
BEGIN;
CREATE FUNCTION securepay_private.payer_milestone_view(t uuid,m uuid)
 RETURNS TABLE(milestone_id uuid,amount_cents text,status text,funding_status text,is_final boolean,request_status text)
 LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT x.id,x.amount_cents::text,x.status,coalesce(f.status,'unfunded'),x.is_final,r.status
 FROM public.securepay_milestones x LEFT JOIN securepay_private.provider_funding f ON f.tenant_id=x.tenant_id AND f.milestone_id=x.id
 LEFT JOIN public.securepay_release_requests r ON r.tenant_id=x.tenant_id AND r.milestone_id=x.id
 WHERE x.tenant_id=t AND x.id=m AND x.payer_customer_id=securepay_private.current_payer(t)
$$;
ALTER FUNCTION securepay_private.payer_milestone_view(uuid,uuid) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.payer_milestone_view(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.payer_milestone_view(uuid,uuid) TO securepay_payer_runtime;
COMMIT;
