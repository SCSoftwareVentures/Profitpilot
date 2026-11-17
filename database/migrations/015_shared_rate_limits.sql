-- Shared API rate-limit counters. No tenant data or raw IP addresses are stored.
CREATE TABLE IF NOT EXISTS public.api_rate_limits (
  bucket_key text NOT NULL,
  window_start bigint NOT NULL,
  request_count integer NOT NULL CHECK (request_count >= 0),
  PRIMARY KEY (bucket_key,window_start)
);
REVOKE ALL ON public.api_rate_limits FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE,DELETE ON public.api_rate_limits TO profitpilot_app;
-- Counter table intentionally has no tenant RLS: only hashed abuse-control keys.
-- A scheduled retention job must purge windows older than the retention horizon.
