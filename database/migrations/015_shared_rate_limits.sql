-- Shared fixed-minute rate limits. No raw IP addresses or tenant data.
BEGIN;
CREATE TABLE IF NOT EXISTS public.api_rate_limits (
  bucket_key text NOT NULL CHECK (bucket_key ~ '^(global|write):[a-f0-9]{64}$'),
  window_start bigint NOT NULL CHECK (window_start >= 0),
  request_count integer NOT NULL CHECK (request_count BETWEEN 1 AND 101),
  PRIMARY KEY (bucket_key,window_start)
);
CREATE INDEX IF NOT EXISTS api_rate_limits_expiry_idx ON public.api_rate_limits(window_start);
REVOKE ALL ON public.api_rate_limits FROM PUBLIC, profitpilot_app;

-- Fixed scope limits, database clock, saturating atomic update, no direct
-- runtime counter changes. All objects referenced with explicit namespaces.
CREATE OR REPLACE FUNCTION public.consume_api_rate_limit(p_bucket text)
RETURNS TABLE(total_hits integer, retry_after integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE
  epoch_seconds numeric := extract(epoch from clock_timestamp());
  minute_id bigint := floor(epoch_seconds / 60)::bigint;
  cap integer;
BEGIN
  IF p_bucket IS NULL OR p_bucket !~ '^(global|write):[a-f0-9]{64}$' THEN
    RAISE EXCEPTION 'Invalid rate-limit bucket' USING ERRCODE='22023';
  END IF;
  cap := CASE WHEN left(p_bucket,6)='write:' THEN 61 ELSE 101 END;
  RETURN QUERY
  INSERT INTO public.api_rate_limits AS counters(bucket_key,window_start,request_count)
  VALUES(p_bucket,minute_id,1)
  ON CONFLICT(bucket_key,window_start) DO UPDATE
  SET request_count=least(counters.request_count+1,cap)
  RETURNING counters.request_count, greatest(1,ceil((minute_id+1)*60-extract(epoch from clock_timestamp()))::integer);
END $$;
REVOKE ALL ON FUNCTION public.consume_api_rate_limit(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.consume_api_rate_limit(text) TO profitpilot_app;

-- Delete expired counters in bounded batches. No caller-supplied cutoff.
-- Keep two completed windows as a safety margin; never delete active counters.
CREATE OR REPLACE FUNCTION public.purge_api_rate_limits()
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE removed integer;
BEGIN
  WITH expired AS (
    SELECT bucket_key,window_start FROM public.api_rate_limits
    WHERE window_start < floor(extract(epoch from clock_timestamp())/60)::bigint-2
    ORDER BY window_start LIMIT 10000 FOR UPDATE SKIP LOCKED
  )
  DELETE FROM public.api_rate_limits AS counters USING expired
  WHERE counters.bucket_key=expired.bucket_key AND counters.window_start=expired.window_start;
  GET DIAGNOSTICS removed = ROW_COUNT;
  RETURN removed;
END $$;
REVOKE ALL ON FUNCTION public.purge_api_rate_limits() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.purge_api_rate_limits() TO profitpilot_app;
COMMIT;
