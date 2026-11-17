\getenv context_secret TENANT_CONTEXT_HMAC_SECRET
SELECT CASE WHEN :'context_secret' ~ '^[0-9a-fA-F]{64,}$' AND length(:'context_secret') % 2 = 0 THEN 1 ELSE 0 END AS valid_secret \gset
\if :valid_secret
INSERT INTO private.tenant_context_keys(key_id,secret,active)
VALUES ('primary',decode(:'context_secret','hex'),true)
ON CONFLICT(key_id) DO NOTHING;
SELECT CASE WHEN EXISTS(SELECT 1 FROM private.tenant_context_keys
 WHERE key_id='primary' AND active AND secret=decode(:'context_secret','hex'))
 THEN 1 ELSE 0 END AS key_matches \gset
\if :key_matches
\else
\echo 'Existing primary key is not the requested active key; use the reviewed rotation procedure'
\quit 3
\endif
\else
\echo 'TENANT_CONTEXT_HMAC_SECRET must be at least 32 bytes of hexadecimal data'
\quit 3
\endif
