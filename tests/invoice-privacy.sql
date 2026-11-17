-- Executed against synthetic CI data after migrations, never with real identifiers.
DO $$
DECLARE sample jsonb;
BEGIN
 FOR sample IN SELECT value FROM jsonb_array_elements(jsonb_build_array(
  '{"invoice_id":"INV-001","site":"Site A","date":"2026-01-01","amount":"10.00"}'::jsonb,
  '{"invoice_id":"INV-002","site":"","date":"not-a-date","amount":"-10.00"}'::jsonb,
  '{"contract_id":"33333333-3333-4333-8333-333333333333","currency":"AUD","tax_basis":"gst_exclusive"}'::jsonb,
  '{}'::jsonb
 )) LOOP
  IF NOT private.invoice_import_payload_safe(sample) THEN RAISE EXCEPTION 'Safe synthetic row rejected'; END IF;
 END LOOP;
 FOR sample IN SELECT value FROM jsonb_array_elements(jsonb_build_array(
  '{"unknown":"unsupported"}'::jsonb,
  '{"site":{"name":"nested"}}'::jsonb,
  '{"amount":100}'::jsonb,
  '{"site":"name@example.invalid"}'::jsonb,
  jsonb_build_object('invoice_id',repeat('9',9)),
  jsonb_build_object('site','999-999-999'),
  jsonb_build_object('site','９９９９９９９９９'),
  jsonb_build_object('site','payment card number'),
  jsonb_build_object('site',repeat('X',161)),
  jsonb_build_object('site','a'||chr(10)||'b'),
  jsonb_build_object('site','a'||chr(8203)||'b'),
  '{"amount":"9999999999999999"}'::jsonb,
  '{"tax_basis":"unsupported"}'::jsonb,
  '{"currency":"AUD-secret"}'::jsonb
 )) LOOP
  IF private.invoice_import_payload_safe(sample) THEN RAISE EXCEPTION 'Unsafe synthetic row accepted'; END IF;
 END LOOP;
 IF private.import_reference_safe('../fixture.csv',255,true) OR private.import_reference_safe('bank account',256,false) THEN
  RAISE EXCEPTION 'Unsafe metadata accepted';
 END IF;
END $$;
