-- Tenant-scoped, read-only reconciliation reporting. Sandbox figures only.
BEGIN;
CREATE ROLE securepay_reporting_runtime NOLOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS;
GRANT USAGE ON SCHEMA securepay_private TO securepay_reporting_runtime;
CREATE TABLE securepay_private.reporting_actors(
 tenant_id uuid NOT NULL,actor_id uuid NOT NULL,secret bytea NOT NULL CHECK(octet_length(secret)=32),
 active boolean NOT NULL DEFAULT true,PRIMARY KEY(tenant_id,actor_id)
);
ALTER TABLE securepay_private.reporting_actors OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.reporting_actors FROM PUBLIC,securepay_reporting_runtime,securepay_payer_runtime,securepay_provider_runtime;
CREATE TABLE securepay_private.reporting_access(
 report_id uuid PRIMARY KEY,tenant_id uuid NOT NULL,actor_id uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
ALTER TABLE securepay_private.reporting_access OWNER TO securepay_context_owner;
REVOKE ALL ON securepay_private.reporting_access FROM PUBLIC,securepay_reporting_runtime;
CREATE TRIGGER sp_chain_reporting_access AFTER INSERT ON securepay_private.reporting_access FOR EACH ROW EXECUTE FUNCTION securepay_private.capture_audit_chain();
CREATE INDEX sp_reporting_milestones ON public.securepay_milestones(tenant_id,id);
CREATE INDEX sp_reporting_journal ON securepay_private.financial_journal(tenant_id,milestone_id);
CREATE FUNCTION securepay_private.reconciliation_report(rid uuid,t uuid,a uuid,expires bigint,sig text) RETURNS jsonb
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE k bytea;n bigint;result jsonb;items jsonb;
BEGIN
 IF rid IS NULL OR t IS NULL OR a IS NULL OR expires IS NULL OR expires NOT BETWEEN floor(extract(epoch FROM clock_timestamp()))::bigint
 AND floor(extract(epoch FROM clock_timestamp()))::bigint+30 OR sig IS NULL OR sig !~ '^[a-f0-9]{64}$' THEN RETURN NULL; END IF;
 SELECT secret INTO k FROM securepay_private.reporting_actors WHERE tenant_id=t AND actor_id=a AND active;
 IF k IS NULL OR encode(public.hmac(convert_to(concat_ws(':','sp-report-v1',rid,t,a,expires),'UTF8'),k,'sha256'),'hex')<>sig THEN RETURN NULL; END IF;
 -- One consistent transaction snapshot is required; cap scope rather than truncate the report.
 IF current_setting('transaction_isolation')<>'repeatable read' THEN RAISE EXCEPTION 'Reporting requires repeatable read'; END IF;
 SELECT count(*) INTO n FROM (SELECT 1 FROM public.securepay_milestones WHERE tenant_id=t LIMIT 251) q;
 IF n>250 THEN RAISE EXCEPTION 'Report scope exceeds sandbox capacity' USING ERRCODE='54000'; END IF;
 INSERT INTO securepay_private.reporting_access(report_id,tenant_id,actor_id) VALUES(rid,t,a);
 SELECT coalesce(jsonb_agg(jsonb_build_object(
  'milestoneId',m.id,'status',m.status,'fundingStatus',coalesce(f.status,'unfunded'),
  'caseId',c.case_id,'caseStatus',c.status,'settlementId',st.settlement_id,
  'fundedCents',b.funded_cents::text,'payoutCents',b.payout_cents::text,
  'refundCents',b.refund_cents::text,'remainingCents',b.remaining_cents::text,
  'journalVerified',securepay_private.verify_financial_journal(t,m.id),
  'unresolvedIssues',((SELECT count(*) FROM securepay_private.provider_reconciliation x WHERE x.tenant_id=t AND x.milestone_id=m.id AND x.resolved_at IS NULL)
   +(SELECT count(*) FROM securepay_private.settlement_leg_conflicts x WHERE x.case_id=c.case_id AND x.resolved_at IS NULL))::text,
  'legs',(SELECT coalesce(jsonb_agg(jsonb_build_object('kind',l.kind,'status',l.status,'amountCents',l.amount_cents::text,'attempts',l.attempts) ORDER BY l.kind),'[]'::jsonb) FROM securepay_private.settlement_legs l WHERE l.settlement_id=st.settlement_id)
 ) ORDER BY m.id),'[]'::jsonb) INTO items
 FROM public.securepay_milestones m
 LEFT JOIN securepay_private.provider_funding f ON f.tenant_id=m.tenant_id AND f.milestone_id=m.id
 LEFT JOIN securepay_private.dispute_cases c ON c.tenant_id=m.tenant_id AND c.milestone_id=m.id
 LEFT JOIN securepay_private.dispute_settlements st ON st.case_id=c.case_id
 CROSS JOIN LATERAL securepay_private.financial_balance(t,m.id) b
 WHERE m.tenant_id=t;
 SELECT jsonb_build_object('schema','securepay-report-v1','mode','sandbox','moneyMoved',false,'tenantId',t,
 'reportId',rid,'generatedAt',clock_timestamp(),'milestones',items,
 'checkpoint',jsonb_build_object('tenantId',t,'last_seq',h.last_seq::text,'last_hash',h.last_hash)) INTO result FROM securepay_private.audit_checkpoint(t) h;
 RETURN result;
EXCEPTION WHEN unique_violation THEN RETURN NULL;
END $$;
ALTER FUNCTION securepay_private.reconciliation_report(uuid,uuid,uuid,bigint,text) OWNER TO securepay_context_owner;
REVOKE ALL ON FUNCTION securepay_private.reconciliation_report(uuid,uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION securepay_private.reconciliation_report(uuid,uuid,uuid,bigint,text) TO securepay_reporting_runtime;
COMMIT;
