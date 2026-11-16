-- ProfitPilot PostgreSQL logical schema scaffold.
-- Not production-deployed. Review migrations, RLS and threat model before use.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE tenants (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  legal_name text NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','closed')),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  auth_subject text NOT NULL UNIQUE,
  email text NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE tenant_memberships (
  tenant_id uuid NOT NULL REFERENCES tenants(id),
  user_id uuid NOT NULL REFERENCES users(id),
  role text NOT NULL CHECK (role IN ('owner','admin','analyst','reviewer','read_only')),
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  granted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id,user_id)
);
CREATE TABLE businesses (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id),
  name text NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(tenant_id,id)
);
CREATE TABLE sites (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id),
  business_id uuid NOT NULL, name text NOT NULL, status text NOT NULL DEFAULT 'active',
  FOREIGN KEY (tenant_id,business_id) REFERENCES businesses(tenant_id,id), UNIQUE(tenant_id,id)
);
CREATE TABLE contracts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id),
  business_id uuid NOT NULL, customer_name text NOT NULL, status text NOT NULL DEFAULT 'active',
  FOREIGN KEY (tenant_id,business_id) REFERENCES businesses(tenant_id,id), UNIQUE(tenant_id,id)
);
CREATE TABLE contract_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL,
  contract_id uuid NOT NULL, version_no integer NOT NULL, effective_from date NOT NULL,
  effective_to date, price numeric(14,2) NOT NULL CHECK(price>=0), currency char(3) NOT NULL DEFAULT 'AUD',
  billing_basis text NOT NULL, scope jsonb NOT NULL DEFAULT '{}'::jsonb, source_ref text,
  approved_by uuid REFERENCES users(id), approved_at timestamptz,
  FOREIGN KEY (tenant_id,contract_id) REFERENCES contracts(tenant_id,id),
  UNIQUE(tenant_id,contract_id,version_no), CHECK(effective_to IS NULL OR effective_to>=effective_from)
);
CREATE TABLE import_batches (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id),
  source_type text NOT NULL, source_period_start date, source_period_end date,
  permission_ref text NOT NULL, status text NOT NULL CHECK(status IN ('registered','validating','review','accepted','rejected','failed')),
  file_sha256 text NOT NULL, file_name text NOT NULL, created_by uuid NOT NULL REFERENCES users(id),
  created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(tenant_id,file_sha256), UNIQUE(tenant_id,id)
);
CREATE TABLE raw_import_rows (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL,
  batch_id uuid NOT NULL, row_number integer NOT NULL, payload jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id,batch_id) REFERENCES import_batches(tenant_id,id),
  UNIQUE(batch_id,row_number)
);
CREATE TABLE mapping_decisions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL,
  raw_row_id uuid NOT NULL REFERENCES raw_import_rows(id), target_type text NOT NULL,
  target_id uuid, decision text NOT NULL CHECK(decision IN ('candidate','accepted','rejected','held')),
  confidence text CHECK(confidence IN ('LOW','MEDIUM','HIGH')), method_version text NOT NULL,
  reviewer_id uuid REFERENCES users(id), reviewed_at timestamptz, reason text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE payroll_pools (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id),
  batch_id uuid NOT NULL, period_start date NOT NULL, period_end date NOT NULL,
  total_amount numeric(14,2) NOT NULL CHECK(total_amount>=0), currency char(3) NOT NULL DEFAULT 'AUD',
  source_ref text NOT NULL, FOREIGN KEY (tenant_id,batch_id) REFERENCES import_batches(tenant_id,id),
  CHECK(period_end>=period_start), UNIQUE(tenant_id,id)
);
CREATE TABLE allocation_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL,
  payroll_pool_id uuid NOT NULL, method_version text NOT NULL, status text NOT NULL CHECK(status IN ('draft','review','confirmed','rejected')),
  direct_amount numeric(14,2) NOT NULL DEFAULT 0, allocated_amount numeric(14,2) NOT NULL DEFAULT 0,
  non_site_amount numeric(14,2) NOT NULL DEFAULT 0, excluded_amount numeric(14,2) NOT NULL DEFAULT 0,
  residual_amount numeric(14,2) NOT NULL, reviewer_id uuid REFERENCES users(id), created_at timestamptz NOT NULL DEFAULT now(),
  FOREIGN KEY (tenant_id,payroll_pool_id) REFERENCES payroll_pools(tenant_id,id),
  CHECK(direct_amount>=0 AND allocated_amount>=0 AND non_site_amount>=0 AND excluded_amount>=0 AND residual_amount>=0)
);
CREATE TABLE invoices (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id),
  direction text NOT NULL CHECK(direction IN ('customer','supplier')), invoice_number text NOT NULL,
  invoice_date date NOT NULL, total_amount numeric(14,2) NOT NULL, currency char(3) NOT NULL DEFAULT 'AUD',
  tax_basis text NOT NULL CHECK(tax_basis IN ('gst_inclusive','gst_exclusive','no_gst','unknown')),
  source_ref text NOT NULL, UNIQUE(tenant_id,direction,invoice_number)
);
CREATE TABLE invoice_lines (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL,
  invoice_id uuid NOT NULL REFERENCES invoices(id), line_number integer NOT NULL,
  description text NOT NULL, amount numeric(14,2) NOT NULL, source_row_id uuid REFERENCES raw_import_rows(id),
  UNIQUE(invoice_id,line_number)
);
CREATE TABLE match_reviews (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL,
  invoice_line_id uuid NOT NULL REFERENCES invoice_lines(id), contract_id uuid REFERENCES contracts(id),
  site_id uuid REFERENCES sites(id), service_period_start date, service_period_end date,
  confidence text NOT NULL CHECK(confidence IN ('LOW','MEDIUM','HIGH','UNMATCHED')),
  decision text NOT NULL CHECK(decision IN ('candidate','confirmed','rejected','held')),
  evidence jsonb NOT NULL DEFAULT '{}'::jsonb, reviewer_id uuid REFERENCES users(id), reviewed_at timestamptz
);
CREATE TABLE variations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL,
  contract_id uuid NOT NULL REFERENCES contracts(id), site_id uuid REFERENCES sites(id),
  description text NOT NULL, status text NOT NULL CHECK(status IN ('observed','requested','candidate','approved','rejected','completed','invoiced','reconciled')),
  proposed_amount numeric(14,2), approved_amount numeric(14,2), evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
  approved_by uuid REFERENCES users(id), approved_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE calculation_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id),
  contract_id uuid NOT NULL REFERENCES contracts(id), site_id uuid NOT NULL REFERENCES sites(id),
  period_start date NOT NULL, period_end date NOT NULL, formula_version text NOT NULL,
  inputs jsonb NOT NULL, outputs jsonb NOT NULL, completeness text NOT NULL CHECK(completeness IN ('complete','incomplete')),
  created_at timestamptz NOT NULL DEFAULT now(), created_by uuid NOT NULL REFERENCES users(id),
  CHECK(period_end>=period_start)
);
CREATE TABLE audit_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id),
  actor_user_id uuid REFERENCES users(id), action text NOT NULL, object_type text NOT NULL,
  object_id uuid, reason text, correlation_id uuid, metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX idx_sites_tenant ON sites(tenant_id);
CREATE INDEX idx_contracts_tenant ON contracts(tenant_id);
CREATE INDEX idx_batches_tenant_created ON import_batches(tenant_id,created_at DESC);
CREATE INDEX idx_audit_tenant_created ON audit_events(tenant_id,created_at DESC);

-- Row-level security is deliberately not enabled here until the deployment's
-- trusted auth context and connection-pool strategy are defined. Every tenant
-- table must receive RLS policies and cross-tenant negative tests before launch.
