-- ProfitPilot migration 006: enforce tenant membership for actor/reviewer references.
-- Prevent an actor who belongs only to another tenant from being recorded as an approver or creator.
BEGIN;
ALTER TABLE contract_versions
 ADD CONSTRAINT contract_versions_approver_same_tenant_fk
 FOREIGN KEY (tenant_id,approved_by) REFERENCES tenant_memberships(tenant_id,user_id);
ALTER TABLE import_batches
 ADD CONSTRAINT import_batches_creator_same_tenant_fk
 FOREIGN KEY (tenant_id,created_by) REFERENCES tenant_memberships(tenant_id,user_id);
ALTER TABLE mapping_decisions
 ADD CONSTRAINT mapping_decisions_reviewer_same_tenant_fk
 FOREIGN KEY (tenant_id,reviewer_id) REFERENCES tenant_memberships(tenant_id,user_id);
ALTER TABLE allocation_runs
 ADD CONSTRAINT allocation_runs_reviewer_same_tenant_fk
 FOREIGN KEY (tenant_id,reviewer_id) REFERENCES tenant_memberships(tenant_id,user_id);
ALTER TABLE match_reviews
 ADD CONSTRAINT match_reviews_reviewer_same_tenant_fk
 FOREIGN KEY (tenant_id,reviewer_id) REFERENCES tenant_memberships(tenant_id,user_id);
ALTER TABLE variations
 ADD CONSTRAINT variations_approver_same_tenant_fk
 FOREIGN KEY (tenant_id,approved_by) REFERENCES tenant_memberships(tenant_id,user_id);
ALTER TABLE calculation_runs
 ADD CONSTRAINT calculation_runs_creator_same_tenant_fk
 FOREIGN KEY (tenant_id,created_by) REFERENCES tenant_memberships(tenant_id,user_id);
ALTER TABLE audit_events
 ADD CONSTRAINT audit_events_actor_same_tenant_fk
 FOREIGN KEY (tenant_id,actor_user_id) REFERENCES tenant_memberships(tenant_id,user_id);
COMMIT;
