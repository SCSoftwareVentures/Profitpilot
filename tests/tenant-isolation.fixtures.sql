-- Two isolated, synthetic tenants with one linked row in every tenant-owned table.
-- Used only by ephemeral CI; all values are fictional.
BEGIN;
INSERT INTO tenants(id,legal_name) VALUES
 ('33333333-3333-4333-8333-333333333333','Isolation fixture tenant C'),
 ('44444444-4444-4444-8444-444444444444','Isolation fixture tenant D');
INSERT INTO users(id,auth_subject,email,status) VALUES
 ('55555555-5555-4555-8555-555555555555','isolation-tenant-c','c@example.invalid','active'),
 ('66666666-6666-4666-8666-666666666666','isolation-tenant-d','d@example.invalid','active'),
 ('77777777-7777-4777-8777-777777777777','isolation-reviewer-c','reviewer-c@example.invalid','active');
INSERT INTO tenant_memberships(tenant_id,user_id,role,status) VALUES
 ('33333333-3333-4333-8333-333333333333','55555555-5555-4555-8555-555555555555','analyst','active'),
 ('33333333-3333-4333-8333-333333333333','77777777-7777-4777-8777-777777777777','reviewer','active'),
 ('44444444-4444-4444-8444-444444444444','66666666-6666-4666-8666-666666666666','analyst','active');

INSERT INTO businesses(id,tenant_id,name) VALUES
 ('88888888-8888-4888-8888-888888888888','33333333-3333-4333-8333-333333333333','Fixture C business'),
 ('99999999-9999-4999-8999-999999999999','44444444-4444-4444-8444-444444444444','Fixture D business');
INSERT INTO sites(id,tenant_id,business_id,name) VALUES
 ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','33333333-3333-4333-8333-333333333333','88888888-8888-4888-8888-888888888888','Fixture C site'),
 ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','44444444-4444-4444-8444-444444444444','99999999-9999-4999-8999-999999999999','Fixture D site');
INSERT INTO contracts(id,tenant_id,business_id,customer_name,status) VALUES
 ('cccccccc-cccc-4ccc-8ccc-cccccccccccc','33333333-3333-4333-8333-333333333333','88888888-8888-4888-8888-888888888888','Fixture C customer','active'),
 ('dddddddd-dddd-4ddd-8ddd-dddddddddddd','44444444-4444-4444-8444-444444444444','99999999-9999-4999-8999-999999999999','Fixture D customer','active');
INSERT INTO contract_versions(id,tenant_id,contract_id,version_no,effective_from,price,currency,billing_basis,approved_by,approved_at)
VALUES
 ('eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee','33333333-3333-4333-8333-333333333333','cccccccc-cccc-4ccc-8ccc-cccccccccccc',1,'2026-01-01',100,'AUD','monthly','55555555-5555-4555-8555-555555555555',now()),
 ('ffffffff-ffff-4fff-8fff-ffffffffffff','44444444-4444-4444-8444-444444444444','dddddddd-dddd-4ddd-8ddd-dddddddddddd',1,'2026-01-01',100,'AUD','monthly','66666666-6666-4666-8666-666666666666',now());

INSERT INTO import_batches(id,tenant_id,source_type,permission_ref,status,file_sha256,file_name,created_by)
VALUES
 ('12121212-1212-4212-8212-121212121212','33333333-3333-4333-8333-333333333333','customer_invoice','fixture permission C','registered',repeat('1',64),'fixture-c.csv','55555555-5555-4555-8555-555555555555'),
 ('13131313-1313-4313-8313-131313131313','44444444-4444-4444-8444-444444444444','customer_invoice','fixture permission D','registered',repeat('2',64),'fixture-d.csv','66666666-6666-4666-8666-666666666666'),
 ('16161616-1616-4616-8616-161616161616','33333333-3333-4333-8333-333333333333','payroll','fixture payroll permission C','registered',repeat('6',64),'payroll-c.csv','55555555-5555-4555-8555-555555555555'),
 ('17171717-1717-4717-8717-171717171717','44444444-4444-4444-8444-444444444444','payroll','fixture payroll permission D','registered',repeat('7',64),'payroll-d.csv','66666666-6666-4666-8666-666666666666');
INSERT INTO raw_import_rows(id,tenant_id,batch_id,row_number,payload) VALUES
 ('14141414-1414-4414-8414-141414141414','33333333-3333-4333-8333-333333333333','12121212-1212-4212-8212-121212121212',1,'{"invoice_id":"C-1"}'),
 ('15151515-1515-4515-8515-151515151515','44444444-4444-4444-8444-444444444444','13131313-1313-4313-8313-131313131313',1,'{"invoice_id":"D-1"}'),
 ('18181818-1818-4818-8818-181818181818','33333333-3333-4333-8333-333333333333','16161616-1616-4616-8616-161616161616',1,'{"source_row_key":"fixture-C-row","amount":"100.00","currency":"AUD"}'),
 ('19191919-1919-4919-8919-191919191919','44444444-4444-4444-8444-444444444444','17171717-1717-4717-8717-171717171717',1,'{"source_row_key":"fixture-D-row","amount":"100.00","currency":"AUD"}');
INSERT INTO mapping_decisions(tenant_id,raw_row_id,target_type,decision,confidence,method_version)
VALUES
 ('33333333-3333-4333-8333-333333333333','14141414-1414-4414-8414-141414141414','invoice_row','candidate','LOW','fixture-1'),
 ('44444444-4444-4444-8444-444444444444','15151515-1515-4515-8515-151515151515','invoice_row','candidate','LOW','fixture-1');
INSERT INTO payroll_pools(id,tenant_id,batch_id,period_start,period_end,total_amount,source_ref)
VALUES
 ('16161616-1616-4616-8616-161616161616','33333333-3333-4333-8333-333333333333','16161616-1616-4616-8616-161616161616','2026-01-01','2026-01-31',100,'fixture-C-payroll'),
 ('17171717-1717-4717-8717-171717171717','44444444-4444-4444-8444-444444444444','17171717-1717-4717-8717-171717171717','2026-01-01','2026-01-31',100,'fixture-D-payroll');
INSERT INTO allocation_runs(id,tenant_id,payroll_pool_id,method_version,status,residual_amount)
VALUES
 ('18181818-1818-4818-8818-181818181818','33333333-3333-4333-8333-333333333333','16161616-1616-4616-8616-161616161616','fixture-1','draft',100),
 ('19191919-1919-4919-8919-191919191919','44444444-4444-4444-8444-444444444444','17171717-1717-4717-8717-171717171717','fixture-1','draft',100);
INSERT INTO payroll_source_rows(id,tenant_id,payroll_pool_id,raw_import_row_id,source_row_key,row_sha256,amount,currency)
VALUES
 ('30303030-3030-4030-8030-303030303030','33333333-3333-4333-8333-333333333333','16161616-1616-4616-8616-161616161616','18181818-1818-4818-8818-181818181818','fixture-C-row',repeat('3',64),100,'AUD'),
 ('31313131-3131-4131-8131-313131313131','44444444-4444-4444-8444-444444444444','17171717-1717-4717-8717-171717171717','19191919-1919-4919-8919-191919191919','fixture-D-row',repeat('4',64),100,'AUD');
INSERT INTO allocation_lines(tenant_id,allocation_run_id,site_id,bucket_type,amount,source_ref,payroll_source_row_id)
VALUES
 ('33333333-3333-4333-8333-333333333333','18181818-1818-4818-8818-181818181818','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','direct',100,'fixture-C-line','30303030-3030-4030-8030-303030303030'),
 ('44444444-4444-4444-8444-444444444444','19191919-1919-4919-8919-191919191919','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','direct',100,'fixture-D-line','31313131-3131-4131-8131-313131313131');
INSERT INTO invoices(id,tenant_id,direction,invoice_number,invoice_date,total_amount,currency,tax_basis,source_ref)
VALUES
 ('20202020-2020-4020-8020-202020202020','33333333-3333-4333-8333-333333333333','customer','C-INV-1','2026-01-15',100,'AUD','no_gst','fixture-C-invoice'),
 ('21212121-2121-4121-8121-212121212121','44444444-4444-4444-8444-444444444444','customer','D-INV-1','2026-01-15',100,'AUD','no_gst','fixture-D-invoice');
INSERT INTO invoice_lines(id,tenant_id,invoice_id,line_number,description,amount,source_row_id)
VALUES
 ('22222222-2222-4222-8222-222222222222','33333333-3333-4333-8333-333333333333','20202020-2020-4020-8020-202020202020',1,'Fixture C line',100,'14141414-1414-4414-8414-141414141414'),
 ('23232323-2323-4323-8323-232323232323','44444444-4444-4444-8444-444444444444','21212121-2121-4121-8121-212121212121',1,'Fixture D line',100,'15151515-1515-4515-8515-151515151515');
INSERT INTO match_reviews(id,tenant_id,invoice_line_id,contract_id,site_id,confidence,decision)
VALUES
 ('24242424-2424-4424-8424-242424242424','33333333-3333-4333-8333-333333333333','22222222-2222-4222-8222-222222222222','cccccccc-cccc-4ccc-8ccc-cccccccccccc','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','MEDIUM','candidate'),
 ('25252525-2525-4525-8525-252525252525','44444444-4444-4444-8444-444444444444','23232323-2323-4323-8323-232323232323','dddddddd-dddd-4ddd-8ddd-dddddddddddd','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','MEDIUM','candidate');
INSERT INTO variations(id,tenant_id,contract_id,site_id,description,status)
VALUES
 ('26262626-2626-4626-8626-262626262626','33333333-3333-4333-8333-333333333333','cccccccc-cccc-4ccc-8ccc-cccccccccccc','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','Fixture C variation','observed'),
 ('27272727-2727-4727-8727-272727272727','44444444-4444-4444-8444-444444444444','dddddddd-dddd-4ddd-8ddd-dddddddddddd','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','Fixture D variation','observed');
INSERT INTO calculation_runs(id,tenant_id,contract_id,site_id,period_start,period_end,formula_version,inputs,outputs,completeness,created_by)
VALUES
 ('28282828-2828-4828-8828-282828282828','33333333-3333-4333-8333-333333333333','cccccccc-cccc-4ccc-8ccc-cccccccccccc','aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','2026-01-01','2026-01-31','fixture-1','{}','{}','incomplete','55555555-5555-4555-8555-555555555555'),
 ('29292929-2929-4929-8929-292929292929','44444444-4444-4444-8444-444444444444','dddddddd-dddd-4ddd-8ddd-dddddddddddd','bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','2026-01-01','2026-01-31','fixture-1','{}','{}','incomplete','66666666-6666-4666-8666-666666666666');
INSERT INTO audit_events(tenant_id,actor_user_id,action,object_type,object_id,reason)
VALUES
 ('33333333-3333-4333-8333-333333333333','55555555-5555-4555-8555-555555555555','fixture','fixture','28282828-2828-4828-8828-282828282828','synthetic isolation test'),
 ('44444444-4444-4444-8444-444444444444','66666666-6666-4666-8666-666666666666','fixture','fixture','29292929-2929-4929-8929-292929292929','synthetic isolation test');
COMMIT;
