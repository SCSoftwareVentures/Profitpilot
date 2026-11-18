import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";

const source=readFileSync(new URL("../server/index.js",import.meta.url),"utf8");
const routes=[...source.matchAll(/app\.(get|post|put|patch|delete)\(\s*["'`]([^"'`]+)["'`]\s*,([^\n]*)/g)]
  .map(([,method,path,middleware])=>({method:method.toUpperCase(),path,middleware}));
const expected=new Map([
  ["GET /health","public-health"],
  ["GET /v1/me","authenticated"],
  ["GET /v1/tenants/:tenantId/contracts","member"],
  ["POST /v1/tenants/:tenantId/imports","role"],
  ["POST /v1/tenants/:tenantId/imports/:batchId/rows","role"],
  ["POST /v1/tenants/:tenantId/imports/:batchId/validate","role"],
  ["POST /v1/tenants/:tenantId/matches/:matchId/decision","role"],
  ["POST /v1/tenants/:tenantId/calculations","role"],
  ["GET /v1/tenants/:tenantId/calculations/:runId","member"],
  ["POST /v1/tenants/:tenantId/calculations/:runId/export","step-up"],
  ["POST /v1/tenants/:tenantId/imports/:batchId/file","step-up"],
  ["POST /v1/tenants/:tenantId/imports/:batchId/file/approve","step-up"],
  ["POST /v1/tenants/:tenantId/payroll/runs/:runId/submit","step-up"],
  ["GET /v1/tenants/:tenantId/payroll/proposals/:proposalId","step-up"],
  ["POST /v1/tenants/:tenantId/payroll/proposals/:proposalId/confirm","step-up"],
  ["GET /v1/tenants/:tenantId/privacy/account","step-up"],
  ["POST /v1/tenants/:tenantId/privacy/account/correct-email","step-up"],
  ["POST /v1/tenants/:tenantId/privacy/invoices/:batchId/disposal-preview","step-up"],
  ["POST /v1/tenants/:tenantId/privacy/invoices/:batchId/disposals/:orderId","step-up"],
  ["POST /v1/tenants/:tenantId/privacy/cases/:caseId","step-up"],
  ["GET /v1/tenants/:tenantId/privacy/cases/:caseId","step-up"],
  ["POST /v1/tenants/:tenantId/workspace/records/:recordId","step-up"],
  ["GET /v1/tenants/:tenantId/workspace/records-by-kind/:kind","step-up"],
  ["POST /v1/tenants/:tenantId/workspace/contracts/:contractId/versions/:orderId","step-up"],
  ["GET /v1/tenants/:tenantId/workspace/contracts/:contractId/versions/:orderId","step-up"],
  ["POST /v1/tenants/:tenantId/payroll/pools/:poolId/allocations/:runId","step-up"],
  ["GET /v1/tenants/:tenantId/payroll/pools/:poolId/allocations/:runId","step-up"],
  ["POST /v1/tenants/:tenantId/payroll/intakes/:batchId/orders/:orderId/preview","step-up"],
  ["GET /v1/tenants/:tenantId/payroll/intakes/:batchId/orders/:orderId","step-up"],
  ["POST /v1/tenants/:tenantId/payroll/intakes/:batchId/orders/:orderId","step-up"],
  ["GET /v1/tenants/:tenantId/privacy/cases/:caseId/deliveries/:orderId/dispatch","step-up"],
  ["POST /v1/tenants/:tenantId/privacy/cases/:caseId/deliveries/:orderId/dispatch","step-up"],
  ["POST /v1/tenants/:tenantId/privacy/cases/:caseId/deliveries/:orderId/receipts/:reviewId/preview","step-up"],
  ["GET /v1/tenants/:tenantId/privacy/cases/:caseId/deliveries/:orderId/receipts/:reviewId","step-up"],
  ["POST /v1/tenants/:tenantId/privacy/cases/:caseId/deliveries/:orderId/receipts/:reviewId","step-up"],
  ["POST /v1/tenants/:tenantId/privacy/cases/:caseId/deliveries/:orderId/preview","step-up"],
  ["GET /v1/tenants/:tenantId/privacy/cases/:caseId/deliveries/:orderId","step-up"],
  ["POST /v1/tenants/:tenantId/privacy/cases/:caseId/deliveries/:orderId","step-up"],
  ["POST /v1/tenants/:tenantId/payroll/runs/:runId/correction-preview","step-up"],
  ["GET /v1/tenants/:tenantId/payroll/corrections/:orderId","step-up"],
  ["POST /v1/tenants/:tenantId/payroll/corrections/:orderId","step-up"]
]);

test("every registered API endpoint has an explicit reviewed authorization classification",()=>{
  assert.ok(source.includes('app.use("/v1",authRequired())'),
    "all /v1 routes must remain behind the authentication middleware");
  assert.ok(source.includes('app.use("/v1",sessionRequired(checkIdentitySession))'),"all authenticated routes must check active session state");
  assert.ok(source.indexOf('app.use("/v1",sessionRequired(checkIdentitySession))')<source.indexOf('app.use("/v1",express.json({limit:"100kb",inflate:false}))'),"authenticate and authorize sessions before parsing request bodies");
  assert.equal(routes.length,expected.size,"route inventory changed: review and classify every new endpoint");
  for(const route of routes){
    const key=`${route.method} ${route.path}`;
    assert.ok(expected.has(key),`unreviewed endpoint: ${key}`);
    const classification=expected.get(key);
    if(classification==="member"||classification==="role"||classification==="step-up")
      assert.match(route.middleware,/\bmembership\b/,`missing tenant membership middleware: ${key}`);
    if(classification==="role"||classification==="step-up")
      assert.match(route.middleware,/\brequireRole\s*\(/,`missing role middleware: ${key}`);
    if(classification==="step-up")assert.match(route.middleware,/\brequireRecentMfa\b/,`missing MFA middleware: ${key}`);
    if(route.path.startsWith("/v1/tenants/"))
      assert.match(route.path,/^\/v1\/tenants\/:tenantId(?:\/|$)/,`tenant route must carry explicit tenant ID: ${key}`);
  }
  assert.ok(!routes.some(({path})=>path.startsWith("/v1")&&!expected.has(
    `${routes.find(r=>r.path===path)?.method} ${path}`)));
});

// Sensitive tenant responses must not be stored in browser or intermediary caches.
test("authenticated API responses carry explicit no-store protection",()=>{
  assert.match(source,/app\.use\(\(req,res,next\)\s*=>\s*\{res\.set\("Cache-Control","no-store"\)/);
  assert.ok(source.indexOf('res.set("Cache-Control","no-store")')<source.indexOf('app.use(process.env.NODE_ENV==="production"?sharedLimiter'),"privacy headers precede throttling");
  assert.ok(source.includes("app.use(createRequestAdmission(32))"),"all routes including health must share admission controls");
  assert.ok(source.indexOf("app.use(helmet())")<source.indexOf("app.use(createRequestAdmission(32))"),"admission rejections must receive security headers");
  assert.ok(source.indexOf('res.set("Cache-Control","no-store")')<source.indexOf('app.use("/v1",authRequired())'),"cache controls must precede authentication and tenant endpoints");
});

test("tenant mutations have a separate bounded rate limiter",()=>{
  assert.match(source,/const mutationLimiter=process\.env\.NODE_ENV==="production"\?sharedLimiter\(\{windowMs:60_000,limit:60,scope:"write"\}\):rateLimit\(\{windowMs:60_000,limit:60,/);
  assert.match(source,/sharedLimiter\(\{windowMs:60_000,limit:100,scope:"global"\}\)/);
  assert.match(source,/app\.use\("\/v1\/tenants\/:tenantId",\(req,res,next\)=>req\.method==="POST"\?mutationLimiter\(req,res,next\):next\(\)\)/);
  assert.ok(source.indexOf('const mutationLimiter=')<source.indexOf('app.post("/v1/tenants/:tenantId/imports"'),"write limiter must be installed before tenant write routes");
});
