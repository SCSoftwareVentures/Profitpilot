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
  ["GET /v1/tenants/:tenantId/calculations/:runId","member"]
]);

test("every registered API endpoint has an explicit reviewed authorization classification",()=>{
  assert.ok(source.includes('app.use("/v1",authRequired())'),
    "all /v1 routes must remain behind the authentication middleware");
  assert.equal(routes.length,expected.size,"route inventory changed: review and classify every new endpoint");
  for(const route of routes){
    const key=`${route.method} ${route.path}`;
    assert.ok(expected.has(key),`unreviewed endpoint: ${key}`);
    const classification=expected.get(key);
    if(classification==="member"||classification==="role")
      assert.match(route.middleware,/\bmembership\b/,`missing tenant membership middleware: ${key}`);
    if(classification==="role")
      assert.match(route.middleware,/\brequireRole\s*\(/,`missing role middleware: ${key}`);
    if(route.path.startsWith("/v1/tenants/"))
      assert.match(route.path,/^\/v1\/tenants\/:tenantId(?:\/|$)/,`tenant route must carry explicit tenant ID: ${key}`);
  }
  assert.ok(!routes.some(({path})=>path.startsWith("/v1")&&!expected.has(
    `${routes.find(r=>r.path===path)?.method} ${path}`)));
});
