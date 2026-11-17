import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";

// Keep a regression guard around the intentionally isolated synthetic test throttle.
const source=readFileSync(new URL("../server/index.js",import.meta.url),"utf8");
test("production rate cap stays 100/min and test allowance requires both strict gates",()=>{
 assert.match(source,/const globalRpmLimit=\(process\.env\.NODE_ENV==="test"&&Boolean\(process\.env\.TEST_ADMIN_DATABASE_URL\)\)\?500:100;/);
 assert.match(source,/rateLimit\(\{windowMs:60_000,limit:globalRpmLimit,standardHeaders:true,legacyHeaders:false\}\)/);
});
