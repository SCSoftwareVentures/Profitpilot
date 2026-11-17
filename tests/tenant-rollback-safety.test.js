import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";

// Structural regression: rollback failure must discard the connection rather
// than return a potentially contaminated tenant session to the pool.
test("tenant transaction rollback failure discards the database client",()=>{
 const source=readFileSync(new URL("../server/db.js",import.meta.url),"utf8");
 assert.match(source,/catch\(rollbackError\)\s*\{[\s\S]*?client\.release\(rollbackError\)/);
 assert.match(source,/finally\s*\{if\(!discarded\)client\.release\(\);\}/);
 assert.match(source,/new AggregateError\(\[error,rollbackError\]/);
});
