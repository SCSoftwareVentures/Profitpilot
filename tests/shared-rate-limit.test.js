import test from "node:test";
import assert from "node:assert/strict";
import {sharedLimiter} from "../server/shared-rate-limit.js";
test("shared limiter rejects invalid configuration",()=>{
 for(const options of [{limit:0,scope:"global"},{limit:1,scope:""},{limit:1,scope:"global",windowMs:100}])assert.throws(()=>sharedLimiter(options));
});
test("shared limiter returns a middleware function",()=>assert.equal(typeof sharedLimiter({limit:60,scope:"write"}),"function"));
