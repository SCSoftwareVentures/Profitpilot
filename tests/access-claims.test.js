import test from "node:test";
import assert from "node:assert/strict";
import {validAccessClaims} from "../src/access-claims.js";
test("validate bounded access claims without allowing extended or ambiguous token lifetimes",()=>{
 const now=1800000000,p={iat:now-5,exp:now+295,sub:"synthetic-user",jti:"0123456789abcdef"};
 assert.equal(validAccessClaims(p,now),true);
 for(const patch of [{exp:now+901},{exp:now},{iat:now+6},{iat:now-901},{iat:now-0.5},{exp:now+0.5},{jti:"unsafe session ID"},{sub:" subject"},{sub:"a\nb"},{sub:"x".repeat(513)}])assert.equal(validAccessClaims({...p,...patch},now),false,JSON.stringify(patch));
});
