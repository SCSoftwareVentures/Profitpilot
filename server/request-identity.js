// The request scope is set only by verified JWT middleware. It is not client input.
import {AsyncLocalStorage} from "node:async_hooks";
const scope=new AsyncLocalStorage();
export function withVerifiedRequestIdentity(identity,fn){
 if(!identity||typeof identity.subject!=="string"||typeof identity.jti!=="string")throw Error("Verified request identity required");
 return scope.run(Object.freeze({...identity,amr:Object.freeze([...(identity.amr||[])])}),fn);
}
export function currentRequestIdentity(){return scope.getStore();}
