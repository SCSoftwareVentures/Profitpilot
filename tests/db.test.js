import test from "node:test";
import assert from "node:assert/strict";
import {EventEmitter} from "node:events";
import {pool,withTenant} from "../server/db.js";

const tenant="11111111-1111-4111-8111-111111111111";
const subject="synthetic-analyst";
const contextStatement="SELECT set_config";

function useClient(t,query){
 const secret=process.env.TENANT_CONTEXT_HMAC_SECRET;
 const secretFile=process.env.TENANT_CONTEXT_HMAC_SECRET_FILE;
 process.env.TENANT_CONTEXT_HMAC_SECRET="a".repeat(64);
 delete process.env.TENANT_CONTEXT_HMAC_SECRET_FILE;
 t.after(()=>{
  if(secret===undefined)delete process.env.TENANT_CONTEXT_HMAC_SECRET;
  else process.env.TENANT_CONTEXT_HMAC_SECRET=secret;
  if(secretFile!==undefined)process.env.TENANT_CONTEXT_HMAC_SECRET_FILE=secretFile;
 });
 const client=new EventEmitter();
 const statements=[];
 client.query=async(sql,params)=>{
  statements.push(sql.startsWith(contextStatement)?contextStatement:sql);
  return query?.(sql,params)??{command:sql};
 };
 client.release=t.mock.fn();
 t.mock.method(pool,"connect",async()=>client);
 return {client,statements};
}

function assertReleased(client,discardError){
 assert.equal(client.listenerCount("error"),0);
 assert.equal(client.release.mock.callCount(),1);
 assert.deepEqual(client.release.mock.calls[0].arguments,[discardError]);
}

test("successful tenant transaction keeps signed context local and preserves repeatable read",async t=>{
 const {client,statements}=useClient(t,(sql,params)=>{
  if(sql.startsWith(contextStatement)){
   assert.equal([...sql.matchAll(/,true\)/g)].length,6);
   assert.deepEqual(params.slice(0,2),[tenant,subject]);
   assert.match(params[5],/^[a-f0-9]{64}$/);
  }
 });
 assert.equal(await withTenant(tenant,subject,c=>{
  assert.equal(c,client);
  return "result";
 },{repeatableRead:true}),"result");
 assert.deepEqual(statements,["BEGIN ISOLATION LEVEL REPEATABLE READ",contextStatement,"COMMIT"]);
 assertReleased(client);
});

test("ordinary transaction error rolls back and releases a reusable client",async t=>{
 const failure=Object.assign(new Error("constraint violation"),{code:"23505"});
 const {client,statements}=useClient(t);
 await assert.rejects(withTenant(tenant,subject,()=>{throw failure;}),error=>error===failure);
 assert.deepEqual(statements,["BEGIN",contextStatement,"ROLLBACK"]);
 assertReleased(client);
});

test("failed rollback discards the client and preserves the initiating error",async t=>{
 const failure=new Error("write failed");
 const rollbackFailure=new Error("connection closed during rollback");
 const {client,statements}=useClient(t,sql=>{if(sql==="ROLLBACK")throw rollbackFailure;});
 await assert.rejects(withTenant(tenant,subject,()=>{throw failure;}),error=>error===failure);
 assert.deepEqual(statements,["BEGIN",contextStatement,"ROLLBACK"]);
 assertReleased(client,rollbackFailure);
});

test("checked-out connection loss rejects the transaction and discards the client",async t=>{
 const failure=new Error("database disconnected");
 const {client,statements}=useClient(t);
 await assert.rejects(withTenant(tenant,subject,c=>{
  c.emit("error",failure);
  assert.equal(client.release.mock.callCount(),0);
 }),error=>error===failure);
 assert.deepEqual(statements,["BEGIN",contextStatement]);
 assertReleased(client,failure);
});

test("a lost COMMIT response is not retried or returned as success",async t=>{
 const failure=new Error("connection closed during commit");
 const {client,statements}=useClient(t,sql=>{
  if(sql==="COMMIT"||sql==="ROLLBACK")throw failure;
 });
 const transaction=t.mock.fn();
 await assert.rejects(withTenant(tenant,subject,transaction),error=>error===failure);
 assert.equal(transaction.mock.callCount(),1);
 assert.deepEqual(statements,["BEGIN",contextStatement,"COMMIT","ROLLBACK"]);
 assertReleased(client,failure);
});

test("a COMMIT response reporting ROLLBACK is rejected",async t=>{
 const {client,statements}=useClient(t,sql=>sql==="COMMIT"?{command:"ROLLBACK"}:undefined);
 await assert.rejects(withTenant(tenant,subject,()=>42),/Tenant transaction did not commit/);
 assert.deepEqual(statements,["BEGIN",contextStatement,"COMMIT","ROLLBACK"]);
 assertReleased(client);
});
