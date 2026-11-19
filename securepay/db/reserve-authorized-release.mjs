/** Transaction wrapper: caller provides an authenticated tenant-scoped pg pool.
 * The proof verifier must consume its proof with the SAME transaction client.
 * Never call the external payment provider inside this transaction.
 */
import {reserveRelease} from "./reserve-release.mjs";
import {consumeReleaseProof} from "./consume-release-proof.mjs";
export async function reserveAuthorizedRelease(pool,scope) {
 if(!pool?.connect)throw new Error("Database unavailable");
 const client=await pool.connect();
 let begun=false;
 try {
   await client.query("BEGIN");begun=true;
   const result=await reserveRelease(client,{
     ...scope,
     verifyAndConsume:({client:tx,...proofScope})=>consumeReleaseProof(tx,proofScope)
   });
   await client.query("COMMIT");begun=false;
   return result;
 } catch(error) {
   if(begun) {
     try {await client.query("ROLLBACK");}
     catch(rollbackError){throw new AggregateError([error,rollbackError],"Release rollback failed");}
   }
   throw error;
 } finally {client.release();}
}
