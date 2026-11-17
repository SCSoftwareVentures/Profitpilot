// Complete cleanup outside any completed transaction. Destroy uncertain connections.
export async function releaseCleanConnection(client,discard){
 if(!discard){
  try{await client.query("DISCARD ALL");}catch(error){discard=error;}
 }
 client.release(discard);
}
