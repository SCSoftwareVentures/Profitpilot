// Ephemeral certificates for synthetic loopback tests only.
import {mkdtempSync,readFileSync,rmSync,chmodSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {execFileSync} from "node:child_process";
export function syntheticTlsFixture(){
 const dir=mkdtempSync(join(tmpdir(),"pp-private-courier-"));chmodSync(dir,0o700);
 try{
  const make=(name,usage)=>{
   const key=join(dir,name+".key"),cert=join(dir,name+".crt");
   execFileSync("openssl",["req","-x509","-newkey","rsa:2048","-nodes","-days","1","-subj","/CN="+name,"-addext","subjectAltName=IP:127.0.0.1","-addext","basicConstraints=critical,CA:TRUE","-addext","extendedKeyUsage="+usage,"-keyout",key,"-out",cert],{stdio:"ignore"});
   return {key:readFileSync(key),cert:readFileSync(cert)};
  };
  const server=make("synthetic-courier-server","serverAuth"),client=make("synthetic-courier-client","clientAuth"),other=make("synthetic-courier-other","clientAuth");
  return {serverKey:server.key,serverCert:server.cert,clientKey:client.key,clientCert:client.cert,otherKey:other.key,otherCert:other.cert};
 }finally{rmSync(dir,{recursive:true,force:true});}
}
