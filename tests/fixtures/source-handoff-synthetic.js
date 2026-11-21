import {createHash} from 'node:crypto';
import {gzipSync} from 'node:zlib';
export const syntheticSha='a'.repeat(40);
const sha=syntheticSha;
const hash=b=>createHash('sha256').update(b).digest('hex');
function header(name,type,size){
 const b=Buffer.alloc(512);
 b.write(name,0,'utf8');
 b.write('0000644\0',100,'ascii');b.write('0000000\0',108,'ascii');b.write('0000000\0',116,'ascii');
 b.write(size.toString(8).padStart(11,'0')+'\0',124,'ascii');
 b.write('00000000000\0',136,'ascii');b[156]=type.charCodeAt(0);b.write('ustar\0',257,'ascii');
 b.fill(32,148,156);const sum=b.reduce((a,x)=>a+x,0);
 b.write(sum.toString(8).padStart(6,'0')+'\0 ',148,'ascii');
 return b;
}
export function entry(name,type,bytes=Buffer.alloc(0)){
 return Buffer.concat([header(name,type,bytes.length),bytes,Buffer.alloc((512-bytes.length%512)%512)]);
}
function pax(key,value){
 const v=key+'='+value+'\n';let n=v.length+3;
 for(;;){const x=String(n).length+1+v.length;if(x===n)break;n=x;}
 return Buffer.from(n+' '+v);
}
export function syntheticTar({name='profitpilot/test.txt',value='hello',type='0',paxCommit=sha,append=[]}={}){
 return gzipSync(Buffer.concat([
 entry('pax_global_header','g',pax('comment',paxCommit)),
 entry(name,type,Buffer.from(value)),...append,
 Buffer.alloc(1024)
 ]));
}
export function syntheticInventory({value='hello'}={}){
 const b=Buffer.from(value);
 return {source:{files:[{path:'test.txt',bytes:b.length,sha256:hash(b)}],fileCount:1,totalBytes:b.length},
  npm:{packages:[{path:'node_modules/example',version:'1.0.0'}],resolvedThirdPartyPackageCount:1}};
}
export function syntheticSbom(){return {bomFormat:'CycloneDX',components:[{
 name:'example',version:'1.0.0',properties:[{name:'cdx:npm:package:path',value:'node_modules/example'}]
}]};}
