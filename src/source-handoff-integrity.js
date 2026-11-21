// B10: bounded, fail-closed verification of Git archive entries against the buyer inventory.
// Checks source integrity and SBOM consistency; cannot establish publisher identity or IP ownership.
import {gunzipSync} from 'node:zlib';
import {createHash} from 'node:crypto';

const LIMIT=70*1024*1024;
const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');
function fail(message){throw Error('Buyer source evidence rejected: '+message);}
function object(o){return o!==null&&typeof o==='object'&&!Array.isArray(o);}
function field(bytes){return bytes.toString('utf8').replace(/\0.*$/s,'');}
function octal(bytes,label){
 const value=field(bytes).trim();
 if(!/^[0-7]+$/.test(value))fail('invalid '+label+' octal header');
 const n=parseInt(value,8);
 if(!Number.isSafeInteger(n)||n<0)fail('invalid '+label+' size');
 return n;
}
function pathAllowed(name){
 if(!name||name.includes('\\')||name.includes('\0')||name.startsWith('/')||
  name.split('/').some(s=>s==='.'||s==='..'))fail('unsafe tar path');
}
function parsePax(data){
 let p=0; const fields=new Map();
 while(p<data.length){
  const space=data.indexOf(0x20,p);
  if(space<0||space-p>10)fail('invalid PAX record size');
  const len=Number(data.subarray(p,space).toString('ascii'));
  if(!Number.isSafeInteger(len)||len<=space-p+2||p+len>data.length)fail('invalid PAX record length');
  const record=data.subarray(space+1,p+len);
  if(record.at(-1)!==10)fail('invalid PAX record terminator');
  const txt=record.subarray(0,-1).toString('utf8'),eq=txt.indexOf('=');
  if(eq<1)fail('invalid PAX record');
  const key=txt.slice(0,eq),val=txt.slice(eq+1);
  if(fields.has(key))fail('duplicate PAX property');
  fields.set(key,val);
  p+=len;
 }
 return fields;
}
function headerName(h){
 const name=field(h.subarray(0,100)),prefix=field(h.subarray(345,500));
 return prefix?prefix+'/'+name:name;
}
function headerCheck(h){
 const actual=octal(h.subarray(148,156),'checksum');
 let calc=0;
 for(let i=0;i<512;i++)calc+=i>=148&&i<156?32:h[i];
 if(actual!==calc)fail('corrupt tar header checksum');
 if(!h.subarray(257,262).equals(Buffer.from('ustar')))fail('non-ustar archive not accepted');
}
export function verifyArchiveInventory(archive,inventory,sha){
 if(!Buffer.isBuffer(archive)||archive.length<128||archive.length>32*1024*1024)fail('invalid compressed archive');
 if(!/^[a-f0-9]{40}$/.test(sha||''))fail('exact Git commit required');
 if(!object(inventory)||!object(inventory.source)||!Array.isArray(inventory.source.files))fail('source inventory missing');
 const expected=new Map();let expectedTotal=0;
 for(const f of inventory.source.files){
  if(!object(f)||typeof f.path!=='string'||!f.path||f.path.startsWith('/')||f.path.includes('\\')||f.path.split('/').some(p=>!p||p==='.'||p==='..')||
   !Number.isSafeInteger(f.bytes)||f.bytes<0||f.bytes>5*1024*1024||
   typeof f.sha256!=='string'||!/^[a-f0-9]{64}$/.test(f.sha256)||expected.has(f.path))fail('invalid or duplicate inventory file');
  expected.set(f.path,f);expectedTotal+=f.bytes;
 }
 if(expected.size===0||expected.size>2000||expectedTotal>64*1024*1024||inventory.source.fileCount!==expected.size||inventory.source.totalBytes!==expectedTotal)
  fail('inventory source count or size mismatch');
 let data;
 try{data=gunzipSync(archive,{maxOutputLength:LIMIT});}
 catch{fail('gzip decompression invalid or exceeds safe limit');}
 if(data.length%512!==0||data.length<2048)fail('misaligned tar archive');
 let offset=0,global=false,zeroTail=false,files=0;const seen=new Set();
 while(offset+512<=data.length){
  const h=data.subarray(offset,offset+512);
  if(h.every(x=>x===0)){
   if(data.length-offset<1024||!data.subarray(offset).every(x=>x===0))fail('tar has unexpected trailing data');
   zeroTail=true;break;
  }
  headerCheck(h);
  const name=headerName(h),type=String.fromCharCode(h[156]||48),size=octal(h.subarray(124,136),'entry size');
  if(size>LIMIT||offset+512+Math.ceil(size/512)*512>data.length)fail('tar truncated or oversized entry');
  const bytes=data.subarray(offset+512,offset+512+size);
  if(type==='g'){
   if(global||files>0||name!=='pax_global_header')fail('unexpected global tar metadata');
   const fields=parsePax(bytes);
   if(fields.size!==1||fields.get('comment')!==sha)fail('tar commit metadata does not match inventory source commit');
   global=true;
  }else if(type==='5'){
   if(!global||size!==0||!name.startsWith('profitpilot/')||!name.endsWith('/'))fail('unexpected tar directory');
   pathAllowed(name);
  }else if(type==='0'){
   if(!global||!name.startsWith('profitpilot/'))fail('unreviewed tar file');
   pathAllowed(name);
   const rel=name.slice('profitpilot/'.length);
   if(!expected.has(rel)||seen.has(rel))fail('missing, duplicated or extra archived file: '+rel);
   const f=expected.get(rel);
   if(bytes.length!==f.bytes||sha256(bytes)!==f.sha256)fail('archived source file hash differs: '+rel);
   seen.add(rel);files++;
  }else fail('unreviewed tar type (symlink, hardlink or special device)');
  offset+=512+Math.ceil(size/512)*512;
 }
 if(!global||!zeroTail||files!==expected.size)fail('archived source file set incomplete');
 return {sourceFileCount:files,sourceBytes:expectedTotal,gitCommitMetadataMatched:true};
}
export function verifySbomInventory(sbom,inventory){
 if(!object(sbom)||sbom.bomFormat!=='CycloneDX'||!Array.isArray(sbom.components)||
  !object(inventory)||!object(inventory.npm)||!Array.isArray(inventory.npm.packages))fail('invalid SBOM/dependency inventory');
 const expected=new Map();
 for(const pkg of inventory.npm.packages){
  if(!object(pkg)||typeof pkg.path!=='string'||!pkg.path.startsWith('node_modules/')||
    typeof pkg.version!=='string'||expected.has(pkg.path))fail('invalid duplicate dependency inventory');
  expected.set(pkg.path,pkg.version);
 }
 if(expected.size===0||expected.size>2000||inventory.npm.resolvedThirdPartyPackageCount!==expected.size||
   sbom.components.length!==expected.size)fail('SBOM dependency count does not match lock inventory');
 const seen=new Set();
 for(const c of sbom.components){
  if(!object(c)||typeof c.name!=='string'||typeof c.version!=='string'||!Array.isArray(c.properties))fail('invalid SBOM component');
  const paths=c.properties.filter(p=>p?.name==='cdx:npm:package:path');
  if(paths.length!==1)fail('SBOM missing unique npm package path');
  const key=paths[0].value;
  if(typeof key!=='string'||!expected.has(key)||seen.has(key)||expected.get(key)!==c.version)
   fail('SBOM component differs from locked dependency inventory');
  if(key.split('node_modules/').at(-1)!==c.name)fail('SBOM package name differs from lock path');
  seen.add(key);
 }
 return {matchedDependencyCount:seen.size};
}
