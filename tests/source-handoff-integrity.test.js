import test from 'node:test';
import assert from 'node:assert/strict';
import {gzipSync,gunzipSync} from 'node:zlib';
import {verifyArchiveInventory,verifySbomInventory} from '../src/source-handoff-integrity.js';
import {syntheticSha as sha,syntheticTar,syntheticInventory,syntheticSbom,entry} from './fixtures/source-handoff-synthetic.js';

test('B10 matches every tar entry, Git commit metadata and lock dependency version',()=>{
 const a=verifyArchiveInventory(syntheticTar(),syntheticInventory(),sha);
 const b=verifySbomInventory(syntheticSbom(),syntheticInventory());
 assert.deepEqual(a,{sourceFileCount:1,sourceBytes:5,gitCommitMetadataMatched:true});
 assert.deepEqual(b,{matchedDependencyCount:1});
});
test('B10 refuses a valid gzip that has the wrong byte content or missing/extra files',()=>{
 assert.throws(()=>verifyArchiveInventory(syntheticTar({value:'world'}),syntheticInventory(),sha),/hash differs/);
 assert.throws(()=>verifyArchiveInventory(syntheticTar({name:'profitpilot/extra.txt'}),syntheticInventory(),sha),/extra archived file/);
 assert.throws(()=>verifyArchiveInventory(syntheticTar({append:[entry('profitpilot/test.txt','0',Buffer.from('hello'))]}),syntheticInventory(),sha),/duplicated or extra/);
});
test('B10 refuses forged archive Git commitment, traversal and symlink',()=>{
 assert.throws(()=>verifyArchiveInventory(syntheticTar({paxCommit:'b'.repeat(40)}),syntheticInventory(),sha),/commit metadata/);
 assert.throws(()=>verifyArchiveInventory(syntheticTar({name:'profitpilot/../test.txt'}),syntheticInventory(),sha),/unsafe tar path/);
 assert.throws(()=>verifyArchiveInventory(syntheticTar({type:'2',value:''}),syntheticInventory({value:''}),sha),/unreviewed tar type/);
});
test('B10 refuses malformed tar header, truncated compressed archive and tampered source manifest',()=>{
 const buf=gunzipSync(syntheticTar());buf[1024+1]=0; // corrupt second entry header checksum
 assert.throws(()=>verifyArchiveInventory(gzipSync(buf),syntheticInventory(),sha),/checksum/);
 const i=syntheticInventory();i.source.totalBytes=99;
 assert.throws(()=>verifyArchiveInventory(syntheticTar(),i,sha),/count or size mismatch/);
 assert.throws(()=>verifyArchiveInventory(syntheticTar().subarray(0,15),syntheticInventory(),sha),/compressed archive/);
});
test('B10 rejects SBOM count, version, path/name and duplicate drift against locked packages',()=>{
 const input=syntheticInventory();const c=syntheticSbom();
 c.components[0].version='2.0.0';
 assert.throws(()=>verifySbomInventory(c,input),/differs/);
 c.components[0].version='1.0.0';c.components[0].name='imposter';
 assert.throws(()=>verifySbomInventory(c,input),/package name/);
 c.components[0].name='example';c.components.push({...c.components[0]});
 assert.throws(()=>verifySbomInventory(c,input),/count/);
});
