import test from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {gzipSync, gunzipSync} from 'node:zlib';
import {checkGitSourceArchive} from '../src/git-source-archive.js';

const archive = execFileSync('git', ['archive', '--format=tar.gz', '--prefix=profitpilot/', 'HEAD'],
  {cwd: new URL('../', import.meta.url), maxBuffer: 32 * 1024 * 1024});
function editReadme(replacement, updateChecksum = true) {
  const tar = Buffer.from(gunzipSync(archive));
  const name = Buffer.from('profitpilot/README.md');
  const index = tar.indexOf(name);
  assert.ok(index >= 0, 'test source has a root README');
  const block = index - index % 512;
  tar.fill(0, index, index + 100);
  tar.write(replacement, index, 'utf8');
  if (updateChecksum) {
    tar.fill(32, block + 148, block + 156);
    let sum = 0;
    for (let i = block; i < block + 512; i++) sum += tar[i];
    tar.write(sum.toString(8).padStart(6, '0') + '\0 ', block + 148, 'ascii');
  }
  return gzipSync(tar);
}
test('accepts structurally valid, gzip-compressed git archive', () => {
  assert.ok(checkGitSourceArchive(archive).sourceFiles >= 1);
});
test('rejects gzip data that is not a TAR archive', () => {
  assert.throws(() => checkGitSourceArchive(gzipSync(Buffer.from('not a TAR'))), /Invalid source archive/);
});
test('rejects damaged TAR header checksum', () => {
  assert.throws(() => checkGitSourceArchive(editReadme('profitpilot/README-change.md', false)), /checksum/);
});
test('rejects traversal path even with a valid recomputed TAR checksum', () => {
  assert.throws(() => checkGitSourceArchive(editReadme('profitpilot/../README.md')), /unsafe or duplicate/);
});
test('rejects source archive missing root README', () => {
  assert.throws(() => checkGitSourceArchive(editReadme('profitpilot/NOTICE.md')), /missing project source files/);
});
test('rejects truncated or invalid gzip archive', () => {
  assert.throws(() => checkGitSourceArchive(archive.subarray(0, 64)), /Invalid source archive/);
});
