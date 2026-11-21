// Structural TAR/GZIP validation for draft source-acquisition evidence.
// This is not a substitute for verifying signed provenance and the Git commit.
import {gunzipSync} from 'node:zlib';

const BLOCK = 512;
const MAX_UNCOMPRESSED = 128 * 1024 * 1024;
const SOURCE_ROOT = 'profitpilot/';

function refuse(reason) {
  throw new Error('Invalid source archive: ' + reason);
}
function value(header, start, end) {
  return header.subarray(start, end).toString('utf8').split('\0', 1)[0];
}
function octal(header, start, end) {
  const raw = header.subarray(start, end).toString('ascii').replace(/\0.*$/s, '').trim();
  if (!/^[0-7]+$/.test(raw)) refuse('invalid TAR numeric field');
  const number = Number.parseInt(raw, 8);
  if (!Number.isSafeInteger(number)) refuse('unsafe TAR numeric field');
  return number;
}
export function checkGitSourceArchive(compressed) {
  let tar;
  try {
    tar = gunzipSync(compressed, {maxOutputLength: MAX_UNCOMPRESSED});
  } catch {
    refuse('invalid or oversized gzip content');
  }
  if (tar.length < BLOCK * 3 || tar.length % BLOCK !== 0) refuse('invalid TAR length');
  let offset = 0;
  let sourceFiles = 0;
  let hasReadme = false;
  let pax = false;
  const seen = new Set();
  while (offset + BLOCK <= tar.length) {
    const header = tar.subarray(offset, offset + BLOCK);
    if (header.every(byte => byte === 0)) {
      if (tar.length - offset < 2 * BLOCK || !tar.subarray(offset).every(byte => byte === 0))
        refuse('missing or corrupted TAR trailer');
      if (!sourceFiles || !hasReadme) refuse('missing project source files');
      return {sourceFiles};
    }
    if (value(header, 257, 263) !== 'ustar') refuse('unsupported TAR header');
    const expected = octal(header, 148, 156);
    let checksum = 0;
    for (let i = 0; i < BLOCK; i++) checksum += i >= 148 && i < 156 ? 32 : header[i];
    if (expected !== checksum) refuse('TAR header checksum mismatch');
    const basename = value(header, 0, 100);
    const prefix = value(header, 345, 500);
    const path = prefix ? prefix + '/' + basename : basename;
    const type = String.fromCharCode(header[156]);
    const length = octal(header, 124, 136);
    if (type === 'g' && path === 'pax_global_header' && !pax && length <= 65536) {
      pax = true; // Git commit metadata; no file extraction is performed.
    } else {
      if (!['\0', '0', '5', '2'].includes(type)) refuse('unsupported source entry type');
      if (!path.startsWith(SOURCE_ROOT) || path.includes('\\') || path.includes('//') ||
          path.split('/').includes('..') || seen.has(path))
        refuse('unsafe or duplicate TAR path');
      seen.add(path);
      if (type === '5' && length !== 0) refuse('directory contains data');
      if (type === '0' || type === '\0') {
        sourceFiles++;
        if (path === SOURCE_ROOT + 'README.md' && length > 0) hasReadme = true;
      }
    }
    const next = offset + BLOCK + Math.ceil(length / BLOCK) * BLOCK;
    if (next > tar.length) refuse('truncated TAR member');
    offset = next;
  }
  refuse('missing TAR trailer');
}
