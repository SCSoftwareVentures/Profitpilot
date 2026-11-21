import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {fileURLToPath} from "node:url";
import {resolve} from "node:path";
const root=resolve(fileURLToPath(new URL("..",import.meta.url)));
const read=p=>readFileSync(resolve(root,p),"utf8");
test("B11 prototype scratch root excludes explicit OpenSSL APK installs and keeps protected libraries",()=>{
 const docker=read("Dockerfile");
 const packages=docker.match(/apk --root \/rootfs --initdb --no-scripts --no-cache add ([^\n]+?) &&/);
 assert.ok(packages,"expected one prototype APK root");
 assert.doesNotMatch(packages[1],/\blibcrypto3\b|\blibssl3\b/);
 assert.match(docker,/apk --root \/rootfs --no-scripts --no-cache add clamav-libs clamav-libunrar/);
 assert.match(docker,/FROM scratch AS api-runtime/);
 assert.match(docker,/USER 1000:1000/);
});
test("B11 runtime checks exercise AES/HMAC/TLS and preserve the exact high severity policy",()=>{
 const ci=read(".github/workflows/ci.yml");
 assert.match(ci,/unexpected crypto package/);
 assert.match(ci,/createCipheriv\("aes-256-gcm"/);
 assert.match(ci,/createHmac\("sha256"/);
 assert.match(ci,/tls\.createSecureContext\(\)/);
 assert.match(ci,/node scripts\/check-container-vulnerabilities\.mjs prototype-vulnerabilities\.json protected-vulnerabilities\.json/);
 const policy=read("scripts/check-container-vulnerabilities.mjs");
 assert.match(policy,/if\(!\["LOW","NEGLIGIBLE"\]\.includes\(severity\)\)/);
 assert.match(policy,/process\.exitCode=1/);
});
