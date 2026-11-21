import test from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {resolve} from "node:path";
import {fileURLToPath} from "node:url";
const dir=resolve(fileURLToPath(new URL("..",import.meta.url)));
const page=()=>readFileSync(resolve(dir,"demo/buyer-walkthrough.html"),"utf8");

test("B2 mobile screen has responsive viewport, touch targets and no external dependencies",()=>{
 const html=page();
 assert.match(html,/<meta name="viewport" content="width=device-width,initial-scale=1">/);
 assert.match(html,/@media\(max-width:780px\)/);
 assert.match(html,/min-height:44px/);
 assert.match(html,/-webkit-text-size-adjust:100%/);
 assert.match(html,/overflow-x:auto/);
 assert.match(html,/prefers-reduced-motion/);
 assert.match(html,/<meta http-equiv="Content-Security-Policy"[^>]*connect-src 'none'/);
 assert.doesNotMatch(html,/<script\b[^>]*\bsrc\s*=/i);
 assert.doesNotMatch(html,/<link\b[^>]*\bhref\s*=/i);
 assert.doesNotMatch(html,/https?:\/\//);
});
test("B2 guided steps and export fallback are accessible without a download",()=>{
 const html=page();
 assert.match(html,/<section class="tour" aria-labelledby="tour-title"/);
 assert.match(html,/<p class="tourstatus" id="tour-progress" aria-live="polite"/);
 assert.match(html,/Step 1 of 3/);
 assert.match(html,/Step 2 of 3/);
 assert.match(html,/Step 3 of 3/);
 assert.match(html,/id="tour-step"/);
 assert.match(html,/id="evidence-json" aria-label=/);
 assert.match(html,/<details class="evidence-preview">/);
 assert.match(html,/user-select:text/);
 assert.match(html,/<div class="tablebox"><table>/);
 assert.match(html,/<th scope="col">/);
 assert.match(html,/<p class="small" id="live-status" role="status" aria-live="polite"/);
 assert.doesNotMatch(html,/innerHTML\s*=/);
});
test("B2 source claims are synthetic, not an unverified mobile certification",()=>{
 const html=page();
 assert.match(html,/Fictional data/i);
 assert.match(html,/not a deployed product/i);
 assert.match(html,/cannot be relied upon/i);
 assert.match(html,/No real approval or persisted evidence/);
 assert.match(html,/No approval path in this demonstration/);
 assert.match(html,/No real reviewer identity/);
 assert.match(html,/What this demonstration does—and does not—prove/);
});
