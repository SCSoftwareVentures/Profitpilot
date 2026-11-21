# ProfitPilot B5 — Buyer demo mobile overflow correction

## Finding

A local Chromium automation check using a 390-pixel mobile viewport expanded the whole HTML page to **794 CSS pixels**. The contract table has a legitimate 740-pixel minimum width, but its grid ancestors used content-sized implicit minimums, allowing table width to propagate to the page. Click automation was consequently interrupted by overlapped/horizontally shifted content. This can harm actual users; it was not safe to call the B3 demo mobile-polished based on static checks alone.

## Correction

- Make the overall demo layout an explicit minmax(0,1fr) grid.
- Set min-width:0 for grid children/panels, use minmax(0,...) columns and bound the tablebox width.
- Preserve horizontal scrolling INSIDE the tablebox; do not shrink or hide financial columns or invent mobile data.
- Keep the standalone source and generated HTML in sync, with static regression guards in tests/buyer-layout-regression.test.js.

## Observed local browser test

The exact CSS patch was exercised in a headless **Chromium**, simulated touch mobile viewport, at 390, 430, 768 and 1024 CSS pixels. At all four widths, the browser viewport and document scroll width matched, the invoice and payroll buttons advanced the state to step 3, fictional contribution displayed AUD 13,700, the evidence JSON was accessible, reset restored step 1, and no browser JavaScript errors or network requests were seen.

**Important:** This was not an actual Apple iPhone, WebKit/Safari, VoiceOver or Voice Control test. Mobile browser emulation is partial assurance and must NOT close the manual IOS-01 to IOS-10 acceptance criteria. The CI static test guards CSS selectors; unless CI is explicitly extended, it does not reproduce the Chromium browser interaction test.

The product remains an offline fictional buyer demonstration, not a production service, certified mobile application, validated demand signal or financial authority. G0-G5 and external acquisition/legal/security review still apply.
