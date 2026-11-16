# iPhone-First UX and Resilience Acceptance Protocol

**Status:** proposed acceptance protocol; not evidence of an implemented or tested native app.
**Target environment:** ChatGPT's owner uses an iPhone, but ProfitPilot itself must be tested in supported iPhone browsers and devices. Do not assume a desktop workflow or require customers to operate a computer for routine review.
**Initial product scope:** contract/site/service-period financial intelligence. This protocol does not authorise software build or customer-data collection.

## 1. Product principle

A business owner or authorised manager must be able to understand a material exception, inspect its evidence, make an authorised review decision and retrieve a useful report from a phone. Dense data preparation may remain a controlled back-office task during concierge validation, but the product must not make desktop-only access a hidden prerequisite for ordinary customer decisions.

Mobile-first means more than a responsive layout. It includes readable evidence, safe touch interactions, interrupted-session recovery, clear data status, and an explicit boundary between offline drafting and authoritative financial actions.

## 2. Supported journey candidates

Validate these journeys on an actual iPhone before selecting final navigation:

1. Sign in securely and select the correct business/tenant.
2. View contract/site/service-period summary and understand its data coverage.
3. Open a material exception and trace it to the supporting source records.
4. Review an invoice-match candidate, inspect evidence and confirm/reject only if the role permits.
5. Inspect labour allocation buckets and identify non-site/unallocated residuals.
6. Review a requested variation and distinguish candidate from approved/billable state.
7. Assign or update an action with owner and due date.
8. Export or share an authorised report using the iOS share sheet, with clear sensitivity warning.
9. Recover from a network interruption or app/browser suspension without duplicate actions or lost unsaved work.

Do not add first-release navigation for marketplace, payments, reviews, jobs or customer CRM solely to satisfy this protocol.

## 3. Layout and interaction acceptance

- Design first at a narrow iPhone viewport; progressively enhance for larger screens.
- No horizontal page scrolling for primary tasks. Wide evidence tables may use deliberate, labelled horizontal regions only where unavoidable.
- Keep the primary action visible without covering evidence or status.
- Use readable type, sufficient contrast and text labels for all financial states.
- Touch targets must be comfortably usable and meet WCAG 2.2 AA target-size requirements or documented exceptions.
- Do not rely on hover, right-click, drag-only interaction or tiny icon-only controls.
- Forms must preserve entered values when validation fails and clearly identify the field and correction.
- Use native date/time and file-selection affordances where appropriate; explain accepted file types and limits before selection.
- Confirm destructive or externally consequential actions with a clear summary; never use ambiguous button labels such as "OK".
- Respect Dynamic Type, VoiceOver, zoom and orientation changes. Avoid fixed-height panels that hide critical content.

## 4. Financial truth on a small screen

Every headline amount must expose, without requiring desktop access:
- currency and tax basis;
- contract, site and service period;
- calculation version and "as at" time;
- source coverage and completeness;
- direct-coded versus approved allocated cost;
- non-site and unallocated residual;
- estimate, candidate, confirmed and unknown states;
- source evidence and material assumptions.

Do not compress away caveats to make a dashboard look clean. If a number cannot be supported, show incomplete/unavailable with the reason rather than zero or a fabricated estimate.

## 5. Network and lifecycle test matrix

Run each task under stable Wi-Fi, mobile data, weak/intermittent connection, airplane-mode interruption and browser/app suspension where relevant.

| Scenario | Expected behaviour |
|---|---|
| Read a previously loaded report offline | Clearly label cached/stale data and its last successful sync time |
| Open an uncached source record offline | Explain it is unavailable; do not show a misleading empty record |
| Draft a non-authoritative note offline | Preserve locally only if secure storage and expiry are designed; visibly mark unsynced |
| Submit an approval/rejection offline | Do not represent it as accepted; require online server confirmation |
| Network drops during import registration | Show pending/unknown outcome and provide safe status reconciliation before retry |
| User taps submit repeatedly | Idempotency prevents duplicate financial or review actions |
| Browser is suspended mid-form | Restore only under a defined secure session policy; explain expired or unsaved state |
| Two reviewers change the same item | Detect conflict; show latest authoritative state and require explicit resolution |
| Session expires during review | Preserve no privileged action; reauthenticate and reload current server state |
| User switches tenant | Clear prior tenant's sensitive cached data and revalidate all server access |

Offline support is not a blanket requirement to permit financial writes. The safe default is read-only cached information with visible staleness; all authoritative decisions require server confirmation.

## 6. iOS browser/device test record

For every session record:
- iPhone model and iOS version;
- browser and version;
- viewport size, orientation and text-size setting;
- assistive technology used;
- network condition;
- test user role and synthetic tenant;
- task completion and time;
- errors, accidental taps and facilitator rescue;
- unsaved data or duplicate-action observations;
- screenshots only from synthetic fixtures;
- defect ID, severity, owner and retest result.

Test at least one current supported iPhone Safari version and one smaller supported viewport. Define the formal support matrix before any public release; do not imply universal iOS/browser compatibility from one device.

## 7. Accessibility checks

- VoiceOver reads page title, section hierarchy, field labels, status, chart summary and action result in a logical order.
- Status is expressed in text, not colour alone.
- Charts have concise text summaries and accessible underlying values.
- Focus remains visible and moves predictably after dialogs and errors.
- Dynamic Type does not clip critical amounts, controls or warnings.
- Authentication and session recovery work with password managers and accessible input methods.
- Error messages identify the problem and corrective action without exposing sensitive data.
- Test key workflows with keyboard/assistive input as well as touch.

## 8. Proposed usability acceptance thresholds

These are proposed test targets to confirm or revise during G4, not achieved results:
- At least 6 of 8 moderated participants complete each critical task without facilitator rescue.
- No participant mistakes an unapproved variation for billable value in the tested task.
- No participant interprets stale/offline data as current.
- No duplicate authoritative action is created in retry/interruption tests.
- All critical financial amounts can be traced to source evidence on the phone.
- No critical accessibility blocker remains in sign-in, evidence review or decision confirmation.
- Record median time-to-first-useful-insight and task-level completion times; do not average away a critical failure.

## 9. Security and privacy constraints

- No sensitive payroll or customer source data in browser local storage unless a reviewed threat model explicitly approves the design and controls.
- Do not store authentication tokens in script-readable persistent storage.
- Clear tenant-specific cache on logout, tenant switch, permission revocation and session expiry according to a tested policy.
- Exports use least-privilege authorization, clear recipient selection and appropriate warnings.
- Redact personal/employee details from push notifications, lock-screen previews, analytics and crash reports.
- No real pilot data until secure upload/storage, access controls, retention/deletion, incident handling and legal/privacy review are approved.

## 10. Release evidence

A mobile acceptance report must include device/browser matrix, participant roles, task denominators, raw completion counts, accessibility findings, network test results, open defects, retest evidence and reviewer sign-off. A responsive screenshot or successful page load is not proof of mobile usability or resilience.
