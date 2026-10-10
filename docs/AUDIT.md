# FootprintX 78-point risk audit

Historical audit retained from the supplied project. For current implementation changes, actual test evidence and launch requirements, use RELEASE_REPORT.md and ACCEPTANCE.md. Historical deployment and integration claims below are not new verification.

**Scope.** The supplied v1 project (`footprintx-ui-updated`) was audited first. Every finding was then re-checked against the v2 implementation in this repository.

**Status values**

| Status | Meaning |
|---|---|
| **Confirmed defect → fixed** | Present in v1, fixed in v2, and the fix is verified by the listed test or check |
| **Potential risk** | Not a demonstrated bug, but a risk that remains or is only partly mitigated |
| **Already addressed** | v1 already handled it; kept or strengthened in v2 |
| **Not applicable** | Doesn't apply to this system |
| **Blocked** | Implemented but can't be verified here (missing credential, provider access or environment) |

**Totals (primary status per check, 78 checks):**

| Status | Count |
|---|---|
| Confirmed defect → fixed | 63 (7 of these were features missing from v1, e.g. the extension) |
| Already addressed | 12 |
| Potential risk | 3 (#47, #54, #70) |
| Not applicable | 0 |
| Blocked | 0 as a primary status |

**Live-verification blocks (secondary flag).** Checks #29, #34, #37, #50, #52 and #55 are fixed in code and tested with fixtures or stubs. Their *live* verification against Google, XposedOrNot, HIBP and SMTP is **blocked** in this environment. The Docker part of #70 is also blocked (no Docker daemon).

A further 10 residual risks that cut across checks are listed at the end.

## A. Account discovery

| # | Check | v1 finding | Status | v2 change and evidence |
|---|---|---|---|---|
| 1 | Coverage and limitations explained | The landing copy said "we do not find every account", but nothing about metadata limits | Confirmed defect → fixed | `PermissionExplainer` (scan limits, services that never email); Accounts intro; `/breaches` limitations. Verified in web E2E. |
| 2 | Weak evidence never creates a false positive | Any sender matching "subscription" or "your account" became an account | Confirmed defect → fixed | Evidence strength model in `services/discovery.js`; weak-only senders become "possible" (excluded from DASI); newsletters ignored; DMARC-failing senders downgraded. Tests: `unit.scoring` (weak, spoofed), `api.flow` (Zomato possible, PayPal and TechCrunch absent). |
| 3 | Deduplication | Upsert by service/domain per connection. Partly done, but with no unique constraint; the JSON store was race-prone. | Confirmed defect → fixed | Unique `(user, connection, service_key)`; evidence unique by HMAC message reference; Gmail-alias canonicalization for connections. Test: idempotent rescan. |
| 4 | Outdated evidence handled transparently | Dormant accounts were rated HIGH after 3 years of "subscription" mail | Confirmed defect → fixed | `DORMANT` is a low-confidence factor (6 points) labelled "inactivity not confirmed"; first/last evidence dates shown on every account. |
| 5 | Partial or failed scans preserve results | One failure failed the whole scan; per-message failures were only logged | Confirmed defect → fixed | Job states `partial`, `failed`, `cancelled`; per-source results; partial data persisted; retries. Tests: `api.gmail` (retry, partial, revoked, cancel). |

## B. Password and remediation

| # | Check | v1 finding | Status | v2 change and evidence |
|---|---|---|---|---|
| 6 | Password changes never assumed | `password_changed` action set a status but wasn't used in scoring; "Mark resolved" removed all risk | Confirmed defect → fixed | Remediation states; credit only for user-reported (×0.5) or verified (×0.2) changes made after the breach. Test: `unit.scoring` remediation. |
| 7 | User-reported vs verified distinct | A single "completed" checkbox | Confirmed defect → fixed | `user_reported` / `verification_pending` / `verified` / `unable_to_verify`; users cannot set `verified` (400). Test: `api.flow`. |
| 8 | Password reuse never guessed | Not guessed | Already addressed | Kept: no reuse inference anywhere; the UI lists reuse as unknown. |
| 9 | Unknown MFA isn't treated as on or off | Unknown MFA added risk points; "Available" was inferred from any MFA keyword | Confirmed defect → fixed | Tri-state MFA from the latest evidence or the user's report; unknown widens the upper bound only. Test: `unit.scoring`. |
| 10 | Account deletion not marked verified | "Delete account record" deleted FootprintX's record; no closure semantics | Confirmed defect → fixed | `closed_user_reported` vs `closed_evidence` (closure email); never "verified". Test: `api.flow` (Dropbox closed, user-reported). |
| 11 | Historical breach evidence kept after remediation | Breach details were overwritten on re-check | Confirmed defect → fixed | `breach_findings` is never deleted by remediation; the factor stays visible. Test: `api.flow` ("historical breach record retained"). |

## C. DASI

| # | Check | v1 finding | Status | v2 change and evidence |
|---|---|---|---|---|
| 12 | Formula, thresholds, weights, direction documented | An uncapped sum (22/11/4 points) in code only | Confirmed defect → fixed | `docs/DASI.md`; methodology served by `/api/dasi` and shown in the UI. |
| 13 | Unknowns explicit | Unknown MFA scored as risk; no-scan state showed 0 | Confirmed defect → fixed | `score = null` when not assessed; upper bound; unknown lists. Tests: `unit.scoring`, `api.flow` (not assessed ≠ 0). |
| 14 | No double counting | Breach and HIGH and forgotten were added independently | Confirmed defect → fixed | One credential factor with a capped increment; recommendations aren't scored. Test: correlated-breach unit test. |
| 15 | Score changes explained | No history of reasons | Confirmed defect → fixed | Snapshots with `change_reasons`, trigger, delta. Tests: `explainChange` unit test; flow test. |
| 16 | Critical findings visible at a moderate aggregate | None | Confirmed defect → fixed | `critical_findings` and the dashboard's "Needs attention now". Unit test: moderate aggregate with a critical finding. |
| 17 | Freshness and confidence represented | None | Confirmed defect → fixed | Coverage, confidence and gaps; assessed-at time; model version. |

## D. Browser extension

| # | Check | v1 finding | Status | v2 change and evidence |
|---|---|---|---|---|
| 18 | False positives / negatives evaluated | No extension existed | Confirmed defect → fixed (feature missing in v1) | `npm run eval:detection` (0% false positives on the benign set, 89.7% look-alike recall, real-feed share 0.39%); FP/FN residual risk in the threat model. |
| 19 | Green = no known threat only | — | Confirmed defect → fixed (feature missing in v1) | `combineVerdict`; popup, Premium page and docs state it is not a guarantee. E2E green test. |
| 20 | Failures never reported as clean | — | Confirmed defect → fixed (feature missing in v1) | Offline, timeout and 5xx → `unavailable`; stale dataset → `unknown`. Unit and E2E (server stopped → grey). |
| 21 | Domain normalization and matching | v1 used naive multi-part-TLD handling | Confirmed defect → fixed | Public Suffix List (tldts) incl. private suffixes; punycode; exact-or-subdomain matching; protected-listing rejection. Tests: `shared/test/domain.test.js`, E2E parent-domain warning. |
| 22 | Minimal, documented permissions | — | Confirmed defect → fixed (feature missing in v1) | `storage`, `alarms`, `webNavigation`, `notifications` plus API host only; documented. Package test asserts it. |
| 23 | Privacy behaviour matches the policy | — | Confirmed defect → fixed (feature missing in v1) | Hash prefixes only; local cache ≤ 24 h; no content scripts. Unit test asserts no hostname leaks; E2E shows clean visits not synced. |
| 24 | Pending / unavailable / disabled / disconnected states | — | Confirmed defect → fixed (feature missing in v1) | `not_checked` reasons (NOT_LINKED, PREMIUM_REQUIRED, PREMIUM_EXPIRED, PROTECTION_PAUSED, LOCAL_PAGE); pending "…". Unit and E2E. |
| 25 | Synced events authenticated and validated | — | Confirmed defect → fixed (feature missing in v1) | Bearer extension session, Premium, per-session opt-in, zod schema, de-duplication, time window. `api.protection` test. |
| 26 | Entitlement / identity not spoofable locally | v1 Premium was UI-only ("coming soon") | Confirmed defect → fixed | Server 402 on lookups and sync; client flags rejected. Tests: `api.protection`, extension unit. |

## E. Security and backend

| # | Check | v1 finding | Status | v2 change and evidence |
|---|---|---|---|---|
| 27 | Authentication and sessions secure | Demo login with an empty body; JWT in localStorage (7 days, unrevocable) | Confirmed defect → fixed | bcrypt, lockout, HttpOnly opaque sessions + CSRF, revocation. `api.auth` tests. |
| 28 | Ownership on every resource | Mostly present, but `list()` loaded every tenant's rows into memory first | Confirmed defect → fixed | SQL `WHERE user_id` on every query; IDOR probe across 12 endpoints. |
| 29 | Tokens stored securely | AES-GCM, but with no AAD binding | Confirmed defect → fixed | Row-bound AAD, key ring, tokens never returned. Tests: crypto unit (AAD swap fails), `api.gmail` (ciphertext at rest). |
| 30 | Encryption and key management | Fallback key derived from `JWT_SECRET` or a hard-coded string | Confirmed defect → fixed | Required keys, trivial-key rejection, rotation support. Config and crypto unit tests. KMS: potential risk (see 30b below). |
| 31 | Logs free of secrets | `audit(null, 'oauth_callback_failed', {reason: err.message})` could store provider text; console logs unredacted | Confirmed defect → fixed | Redacting logger plus redacted audit details. Test: log-hygiene assertion. |
| 32 | Abuse controls and rate limits | Global 150/15 min; strict 20 | Already addressed | Strengthened: per-route limiters plus account lockout. `api.ratelimit` test. |
| 33 | Untrusted email content safe | Snippets processed; display names unsanitized | Confirmed defect → fixed | Headers only; bounded regexes; sanitized names; nothing rendered as HTML. |
| 34 | Deletion and token revocation | Disconnect deleted the row without revoking at Google; no account deletion | Confirmed defect → fixed | Revoke on disconnect and on deletion; cascades. Tests: `api.gmail` (revoke called), `api.security` (deletion). Live Google revocation: **blocked**. |
| 35 | Recovery and authorization boundaries tested | No recovery flow | Confirmed defect → fixed | Reset flow (single-use, revokes sessions). `api.auth` test. |
| 36 | Audit trail for sensitive actions | Present for some actions | Already addressed | Extended to all sensitive actions; IP stored as an HMAC; pseudonymised on deletion. |

**30b (potential risk):** keys come from environment variables; there is no KMS envelope encryption or re-encryption tool yet.

## F. Privacy and consent

| # | Check | v1 finding | Status | v2 change and evidence |
|---|---|---|---|---|
| 37 | Gmail scopes justified and minimal | `gmail.readonly` + `openid` + `userinfo.email` | Confirmed defect → fixed | `gmail.metadata` default; profile address from `users.getProfile`; scope verified on callback. `api.gmail` test (consent URL). |
| 38 | Only necessary data kept | No bodies kept, but snippets processed | Already addressed | Kept; subjects discarded; message IDs stored as HMAC. Flow test checks for subject absence. |
| 39 | Provider sharing disclosed | Consent UI existed for breach checks | Already addressed | Strengthened: consent bound to provider and policy version; Privacy tab lists all recipients. |
| 40 | Event sync opt-in and explained | — | Confirmed defect → fixed (feature missing in v1) | Off by default; explained in the extension options; enforced server-side. |
| 41 | Disconnect stops access | Row deleted; token not revoked; findings orphaned | Confirmed defect → fixed | Status `disconnected`; queued scans cancelled; token revoked and deleted; findings kept or deleted by choice. Tests: flow and gmail. |
| 42 | Privacy statements match behaviour | Settings claimed "OAuth tokens… encrypted" (true) but "Disconnecting removes its stored authorization" (it didn't revoke) | Confirmed defect → fixed | `docs/PRIVACY.md` and the in-app text match the code (retention constants served from code). |

## G. Free and Premium

| # | Check | v1 finding | Status | v2 change and evidence |
|---|---|---|---|---|
| 43 | Clear boundaries | Per-mailbox paywall | Confirmed defect → fixed | `docs/PLANS.md`; comparison table in the UI. |
| 44 | Server-side enforcement | No enforcement | Confirmed defect → fixed | `requirePremium()` on lookups and sync; history cap. `api.protection` tests. |
| 45 | Expiration, cancellation, downgrade | None | Confirmed defect → fixed | States, grace period, maintenance expiry, no data deletion. Test: expiry and cancellation. |
| 46 | Cross-device identity and entitlement | — | Confirmed defect → fixed | Entitlement attached to the user server-side; any linked browser sees it. |
| 47 | API costs and quotas considered | Not documented | Potential risk | Documented in PLANS.md and PROVIDERS.md (Gmail quota pacing, XposedOrNot 25/h). A production quota budget is still needed. |
| 48 | Configurable pricing, not shown as final | Hard-coded USD prices | Confirmed defect → fixed | Environment-driven price and currency; "proposed" label. Test: billing-disabled test. |

## H. External integrations

| # | Check | v1 finding | Status | v2 change and evidence |
|---|---|---|---|---|
| 49 | Breach / reputation / discovery separate | Breach results were written into account risk directly; no reputation layer | Confirmed defect → fixed | Separate tables, services and statuses (ARCHITECTURE.md). |
| 50 | Rate limits and retries respected | Throttling existed for breach providers | Already addressed | Kept; added Gmail retries with backoff and `Retry-After`; feed timeouts. |
| 51 | Credentials managed securely | Server-side only | Already addressed | Kept; config validation; nothing in client bundles (package test: no secrets or remote code). |
| 52 | Schema changes fail safely | XposedOrNot shape check existed | Already addressed | Strengthened: non-JSON and malformed responses → `unavailable`, including on a 200 response. Stubbed-fetch test. |
| 53 | Freshness and timestamps visible | Partly | Confirmed defect → fixed | `checked_at`, `first_seen` / `last_seen`, dataset age shown in the UI and the extension. |
| 54 | Conflicting provider results transparent | Single provider overwrote results | Potential risk | Findings keyed by provider and shown with their source. Two providers aren't queried simultaneously, so there's no reconciliation UI yet. |
| 55 | Unavailability never a clean result | Already handled for breach checks | Already addressed | Extended to reputation, the extension and exposure status (stays `unknown`). Tests. |
| — | **Live verification** of Google OAuth/Gmail, XposedOrNot, HIBP, SMTP | — | **Blocked** | No credentials or egress in this environment. Fixture-tested only. |

## I. User experience

| # | Check | v1 finding | Status | v2 change and evidence |
|---|---|---|---|---|
| 56 | Understandable language | Jargon-light, but "DASI" unexplained | Confirmed defect → fixed | Plain-language labels in one place (`labels.js`); methodology page. |
| 57 | Prioritized by severity and confidence | Sorted by HIGH/MEDIUM/LOW only | Confirmed defect → fixed | Priority = severity × confidence × impact; tested ordering. |
| 58 | Accurate official links | Fabricated defaults | Confirmed defect → fixed | Verified registry (sources recorded); no link when unverified. Unit test. |
| 59 | Warnings don't overstate | "Potentially exposed" counted alerts as exposure | Confirmed defect → fixed | "Doesn't prove…" wording on breaches, alerts and green results; amber is never "phishing". |
| 60 | Remediation history clear | None | Confirmed defect → fixed | Remediation timeline on the Recommendations and Activity pages. Web E2E. |
| 61 | Users can correct false positives | Only "delete record" (reappeared on rescan) | Confirmed defect → fixed | Dismiss (sticky across scans), confirm, restore, rename, MFA and closure reports. Flow test and web E2E. |
| 62 | Loading, empty, partial, offline, error states | Minimal | Confirmed defect → fixed | Shared components (`Loading`, `Empty`, `ErrorNote`, `Note`); partial-scan display; network errors. |
| 63 | Accessibility and keyboard | No focus styles; colour-only badges | Confirmed defect → fixed | Focus-visible, skip link, landmarks, labels, text with every colour, native dialog, focus moved on route change. E2E focus check. A formal WCAG audit is a potential risk (not performed). |

## J. Code, tests, deployment

| # | Check | v1 finding | Status | v2 change and evidence |
|---|---|---|---|---|
| 64 | No hidden mocks in production paths | Demo mode with random fabricated data could run without the operator noticing | Confirmed defect → fixed | Synthetic data only with `DEV_SYNTHETIC_DATA` (rejected in production) and labelled everywhere. Config test. |
| 65 | Unit tests for critical logic | Some (53) | Already addressed | Expanded: shared 14, scoring/discovery/crypto/config units. |
| 66 | Integration tests for workflows | Engine-level only | Confirmed defect → fixed | Full API flows on PGlite and PostgreSQL; web and extension E2E in Chromium. |
| 67 | Security and abuse tests | RBAC/crypto only | Confirmed defect → fixed | IDOR, CSRF, origin, rate limits, entitlement spoofing, log hygiene, deletion. |
| 68 | `.env.example` correct | Present; included placeholder SMTP credentials | Confirmed defect → fixed | Complete `.env.example` with no secret-looking placeholders; `npm run setup` generates keys. |
| 69 | Fixtures separated | Seed lived inside the engine | Confirmed defect → fixed | `backend/fixtures/`, `e2e/fixtures/` (labelled test-only), a separate synthetic table. |
| 70 | Deployment documented and functional | README only | Potential risk | DEPLOYMENT.md, Dockerfile and compose added, **but the Docker build wasn't run here (no daemon) → blocked for verification**. |
| 71 | Monitoring and safe logging | Console logs | Confirmed defect → fixed | Structured redacted logs, request IDs, readiness probe, documented alert signals. External monitoring stack: not included. |
| 72 | Migrations and backup guidance | None (schemaless) | Confirmed defect → fixed | SQL migrations, runner, readiness check; backup/restore guidance in DATABASE.md. Automated backups: operator responsibility (potential risk). |

## K. Product readiness

| # | Check | v1 finding | Status | v2 change and evidence |
|---|---|---|---|---|
| 73 | Prioritized by value and risk | — | Already addressed | Work followed the prompt's priority order; remaining work is listed in the README. |
| 74 | Scope and capabilities clear | Mixed claims | Confirmed defect → fixed | README capability table; landing page "can and can't see". |
| 75 | Detection quality evaluable | — | Confirmed defect → fixed | `eval:detection` with datasets and a gate. |
| 76 | Release criteria and acceptance tests | — | Confirmed defect → fixed | TESTING.md. |
| 77 | Unsupported promises removed | "Continuous monitoring", "Most flexible" plans | Confirmed defect → fixed | Copy reviewed; Premium limitations stated. |
| 78 | Status distinguishes implemented / tested / untested / blocked | — | Already addressed (this document, README) | — |

## Remaining potential risks (consolidated)

1. No MFA for FootprintX accounts themselves, and no breached-password check at registration.
2. Keys are held in environment variables (no KMS); the re-encryption tool for key rotation isn't built.
3. In-memory rate limiting doesn't share state across instances.
4. Registration reveals that an email exists, via a generic 409 (mitigated by rate limits).
5. Gmail metadata mode covers only the most recent N messages; `readonly` mode is broader but grants more.
6. The free XposedOrNot tier is unsuitable at scale; HIBP or paid XposedOrNot is needed.
7. Heuristics detect only a small share of real phishing on their own; protection depends on feed freshness.
8. No conflicting-provider reconciliation UI.
9. No formal WCAG audit, penetration test, or Firefox runtime test.
10. Deployment artefacts (Dockerfile, compose) are unverified here.

## Not applicable

- **v1 Mongo-specific split-brain fallback:** removed along with MongoDB.
- **v1 `/api/internal/security-demo`:** removed.
- **HIBP licensing checks for the default build:** HIBP is off unless an operator configures a key.
