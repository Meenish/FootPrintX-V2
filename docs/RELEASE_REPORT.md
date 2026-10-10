# FootprintX engineering delivery report

Release review: 11 October 2026. Based on the supplied footprintx-v2.1 archive, CONTINUE-HERE.md and FOOTPRINTXmaster.pdf. Original Desktop files were preserved. Purchases remain disabled. Deployment uses Node.js and PostgreSQL directly; no Docker deployment was prepared.

## Result and launch status

The source, migration, web app and two browser builds are packaged with deployment scripts and operating instructions. Local database/API/browser behavior has been exercised. There is no public deployment, production database, configured live Google/SMTP service or browser-store publication. Complete the external launch checklist below before calling the service production-ready.

## Audit findings and preserved work

The existing implementation already had React/Vite, an Express API, PostgreSQL/PGlite, Gmail discovery, encrypted credentials, opaque sessions and CSRF, DASI, recommendations, remediation history, breach adapters, reputation feeds, extension protection, backend Premium enforcement and privacy controls. These were retained.

The major gaps were no independent extension account-awareness query, CSV-only security reports, no working contact delivery, automatic warning redirects, incomplete deployment verification and stale handoff claims. Windows/browser verification was needed. The existing official-link catalog, direct Node development launcher and immediate remediation scan behavior were preserved. No speculative provider deep links were added.

## Implemented and repaired

- Added user-scoped, domain-normalized extension account association with confirmed/possible/no-match states, source context, bounded cache and relink invalidation. Current website login is explicitly unavailable.
- Added six-sheet XLSX reports with actual user records, entitlement-limited security activity, no-data states and safe string cells. JSON privacy portability remains separate.
- Added authenticated, validated and rate-limited contact submission. Content is encrypted, outcomes persist, missing configuration is unavailable, and only SMTP acceptance produces a success message.
- Made optional email preferences off for new users, preserving existing choices. Notification sends are atomically claimed to prevent duplicate concurrent delivery. Only clearly pre-acceptance connection failures retry; ambiguous failures remain recorded.
- Made redirect-to-warning opt-in. Toolbar and notifications still warn; stored return targets contain only origins. Added SPA navigation handling and corrected privacy explanations.
- Production extension downloads validate embedded build origins. Both targets get build-info.json and ZIP packaging. Disabled billing cannot resume a development subscription in production.
- Added a production build command, environment template, preflight, smoke command, direct Node service/proxy templates, PostgreSQL test launcher and CI workflow.

## Architecture and data flows

The browser web app uses same-origin /api with HttpOnly sessions and CSRF. Express persists user data, scans and evidence in PostgreSQL. The worker consumes database jobs and schedules monitoring. Provider credentials remain server-side and encrypted. Gmail metadata is classified into evidence; subjects are not stored and message bodies are not fetched in metadata mode. Discovery distinguishes strong account evidence, weak possible matches, spoofed mail and excluded newsletters. Scans can be partial and disconnected sources are not rescanned.

Risk assessment consumes owned evidence, breach records and user/verified remediation. DASI model `dasi-2.0.0` is unchanged: 0–100, higher means more observed risk, with confidence, unknown upper bounds, capped correlated breach contributions and historical explanations. It is an internal index, not a universal standard. See DASI.md.

The extension uses a separate Bearer session. Reputation sends hash prefixes and compares full hashes locally. Account awareness separately sends the normalized hostname to search the user's inventory; it never establishes current login. Opt-in event sync sends warning domains/times only. Paths, queries, cookies, forms and passwords are not collected. Permissions are storage, alarms, webNavigation, notifications and the configured API host; no content scripts, cookies permission or all-sites host access.

Supported adapters are Gmail, Phishing.Database threat feeds, XposedOrNot/HIBP breach lookup and SMTP. Dataset freshness and provider errors are explicit; unavailable or unknown results never become green. Adapters do not imply configured or verified live services. Account discovery and threat feeds are incomplete by nature.

## Schema and API

Migration 004 creates user-owned encrypted contact_submissions with pending/accepted/failed outcomes and changes the default security-email preference for new users. Existing preferences are unchanged. Contact records expire after 90 days and cascade on user deletion. Privacy export includes their decrypted content only for the owner. Migrations 001–003 are retained.

New contracts: POST /api/extension/account-awareness (extension token + Premium), GET /api/reports/security.xlsx (web session), POST /api/contact (web session + CSRF), and contactConfigured in /api/config. See API.md for validation, response states and failure codes.

Important implementation files: backend/src/services/{awareness,reports,contact,notifications,extensionPackage}.js; backend/src/routes/{settings,protection}.js; backend/migrations/004_contact_and_consent.sql; extension/src/lib/awareness.js and background.js; frontend/src/pages/Contact.jsx, Accounts.jsx and Settings.jsx; scripts/{build-production,preflight,smoke,test-postgres}.mjs; deploy/; package-lock.json; backend/test/api.completion.test.js; e2e/.

## Verification evidence

The accompanying verification directory contains actual command logs. Unit/integration runs use isolated fixtures; browser screenshots visibly identify synthetic development data.

| Check | Recorded outcome |
|---|---|
| Shared/backend/extension automated suite | 14 + 100 + 15 tests passed, 129 total |
| Backend suite on PostgreSQL 16.15 | 100 passed, zero failures; fresh disposable schema, stopped after verification |
| Frontend and both extension builds | Built successfully |
| Production build command | Passed with a reserved .invalid origin and temporary local build keys; then extension packages rebuilt for localhost. No service was deployed |
| Clean lockfile verification | `npm ci --dry-run --ignore-scripts --no-audit` passed in a clean manifests-only directory |
| ESLint | Passed |
| Production dependency audit | Zero known vulnerabilities at audit time; ExcelJS nested uuid pinned to supported 11.x |
| Detection benchmark | 0/169 benign fixtures flagged; 35/39 crafted look-alikes detected; 6/6 matching cases; 5/5 protected listings rejected |
| Chromium browser workflows | 19 passed, zero failures: 11 extension scenarios plus 8 web scenarios |
| Responsive presentation | Desktop 1280px and mobile 390px inspected; mobile no-horizontal-overflow assertion passed |
| Firefox | Build/manifest checks only; actual Firefox execution remains pending |

The Windows sandbox denied native Node realpath calls and workspace symlinks. Verification used a separate installation with identical dependencies and a local fs compatibility shim outside the delivered source. PostgreSQL and clients had to run under the same launcher; initial separate-process connection attempts failed before the successful 100-test run. Extension profiles were moved under the workspace after temporary-profile failures. The popup test now waits for asynchronous entitlement rendering.

Browser file-save verification remains limited: Chromium canceled an XLSX save and also an unrelated plain-text download. The network body exposed to the browser-test protocol was empty. The final UI test verifies the request, successful response metadata and named download event; backend tests separately reopen the real XLSX bytes, check all six sheets, isolation, empty accounts and formula safety. Saving and opening the downloaded file in an unrestricted browser remains a launch check. These earlier failures are not counted as successful saves.

No live Gmail mailbox, SMTP inbox, paid breach API, production HTTPS service, backup restoration, browser-store publication or hosted CI execution is claimed. No real contact email was sent during tests.

## Configuration and external launch checklist

1. Choose domain and persistent Node hosting. Provision PostgreSQL and encrypted backups, keep encryption-key recovery separately protected, and rehearse a restore. Configure DNS/HTTPS and a running worker.
2. Set NODE_ENV, HOST/PORT, APP_URL, API_PUBLIC_URL, DATABASE_URL, ENCRYPTION_KEYS, INDEX_KEY, SERVE_FRONTEND and TRUST_PROXY. The production environment template lists values/placeholders without secrets. Configure validated database TLS for remote connections.
3. Provide GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET, enable Gmail API, register the exact callback and complete required Google consent/restricted-scope approvals. Test a real authorized mailbox and revocation.
4. Configure SMTP_HOST/PORT/SECURE/USER/PASSWORD/FROM and CONTACT_TO. Verify sender DNS and actual inbox delivery for contact, password reset and consented alerts.
5. Enable THREAT_FEEDS and sync a fresh dataset. Choose BREACH_PROVIDER and provide HIBP_API_KEY if using HIBP. Verify provider limits, terms, consent and live responses.
6. Keep BILLING_MODE=disabled and DEV_SYNTHETIC_DATA=false. No payment provider is configured. Premium protections remain backend-gated; production users cannot buy access in this release.
7. Build for the real origin, migrate after backup, pass preflight and run smoke checks. Exercise authenticated workflows, restart persistence and the Excel save. Configure uptime/error/worker/dataset alerts.
8. Test Firefox and intended branded Chrome/Edge versions, then complete extension signing/store review before store distribution. Current included packages target localhost and are not public deployment packages.

Security/operational limits: no external penetration test; multi-instance deployments need shared/edge rate limits; SMTP acceptance does not prove inbox receipt; stored contact messages in the operator's mailbox need separate retention controls; deletion cannot instantly rewrite backups. No known failing core authorization/scoring tests remain, but passing tests do not establish absence of all security defects.

## Commands and next steps

Local: `npm ci`, `npm run setup`, `npm run dev`. Production after environment setup: `npm run build:production`, `npm run migrate`, `npm run threat:sync -w backend`, `npm run preflight`, `npm start`. Complete commands, supervision, rollback, backup and incident procedures are in DEPLOY-NODE.md. The requirement-by-requirement status is in ACCEPTANCE.md.
