# FootprintX API contract (v2)

Base path: `/api`. Request and response bodies are JSON unless a download endpoint specifies otherwise. Times are ISO-8601 UTC strings. IDs are UUIDs.

## Release additions

- `POST /extension/account-awareness` (**ext**, Premium): strict body `{ "domain": "example.org" }`. Returns `state` (`account_known`, `possible_association`, `no_match`), evidence summaries in `matches`, and an independent `login` object whose state is `unavailable`. Only the authenticated user's non-dismissed inventory is searched. Invalid/local domains are rejected. This lookup does not persist visits.
- `GET /reports/security.xlsx` (**web**): returns a real XLSX attachment with Summary, Accounts, Risk Findings, Recommendations, DASI History and Security Activity sheets. User ownership and activity-history entitlement are enforced. No-data sheets explicitly say so. The JSON privacy export remains a separate data-portability feature.
- `POST /contact` (**web**, CSRF required, five/hour): strict `{ "name": "...", "email": "...", "message": "..." }`. Name is 1–100 characters, email at most 254, message 10–5000. Requires configured SMTP and CONTACT_TO. Success means SMTP acceptance, not inbox delivery. Missing configuration returns 503; rejected/unconfirmed delivery returns 502. Encrypted submissions track pending/accepted/failed status.
- `GET /config` additionally exposes `contactConfigured` so the UI can explain unavailable delivery.
- Production extension download endpoints reject missing or mismatched `build-info.json` origins with 503. Build both packages with `npm run build:production`.

Purchases remain disabled in the supplied production configuration. Client-supplied plans never grant Premium. See [RELEASE_REPORT.md](RELEASE_REPORT.md) for integration verification limits.

This is the contract between the web app (frontend), the browser extension and the backend. The integration tests in `backend/test/api.*.test.js` exercise every endpoint listed here. If you change one, change both.

## Conventions

### Authentication

| Client | Credential | Where it's accepted |
|---|---|---|
| Web app | `fx_session` HttpOnly cookie (named `__Host-fx_session` when served over HTTPS), issued by register/login | All endpoints marked **web** |
| Browser extension | `Authorization: Bearer <token>`, issued by `POST /extension/link` | Endpoints marked **ext** |

- A web session cookie never works as a Bearer token, and an extension token never works as a cookie. Using the wrong session kind returns `403 WRONG_SESSION_KIND`.
- **CSRF.** Every state-changing web request (`POST`, `PUT`, `PATCH`, `DELETE`) must send `X-CSRF-Token: <value of the fx_csrf cookie>`. Otherwise it fails with `403 CSRF_FAILED`.
- State-changing requests that carry a body must be `application/json`. Anything else gets `415`.
- Cross-origin state-changing requests from origins that aren't allowed get `403 ORIGIN_NOT_ALLOWED`.

### Errors

```json
{ "error": { "code": "VALIDATION_FAILED", "message": "The request is invalid.", "details": [{ "path": "email", "message": "Invalid email" }] } }
```

| Status | Typical codes |
|---|---|
| 400 | `VALIDATION_FAILED`, `INVALID_JSON`, `WEAK_PASSWORD`, `INVALID_DOMAIN`, `RESET_INVALID`, `LINK_CODE_INVALID` |
| 401 | `UNAUTHENTICATED`, `INVALID_CREDENTIALS` |
| 402 | `PREMIUM_REQUIRED`, `PREMIUM_EXPIRED` |
| 403 | `CSRF_FAILED`, `FORBIDDEN`, `CONSENT_REQUIRED`, `SYNC_NOT_ENABLED`, `ORIGIN_NOT_ALLOWED`, `WRONG_SESSION_KIND` |
| 404 | `NOT_FOUND` (also returned for other users' resources — existence is never revealed) |
| 409 | `CONFLICT`, `INVALID_TRANSITION`, `CONNECTION_INACTIVE`, `REGISTRATION_FAILED`, `DUPLICATE` |
| 413 | `PAYLOAD_TOO_LARGE` (bodies over 64 KB) |
| 429 | `RATE_LIMITED`, `ACCOUNT_LOCKED` |
| 503 | `GOOGLE_NOT_CONFIGURED`, `BREACH_PROVIDER_DISABLED`, `BILLING_NOT_CONFIGURED` |

### Lists

Collection endpoints return `{ "items": [...] }`.

---

## Meta (public)

| Method | Path | Notes |
|---|---|---|
| GET | `/health` | Liveness check: `{ status: "ok", version }`. Never touches the database. |
| GET | `/ready` | Readiness check: `200 { ready: true }`, or `503 { ready: false, reason: "database_unavailable" \| "migrations_pending" }`. |
| GET | `/config` | Public feature flags for the UI: `googleConfigured`, `gmailScopeMode`, `syntheticDataEnabled`, `breachProvider`, `billing` (the plan catalog), `emailDeliveryConfigured`, `dasiModelVersion`, `environment`. |

## Auth (`/auth`)

| Method | Path | Client | Body → Response |
|---|---|---|---|
| POST | `/auth/register` | public | `{ email, password, displayName? }` → `201 { user, csrfToken }` and sets cookies. The password needs 12–128 characters. A duplicate email returns a deliberately generic `409 REGISTRATION_FAILED`. |
| POST | `/auth/login` | public | `{ email, password }` → `{ user, csrfToken }`. A wrong password and an unknown email give the identical `401`. After 10 failures the account locks for 15 minutes (`429 ACCOUNT_LOCKED`). |
| POST | `/auth/logout` | web | `204`. Revokes the session server-side. |
| GET | `/auth/me` | web | `{ user, session, entitlement }` |
| POST | `/auth/password/change` | web | `{ currentPassword, newPassword }` → `{ ok, otherSessionsSignedOut: true }` |
| POST | `/auth/password/reset-request` | public | `{ email }` → always `202 { ok, message, emailDeliveryConfigured }` |
| POST | `/auth/password/reset` | public | `{ token, newPassword }` → `{ ok }`. The token is single-use, valid for 30 minutes, and revokes every existing session. |
| GET | `/auth/sessions` | web | `{ items: [{ id, kind, label, created_at, last_seen_at, expires_at, current }] }` |
| DELETE | `/auth/sessions/:id` | web | `204` |

## Mailbox connections

| Method | Path | Client | Notes |
|---|---|---|---|
| GET | `/connections` | web | `{ items: [{ id, provider, email_masked, scope_mode, status, is_synthetic, connected_at, last_scan_at, latestScan }], googleConfigured, scopeMode, syntheticDataEnabled }`. Tokens and encrypted emails are never returned. |
| POST | `/connections/google/start` | web | `{ url, scopeMode }`. The browser navigates to `url` (Google consent with PKCE and a single-use state). Returns `503 GOOGLE_NOT_CONFIGURED` if credentials are missing. |
| GET | `/connections/google/callback` | browser redirect | Always responds `303` to `APP_URL/settings?tab=connections&oauth=connected&connection=…&scan=…`, or `oauth=denied`, or `oauth=error&reason=OAUTH_STATE_INVALID\|OAUTH_USER_MISMATCH\|SCOPE_MISSING\|NO_REFRESH_TOKEN\|…`. |
| POST | `/connections/synthetic` | web (development only) | `201 { connectionId, scanJob, synthetic: true }`. Returns `404` unless `DEV_SYNTHETIC_DATA=true`. |
| POST | `/connections/:id/disconnect` | web | `{ deleteFindings: boolean }` → `{ revokeResult: "revoked"\|"already_invalid"\|"failed"\|"not_applicable", deletedFindings, dasi }` |
| DELETE | `/connections/:id` | web | Only for disconnected connections; deletes the connection and its findings. `204`. |
| POST | `/connections/:id/scan` | web | `202 { job, deduplicated }`. Returns the job already queued or running instead of starting a duplicate. `409` if the connection isn't active. |
| POST | `/connections/:id/breach-check` | web | `{ force?: boolean }` → `{ status: "ok", cached, provider, checkedAt, breachCount, matched, added }` or `{ status: "unavailable", provider, errorCode, message }`. `403 CONSENT_REQUIRED` without consent. |
| POST | `/connections/:id/synthetic-events` | web (development only) | `{ kind: "password_changed"\|"mfa_enabled"\|"security_alert"\|"signup", domain, serviceName? }`. Adds a labelled message to a synthetic mailbox, for example to demonstrate verification. |

## Scans

Scan job object: `{ id, connection_id, trigger, status, stage, progress: { messagesListed, messagesProcessed, messagesFailed, servicesSeen }, source_results: [{ source, status: "ok"|"degraded"|"failed", listed, fetched, failed, error? }], summary: { confirmed, possible, newAccounts, updatedAccounts }, error_code, error_message, attempts, created_at, started_at, finished_at }`

- `status` is one of `queued`, `running`, `partial`, `completed`, `failed`, `cancelled`.
- Progress numbers reflect real work done.

| Method | Path | Notes |
|---|---|---|
| GET | `/scans` | The 30 most recent scans (with `email_masked`). |
| GET | `/scans/:id` | Poll every ~1.5 s while the scan is `queued` or `running`. |
| POST | `/scans/:id/cancel` | A queued scan is cancelled immediately. A running scan stops at the next batch and keeps partial results. |

## Accounts (inventory)

Account object fields:

- Identity: `id, connection_id, connection_email, service_key, service_name, service_domain, category`
- Discovery: `status` (confirmed/possible/dismissed), `discovery_source`, `confidence`, `manually_added`, `user_corrected`, `dismissed_reason`, `first_observed_at`, `last_observed_at`, `last_checked_at`
- Security posture: `mfa_status` (enabled/disabled/unknown), `mfa_source`, `exposure_status` (confirmed_evidence/no_evidence_found/unknown), `account_state`
- Risk: `risk_score, risk_upper, risk_level, risk_factors { factors[], unknowns[], critical[], excluded, impact }, risk_model_version`
- `is_synthetic`

| Method | Path | Notes |
|---|---|---|
| GET | `/accounts?status=confirmed\|possible\|dismissed` | `{ items }` |
| POST | `/accounts` | Manual tracking: `{ serviceName?, domain?, identifier? }` → `201 { account, evidence, breaches, recommendations }` |
| GET | `/accounts/export.csv` | CSV with formula-injection protection. |
| GET | `/accounts/:id` | `{ account, evidence[], breaches[], recommendations[] }`. Evidence items: `{ kind, strength, source, sender_domain, sender_authenticated, observed_at }`. No subjects or message ids are included. |
| PATCH | `/accounts/:id` | Any of `{ action: "dismiss"\|"confirm"\|"restore", reason, serviceName, mfaStatus: "enabled"\|"disabled"\|"unknown", accountState: "closed"\|"open" }`. User-supplied MFA and closure values are stored as user-reported. Triggers a recalculation. |
| DELETE | `/accounts/:id` | Manual entries only (discovered accounts are dismissed instead). |

## Risk (DASI)

| Method | Path | Notes |
|---|---|---|
| GET | `/dasi` | `{ snapshot, methodology }`. `snapshot.score` is `null` when nothing has been assessed yet; it is never shown as 0. Snapshot fields: `model_version, score, upper_bound, level, confidence, coverage, contributors[], critical_findings[], trigger, previous_score, delta, change_reasons[], created_at`. |
| GET | `/dasi/history` | Up to 90 snapshots, newest first. |
| POST | `/dasi/recalculate` | Forces a recalculation (rate-limited). |

## Recommendations & remediation

Recommendation fields: `id, account_id, service_name, service_domain, action_type, severity, priority, title, explanation, why_it_matters, next_step, evidence[], official_url, official_url_kind ("settings_page"|"help_page"|"none"), expected_effect, status, applicable, verification_method, verification_evidence, reported_at, verified_at, verification_deadline, dismissed_reason, updated_at`

| Method | Path | Notes |
|---|---|---|
| GET | `/recommendations` | Ordered by status, then priority. |
| GET | `/recommendations/history` | Remediation events: `{ from_status, to_status, actor: "user"\|"system", note, evidence, created_at, title }` |
| PATCH | `/recommendations/:id` | `{ status: "recommended"\|"in_progress"\|"user_reported"\|"dismissed", note?, dismissedReason? }` → `{ recommendation, transition: { from, to }, dasi }`. Clients cannot set `verified` or `unable_to_verify`. If you report a verifiable action (password change or MFA) while a mailbox is connected, the status becomes `verification_pending`. |

## Alerts, activity, dashboard

| Method | Path | Notes |
|---|---|---|
| GET | `/alerts?status=` | `{ items: [{ id, kind, severity, title, body, account_id, domain, status, created_at }] }` |
| PATCH | `/alerts/:id` | `{ status: "read"\|"dismissed"\|"unread" }` |
| POST | `/alerts/read-all` | |
| GET | `/dashboard` | `{ dasi, accounts: { confirmed, possible, dismissed, definitions }, recommendations: { open, top[], awaitingVerification }, alerts: { unread, recent[] }, connections[], scans[], entitlement, extension: { linkedBrowsers, lastSeenAt }, websiteChecks[], syntheticData }` |
| GET | `/activity?days=` | `{ days, maxDays, plan, scans[], alerts[], remediation[], scoreChanges[], extensionEvents[], websiteChecks[] }`. Free plans are capped at 30 days, Premium at 365. |

## Breach intelligence

| Method | Path | Notes |
|---|---|---|
| GET | `/breaches` | `{ provider: { name, label, url, sends } \| null, consent: { …, current }, policyVersion, checks[], findings[], limitations[] }` |
| POST | `/breaches/consent` | `{ granted: boolean }`. Consent is bound to the provider and the policy version. |

## Website reputation

Statuses: `no_known_threat`, `suspicious`, `malicious`, `unknown`, `unavailable`.

| Method | Path | Client | Notes |
|---|---|---|---|
| POST | `/reputation/check` | web, ext | `{ domain }` (a host or URL; only the hostname is used) → `{ domain, displayDomain, registrableDomain, status, reasons[], explanation, dataset, checkedAt }` |
| GET | `/reputation/dataset` | web, ext | `{ usable, reason, version, updatedAt, ageHours, indicatorCount, sources[] }` |
| POST | `/reputation/false-positive` | web, ext | `{ domain, reportedStatus, note? }` → `201`. Recorded for review only; listings are never changed automatically. |

## Browser extension

| Method | Path | Client | Notes |
|---|---|---|---|
| POST | `/extension/link-codes` | web | `201 { code: "ABCD-EFGH", expiresAt }`. Single-use, valid for 10 minutes. |
| GET | `/extension/devices` | web | Linked browsers. |
| DELETE | `/extension/devices/:id` | web | Unlinks a browser (revokes its token). |
| GET / DELETE | `/extension/events` | web | Lists or deletes synced security events. |
| POST | `/extension/link` | public (rate-limited) | `{ code, label? }` → `201 { token, expiresAt }` (a 90-day extension session). |
| GET | `/extension/status` | ext | `{ linked, account: { emailMasked }, session: { syncEnabled }, entitlement: { plan, state, features, currentPeriodEnd }, dataset, serverTime }` |
| POST | `/extension/unlink` | ext | `204` |
| PUT | `/extension/settings` | ext | `{ syncEnabled }`. Turning sync on requires Premium. |
| POST | `/extension/lookup` | ext, **Premium** | `{ prefixes: ["8 hex chars", …] }` (1–10 prefixes) → `{ matches: [{ fullHash, source, sourceLabel, threatType, firstSeenAt, lastSeenAt }], dataset, entitlement }`. The server never receives a hostname. |
| POST | `/extension/events` | ext, **Premium**, sync on | `{ events: [{ clientEventId (uuid), type: "malicious_site_blocked"\|"suspicious_site_warned"\|"cached_result_escalated", domain, status: "malicious"\|"suspicious", reasonCodes?, datasetVersion?, occurredAt }] }` (1–20 events) → `202 { accepted, duplicates, rejected[] }` |

## Plans & billing

| Method | Path | Notes |
|---|---|---|
| GET | `/billing` | `{ catalog: { billingMode, checkoutAvailable, currency, premium: { priceMinor, interval, priceStatus, display }, developmentNotice }, entitlement }` |
| POST | `/billing/dev-checkout` | `BILLING_MODE=development` only: grants Premium with `paymentProcessed: false`. Otherwise `503 BILLING_NOT_CONFIGURED`. |
| POST | `/billing/cancel` / `/billing/resume` | Cancel at period end, or undo the cancellation (development subscriptions). |
| POST | `/billing/dev-expire` | Development only: ends Premium immediately so you can test the downgrade. |

Entitlement: `{ plan: "free"|"premium", state: "none"|"active"|"trialing"|"canceling"|"past_due_grace"|"expired"|"canceled", features, subscription, checkedAt }`.

## Notifications & privacy

| Method | Path | Notes |
|---|---|---|
| GET / PATCH | `/notifications/preferences` | Fields: `security_alerts_email, remediation_reminders_email, periodic_summary_email, product_updates_email` |
| GET | `/notifications/deliveries` | Category, status and reason only. Message content is never stored or returned. |
| POST | `/notifications/unsubscribe` | Public. `{ u, c, t }` from the HMAC-signed link in an email. |
| GET | `/privacy/export` | Downloads a JSON file of the user's data (no secrets). |
| GET | `/privacy/retention` | Retention periods in days. |
| DELETE | `/account` | `{ password, confirm: "DELETE" }` → `{ deleted, googleTokenRevocations, backupsNote }` |

## Admin (role `admin`; grant with `npm run make-admin -w backend -- user@example.com`)

| Method | Path | Notes |
|---|---|---|
| POST | `/admin/threat-sync` | Runs the feed sync now. |
| GET | `/admin/false-positives` | Reported false positives awaiting review. |

## Breaking changes from the v1 prototype

See [CHANGES_FROM_V1.md](CHANGES_FROM_V1.md).
