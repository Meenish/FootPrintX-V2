# Architecture

```
┌──────────────────────┐   same-origin /api (cookie + CSRF)   ┌─────────────────────────────────────┐
│  Web app (React/Vite)│ ────────────────────────────────────▶│  API (Node 22, Express, ESM)        │
│  frontend/           │                                      │  backend/src/app.js                 │
└──────────────────────┘                                      │  ├─ routes/  auth, core, protection, │
┌──────────────────────┐   Bearer token, scoped endpoints    │  │           settings                │
│  Browser extension   │ ────────────────────────────────────▶│  ├─ services/ discovery, scanner,    │
│  (MV3: Chromium, FF) │                                      │  │   risk+dasi, recommendations,     │
│  extension/          │                                      │  │   breach, reputation, billing,    │
└──────────────────────┘                                      │  │   notifications, extension,       │
          ▲   shared/ — domain normalization, matching,       │  │   privacy, maintenance            │
          └── lookalike heuristics, statuses (one copy)       │  └─ worker.js (jobs + scheduler)     │
                                                              └──────┬───────────────┬──────────────┘
                                                                     │               │ outbound (server only)
                                                       ┌─────────────▼───┐   ┌───────▼──────────────────────┐
                                                       │ PostgreSQL 16   │   │ Google OAuth + Gmail API      │
                                                       │ (PGlite in dev/ │   │ XposedOrNot / HIBP (opt-in)   │
                                                       │  tests)         │   │ Threat feeds (Phishing.Database│
                                                       └─────────────────┘   │  or a local file)             │
                                                                             │ SMTP (optional)               │
                                                                             └───────────────────────────────┘
```

## Three separate concepts, three separate data paths

| Concept | Question it answers | Data | Code |
|---|---|---|---|
| Account discovery | Is this email associated with service X? | `discovered_accounts`, `account_evidence` | `services/discovery.js`, `scanner.js`, `accounts.js` |
| Account security assessment | How risky is this account, given the evidence? | `risk_*` columns, `breach_findings`, `dasi_snapshots`, `recommendations` | `dasi.js`, `risk.js`, `recommendationRules.js`, `breach.js` |
| Website threat detection | Is this site associated with known threats? | `threat_indicators`, `domain_checks`, `extension_events` | `reputation.js`, `shared/`, `extension/` |

These paths stay apart:

- A website check never creates or changes an account.
- A breach of a service is linked to a user's account only when the breach dataset contains that user's address, and only by an exact registrable-domain match.
- Threat listings affect an account only through an exact service-domain match. This shows up as the `THREAT_LISTED` factor.

## Key design decisions

| Decision | Why |
|---|---|
| PostgreSQL with SQL migrations, replacing MongoDB plus a JSON file | The v1 code loaded entire collections into memory and filtered them in JavaScript, with no per-tenant indexes and no constraints. PostgreSQL gives foreign keys with `ON DELETE CASCADE` (account deletion), unique constraints (idempotent scans, de-duplication) and transactions. |
| PGlite for development and tests | It is the real PostgreSQL 16 engine compiled to WASM, so `npm install` is enough to start. The same SQL and migrations run on PGlite and on PostgreSQL, and the whole test suite passes on both. Production rejects PGlite. |
| PostgreSQL-backed job queue (`scan_jobs` with `FOR UPDATE SKIP LOCKED`), replacing Redis/BullMQ | One fewer service to run. Jobs survive restarts, at most one job can be active per mailbox (partial unique index), and multiple workers are safe. |
| Opaque session tokens in HttpOnly cookies, with a synchronizer CSRF token, replacing a JWT in localStorage | A token in localStorage can be stolen by any XSS. Opaque tokens are revocable (logout, password change, deletion). Only hashes are stored. |
| Separate extension session kind (Bearer) | Extension tokens can't act as web sessions and are scoped to the extension endpoints. Users revoke them per browser. |
| `gmail.metadata` scope by default | Least privilege: Google itself enforces that message bodies can't be read. `readonly` is opt-in for deeper, search-based discovery. |
| Hash-prefix reputation lookups | Full hashes are compared on the device. These prefixes are separate from the authenticated account-awareness request, which sends the normalized hostname to search the user's inventory. Optional warning sync also sends domains. No full URLs are uploaded. |
| Server-side entitlement on every Premium API | Editing the extension's storage or the web app's state can't unlock Premium. The server answers `402`. |
| `shared/` package bundled into the extension | Backend and extension use identical normalization, matching and heuristics, unit-tested once. |

## Request lifecycle (web)

1. `requestId` and `requestLogger` run. The logger records route patterns only, never IDs, query strings or bodies.
2. `helmet` sets security headers: CSP, `frame-ancestors 'none'`, `no-referrer`, and HSTS in production.
3. CORS: only `APP_URL` (plus `CORS_ORIGINS`) may send credentials. Cross-origin unsafe methods from any other origin are refused.
4. Requests pass the JSON body limit (64 KB), cookie parsing, the global rate limit and the JSON-only rule for unsafe methods.
5. `authenticate` resolves the cookie or Bearer token to a user and session. `requireAuth({ kinds })` checks the session kind and the CSRF token.
6. The route runs `zod` validation, the service call (ownership is enforced with `WHERE user_id = $n` in every query) and audit logging.
7. The error middleware returns a uniform error shape with no stack traces.

## Background work (`services/worker.js`)

| Task | Interval | What it does |
|---|---|---|
| Scan worker | polls every 1.5 s | Claims jobs and runs them. Concurrency is 2 per process. |
| Stale-job recovery | every scheduler tick | Re-queues `running` jobs that have had no heartbeat for 5 minutes. |
| `monitor_scans` | hourly | Queues rescans for Gmail mailboxes not scanned within `MONITOR_INTERVAL_HOURS`. |
| `threat_sync` | every `THREAT_SYNC_INTERVAL_HOURS` | Refreshes the threat feeds and alerts users whose tracked domains or recent visits are newly listed. |
| `maintenance` | hourly | Enforces retention, expires subscriptions and verification windows. |
| `digests` | daily | Sends opt-in weekly summaries and reminders, de-duplicated per ISO week. |

Each task holds a lease row in `scheduled_tasks`, so running several processes is safe. Set `RUN_WORKER` and `RUN_SCHEDULER` to `false` on API instances and run `npm run worker -w backend` separately to split the roles.

## Frontend

- React 18 with react-router 7, built by Vite 6. In development, Vite proxies `/api` so the browser sees a single origin. In production the API serves `frontend/dist` itself (`SERVE_FRONTEND=true`) or both sit behind one reverse proxy.
- Data hooks are in `lib/hooks.js`, with polling paused when the tab is hidden. All wording for statuses lives in `lib/labels.js`.
- Screens: Landing, Login/Register/Forgot/Reset, Onboarding, Overview, Accounts and Account detail, Recommendations, Risk score, Activity, Website check, Settings (Mailboxes, Notifications, Browser extension, Sign-in & security, Privacy & data), Plans, Unsubscribe.

## Extension

See [EXTENSION.md](EXTENSION.md).
