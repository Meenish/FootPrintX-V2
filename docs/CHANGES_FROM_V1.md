# Changes from the v1 prototype (`footprintx-ui-updated`)

These are breaking changes, listed for the backend and frontend owners.

| Area | v1 | v2 | Why |
|---|---|---|---|
| Persistence | MongoDB (schemaless) or a local JSON file; entire collections loaded and filtered in JS | PostgreSQL with migrations; PGlite for development and tests | Per-tenant indexes, constraints, transactions, cascades |
| Job queue | Redis + BullMQ (optional), otherwise inline | PostgreSQL `scan_jobs` (SKIP LOCKED) with real progress, retries, cancellation | Fewer services; durable; honest progress |
| Auth | Google sign-in only (real mode), or a demo login with an empty body; JWT in `localStorage`, 7 days, not revocable | Email/password accounts; HttpOnly cookie sessions + CSRF; revocable; password reset | Removes the universal demo login; XSS can't steal tokens |
| Google sign-in | Used to log in | **Removed.** Google is used only to connect mailboxes. | Separates identity from authorized data sources |
| Gmail scope | `gmail.readonly` + `openid` + `userinfo.email` | `gmail.metadata` by default (`readonly` opt-in); the address comes from `users.getProfile` | Least privilege |
| Encryption | AES-256-GCM with a fallback key derived from `JWT_SECRET` or `'development-only-change-me'` | Key ring, AAD row binding, no fallback key, startup refuses weak or missing keys | Defect: a predictable key |
| Demo data | Random dates, fabricated "security alerts", random risk levels | Deterministic, labelled synthetic mailbox through the real pipeline; development only | No fabricated findings |
| Scan progress | A 350 ms `setTimeout` animation | Job record counts (listed / read / failed) | Defect: fake progress |
| Scan emails | An email after every manual scan | No routine scan emails; de-duplicated alerts with a daily cap | Inbox flood |
| DASI | Uncapped sum with risk points for unknown MFA | `dasi-2.0.0`: explainable, versioned, upper bound for unknowns, confidence, history | See [DASI.md](DASI.md) |
| Official links | Any unknown service linked to Google's security page | A verified registry; no link when unverified | Defect: fabricated links |
| Remediation | A "completed" checkbox | User-reported vs verified (security email), plus history | Honesty |
| Pricing | Per-mailbox paid tiers in USD; buttons fired `alert()` | Free (unlimited mailboxes) / Premium (browser protection); configurable INR price, labelled "proposed" | Matches the product brief |
| Frontend build | `"build": "vite"` (started the dev server) | `vite build` | Defect |
| xlsx export | `xlsx@0.18.5` (known advisories) | Removed; CSV export generated server-side with formula-injection protection | Security |

## Route mapping

| v1 | v2 |
|---|---|
| `POST /api/auth/login` (demo: empty body) | `POST /api/auth/login { email, password }`; `POST /api/auth/register` |
| `POST /api/auth/exchange`, `GET /api/oauth/google/login` | Removed (Google sign-in removed) |
| `GET /api/oauth/google` | `POST /api/connections/google/start` |
| `GET /api/oauth/google/callback` | `GET /api/connections/google/callback` (**update the Google Console redirect URI**) |
| `DELETE /api/oauth/google/:id` | `POST /api/connections/:id/disconnect` |
| `POST /api/scan`, `GET /api/scan/status`, `/api/scan/history` | `POST /api/connections/:id/scan`, `GET /api/scans/:id`, `GET /api/scans` |
| `GET /api/dashboard`, `/api/accounts`, `/api/accounts/:id`, `/api/recommendations`, `/api/alerts` | Same paths, new response shapes (see [API.md](API.md)) |
| `PATCH /api/accounts/:id { action }` | `PATCH /api/accounts/:id { action: dismiss\|confirm\|restore, serviceName, mfaStatus, accountState }`; remediation moved to `PATCH /api/recommendations/:id` |
| `GET/POST /api/consent/breach`, `POST /api/breaches/scan` | `GET /api/breaches`, `POST /api/breaches/consent`, `POST /api/connections/:id/breach-check` |
| `/api/reports`, `/api/reports/generate` | Replaced by `/api/activity`, `/api/dasi/history`, `/api/accounts/export.csv`, `/api/privacy/export` |
| `/api/pricing`, `/api/pricing/estimate` | `GET /api/billing` |
| `/api/settings` | `/api/connections`, `/api/notifications/preferences` |
| `/api/internal/security-demo` | Removed |

**Data migration:** v1 data was demo or prototype data and is not migrated. Users reconnect their mailboxes.
