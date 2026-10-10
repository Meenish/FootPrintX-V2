# Testing and release gates

The current evidence is in [RELEASE_REPORT.md](RELEASE_REPORT.md) and the release verification logs. Older audit results are historical and are not evidence of this release's live integrations.

| Command | Scope |
|---|---|
| `npm run lint` | Frontend, backend, shared logic, extension and scripts |
| `npm test` | Shared domain logic, backend integration/unit tests with isolated PGlite, extension unit tests |
| `npm run test:pg` | Backend suite against TEST_DATABASE_URL; destroys and recreates that disposable database's public schema |
| `npm run build` | Frontend and both localhost extension ZIPs |
| `npm run test:e2e` | Chromium web workflows and actual extension with a real local API |
| `npm run audit:deps` | Production dependency audit |
| `npm run eval:detection` | Labeled domain-classification benchmark, not a real-world accuracy guarantee |
| `npm run preflight` | Production configuration, database/migrations, artifacts and dataset checks |
| `node scripts/smoke.mjs https://YOUR_DOMAIN` | Live deployment health, readiness, config and frontend checks |

Install the browser with `npx playwright-core install chromium` (Linux CI uses `--with-deps`). Override its executable with FX_CHROMIUM if needed. Ports 5071, 5072 and 8099 must be free. Run suites sequentially because extension tests rebuild shared artifacts. Browser profiles and downloads are written under .test-artifacts. Fixtures are clearly labeled, use isolated databases and locally mapped hosts, and never require visiting malicious sites.

Before public launch, verify live Google OAuth and an authorized Gmail scan, provider quotas/consent, SMTP inbox delivery, HTTPS and secure cookies, restart persistence, a backup restore, production extension origins and Firefox behavior. Provision operational monitoring. Purchases intentionally remain disabled. Do not enable production synthetic data or development billing to bypass missing integration configuration.

The automated suites cover tenant isolation, CSRF, sessions/recovery, scan evidence and failures, scoring, remediation, notification consent/delivery failures, report cells, contact acceptance/failure, privacy deletion, package-origin validation, entitlement enforcement, cache failures, warnings and browser UI. They do not replace external security review or real provider/hosting acceptance.
