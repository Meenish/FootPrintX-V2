# Node.js and PostgreSQL deployment

Purchases remain disabled. No Docker deployment is required. No public deployment has been created. Supply a real domain, host, PostgreSQL, Google OAuth configuration and SMTP provider.

## Local development

Use Node.js 22 or newer and run `npm ci`, `npm run setup`, then `npm run dev`.
Open http://localhost:5173. Setup creates random keys without overwriting an existing backend/.env. Keep existing keys and data when upgrading. PGlite is development-only. Production rejects synthetic data and development billing.

## Configure production

Use a managed persistent Node service or Linux VM, with PostgreSQL 16 or newer and one public HTTPS origin for frontend and API. Short-lived functions cannot run the in-process scheduler reliably.

1. Copy deploy/production.env.example to a private environment file or the host's secret settings. For local preparation, backend/.env is supported. Never commit secrets.
2. Generate two different keys using `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`. Set ENCRYPTION_KEYS and INDEX_KEY. Store them in a secret manager and a separate protected recovery backup. Preserve existing keys for existing data.
3. Configure DATABASE_URL for a dedicated least-privilege PostgreSQL role. Remote database connections need validated TLS and the provider's CA configuration. Never disable certificate verification.
4. Set APP_URL and API_PUBLIC_URL to the same real HTTPS origin; SERVE_FRONTEND=true. HOST defaults to 127.0.0.1. Use HOST=0.0.0.0 only when the host requires it. For the supplied proxy, TRUST_PROXY=1. Keep port 5000 and PostgreSQL private.
5. Configure GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET; enable Gmail API and register `https://YOUR_DOMAIN/api/connections/google/callback`. Complete Google's consent-screen verification and restricted-scope approval where required. Test an authorized mailbox.
6. Configure SMTP_HOST, SMTP_PORT, SMTP_SECURE, SMTP_USER, SMTP_PASSWORD, SMTP_FROM and CONTACT_TO. Verify the sender and provider-required SPF/DKIM/DMARC. Test contact, reset and consented notification delivery. SMTP acceptance does not guarantee inbox delivery.
7. Set THREAT_FEEDS=phishing_database and review its scope and terms. Select BREACH_PROVIDER=xposedornot or hibp (requires HIBP_API_KEY). Users consent separately before sending their email to a breach provider.
8. Keep BILLING_MODE=disabled and DEV_SYNTHETIC_DATA=false. No live checkout or payment webhook is configured. Never copy development subscriptions into production.

With production environment variables loaded:

```text
npm ci
npm run lint
npm test
npm run build:production
npm run migrate
npm run threat:sync -w backend
npm run preflight
npm start
```

Back up before migrations. Migrations are transactional and recorded; startup also applies pending migrations. The production build embeds public origins into both extensions. Keep each build-info.json beside its unpacked build and ZIP. The API rejects packages built for different origins. Rebuild after a public URL change. Plain `npm run build` produces localhost packages unless FX_API_BASE and FX_APP_URL are explicitly set.

Preflight checks configuration, database access, migrations, fresh threat data and artifacts. It does not prove provider approval or live delivery.

## Supervision and HTTPS

deploy/footprintx.service is a Linux systemd template. Create a restricted footprintx service user; use /opt/footprintx/current for the release and /etc/footprintx/production.env for owner-readable secrets. Adjust paths for the host. deploy/Caddyfile is a proxy template; set FOOTPRINTX_DOMAIN to the real hostname, configure DNS and allow inbound ports 80/443. This package does not install services or change DNS.

For managed Node hosting, start `node backend/src/server.js`. Run one API process with its worker, or set RUN_WORKER=false and RUN_SCHEDULER=false on API instances and run `node backend/src/workerMain.js` separately. At least one worker must stay running. Multiple API processes require shared or edge rate limiting.

## Verify and monitor

Run `node scripts/smoke.mjs https://YOUR_DOMAIN`. Require successful /api/health, /api/ready, /api/config and frontend checks. Then register a test user, complete Gmail OAuth, scan an authorized mailbox, review DASI, record remediation, reopen Excel, test contact and reset email, restart and confirm persistence. Download the production extension and verify its origin. Test malicious classifications only with isolated harmless fixtures, never by visiting malicious sites or seeding fake production results.

Configure uptime checks and alerts for readiness, 5xx rates, stale threat data, failed feed runs, failed notification deliveries, stuck scan jobs and missing workers. Logs redact sensitive data and record route patterns. Do not log request bodies or sensitive query strings at the proxy. No external monitoring account is configured by this package.

## Backups and rollback

Prefer encrypted managed backups with point-in-time recovery. Alternatively use `pg_dump --format=custom --file=backup.dump` with secure PGHOST, PGPORT, PGUSER, PGDATABASE and PGPASSFILE settings. Avoid passwords on command lines. Encrypt dumps outside the source tree, restrict access and retain 30 days. Keep encryption-key recovery separately protected.

Rehearse `pg_restore --dbname=RESTORE_DATABASE backup.dump` into an empty isolated database. Check migrations, counts, encrypted-record readability, ownership and reports. Disable outbound providers and scheduled email for restored copies.

Keep the previous release. To roll back, stop writes, restore that release and check schema compatibility. Migration 004 adds contact records and changes only the default email preference. Existing choices remain. Do not delete migration rows. Database restoration requires a plan for subsequent writes and deletion requests; replay deletions before reopening.

## Retention and incidents

Contacts are encrypted, user-owned, exported with privacy data, deleted with the user and purged after 90 days. Other retention is in docs/PRIVACY.md and /api/privacy/retention. Live deletion does not rewrite backups; backups expire under the operator's policy. The support mailbox needs its own retention controls.

On compromise: isolate affected services, preserve redacted logs, revoke exposed sessions and provider credentials, rotate keys using THREAT_MODEL.md, assess disclosure and required notifications, restore a known-good release and verify before reopening. Changing INDEX_KEY requires planned re-indexing.
