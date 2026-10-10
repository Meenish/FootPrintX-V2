# FootprintX

FootprintX discovers accounts from an authorized mailbox, explains evidence-based risk, tracks remediation and offers browser warnings. Account association, current login status and website safety are separate assessments. Discovery is partial; no result guarantees safety. DASI is FootprintX's own index.

Start with [START-HERE.md](START-HERE.md). See [the release report](docs/RELEASE_REPORT.md) for verified results and [the acceptance checklist](docs/ACCEPTANCE.md) for remaining launch requirements.

## Run locally

Use Node.js 22 or newer:

```text
npm ci
npm run setup
npm run dev
```

Open http://localhost:5173. Setup generates local secrets, preserves an existing backend/.env, enables a labeled synthetic mailbox for development, and keeps purchases disabled. Existing installations should set BILLING_MODE=disabled explicitly. Production rejects synthetic data and development billing. Google OAuth is required for real Gmail scanning; SMTP and CONTACT_TO are required for contact delivery.

## Deploy

Follow [Node.js and PostgreSQL deployment](docs/DEPLOY-NODE.md). The package includes production configuration, systemd and HTTPS proxy templates, preflight and smoke checks, migrations and operational procedures. A domain, host, PostgreSQL and provider setup are still required. No live deployment or browser-store publication has been performed. Docker is not the deployment path.

Both extension builds ship as localhost packages for inspection. Rebuild for the real domain with `npm run build:production` before distributing. See [extension installation](docs/EXTENSION.md). Automatic protection and account awareness require a server-authorized Premium entitlement; purchases are disabled. Test checkout is isolated to explicitly configured development environments and the automated test harness.

## Project layout

| Directory | Purpose |
|---|---|
| backend | Express API, PostgreSQL migrations, persistent jobs, provider adapters and tests |
| frontend | React/Vite application |
| extension | Manifest V3 Chromium and Firefox source/builds |
| shared | Domain normalization, matching and look-alike rules |
| e2e | Real local API and Chromium workflows using labeled fixtures |
| deploy, scripts | Direct Node deployment templates and checks |
| docs | API, scoring, privacy, architecture, testing and release evidence |

Use `npm test`, `npm run lint`, `npm run build` and `npm run audit:deps`. Install Chromium with `npx playwright-core install chromium`, then `npm run test:e2e`. For an isolated disposable PostgreSQL database, set TEST_DATABASE_URL and run `npm run test:pg`; it resets that database's public schema.

The supplied CONTINUE-HERE.md and older audit documents are retained as historical context. This release's report supersedes their test counts and deployment status.
