# FootprintX release

This release follows the supplied master specification, with purchases disabled and Node/PostgreSQL deployment as requested. See docs/RELEASE_REPORT.md for actual verification and external requirements. No live deployment is claimed.

## Run locally

Use Node.js 22 or newer:

```text
npm ci
npm run setup
npm run dev
```

Open http://localhost:5173. Preserve existing backend/.env keys and data. Setup never overwrites that file. Configure OAuth before connecting Gmail and SMTP plus CONTACT_TO before contact or recovery email.

## Prepare deployment

Follow [the Node/PostgreSQL guide](docs/DEPLOY-NODE.md). With production environment variables configured:

```text
npm run build:production
npm run migrate
npm run threat:sync -w backend
npm run preflight
npm start
```

Settings provides extension downloads. Localhost packages must be rebuilt for the real domain. Firefox installation and browser-store publication need the applicable signing/approval process.

## Verify

```text
npm run lint
npm test
npm run build
npx playwright-core install chromium
npm run test:e2e
npm run audit:deps
```

For disposable PostgreSQL only, set TEST_DATABASE_URL and run `npm run test:pg`. That command resets its public schema. Never use a user's database. Browser tests use harmless local fixtures.

Read docs/ACCEPTANCE.md for requirement status, docs/API.md for contracts and docs/DASI.md for scoring. CONTINUE-HERE.md and older audits are historical; this release report supersedes their claims.
