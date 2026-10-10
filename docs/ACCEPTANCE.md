# Master-specification acceptance checklist

Status refers to this source release, not a deployed service. Automated provider tests use controlled responses; production configuration is intentionally not invented.

| Requirement | Status and evidence |
|---|---|
| Audit and preserve existing implementation | Existing React/Express/PostgreSQL implementation retained; gaps and changes in RELEASE_REPORT.md |
| Authentication, recovery, sessions, ownership | Implemented; backend authorization, auth and rate-limit suites |
| Gmail consent and discovery | Implemented; metadata evidence classification, scan failures, disconnect/revocation and dedup tested; live OAuth approval/credentials still required |
| Multiple sources, incomplete evidence, inventory | Implemented; confirmed/possible/dismissed, source state and timestamps; no universal-discovery claim |
| DASI and risk findings | Implemented, model dasi-2.0.0; deterministic factors, unknown upper bound, critical findings and snapshots tested |
| Recommendations and remediation | Implemented; official catalog links, user-reported versus independently verified status; browser workflow tested |
| Real threat intelligence | Implemented adapters for Phishing.Database, XposedOrNot and HIBP; errors remain unavailable; operator must configure feeds/provider and verify live service |
| Extension account association | Implemented; normalized domain, owned inventory only, confirmed/possible/no-match; API and browser tests |
| Extension current login awareness | Explicitly unavailable. No reliable site-session integration is supplied; account association is never treated as login |
| Extension website safety | Implemented independently; red/amber/green/grey, unknown never green, cache and offline cases tested |
| Navigation and warning UX | Implemented; opt-in interstitial, toolbar, popup, SPA navigation, origin-only return links |
| Free and Premium permissions | Backend gates tested including spoofing; disabled purchases per user instruction; development-only checkout remains labeled and production-rejected |
| Optional extension event sync | Off by default; warning-only, ownership and retention tested |
| Excel report | Six-sheet XLSX with real owned data and injection-safe cells; backend workbook parsing and browser download initiation verified. Unrestricted browser file-save check pending |
| Contact | Validated/rate-limited, encrypted persistent outcome, verified SMTP acceptance; stubbed accepted/rejected tests; live mail setup required |
| Notification consent and delivery | New optional preferences off; dedup claims, delivery outcomes and limited safe retries tested; live inbox delivery required |
| Privacy and security | Encryption, secret redaction, token revocation, export, deletion, retention, CSRF and tenant isolation tested |
| Responsive UI and failure states | Chromium desktop/mobile workflows, visible synthetic label, keyboard focus and unavailable contact checked |
| PostgreSQL migrations | Migrations 001–004 and backend tests pass on fresh PostgreSQL 16.15; deployment database not provisioned |
| Reproducible build and CI | Lockfile, lint, builds, tests, audit, GitHub Actions workflow provided; remote CI not run in this task |
| Production configuration and deployment | Direct Node/systemd/Caddy templates, preflight/smoke scripts and rollback guide; no Docker deployment |
| Monitoring, backups, incidents | Health/readiness endpoints plus operating procedures provided; operator must provision alerts and execute restore rehearsal |
| Browser release | Chromium exercised; Firefox built and manifest validated only; stores/signing pending |
| Public deployment and smoke test | Pending domain, hosting and credentials; no public URL or deployment claimed |

Public launch acceptance remains open for the external items above. See DEPLOY-NODE.md for exact configuration and commands.
