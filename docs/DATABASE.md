# Database

**Engine.** Production uses PostgreSQL 16 or later. Development and tests use PGlite, which is the same SQL engine.

**Migrations.** Migrations live in `backend/migrations/NNN_name.sql` and are applied in order by `npm run migrate`. The API also applies them on startup. Each migration runs in its own transaction, guarded by a Postgres advisory lock, and its version is recorded in `schema_migrations`. The readiness probe (`/api/ready`) returns 503 while any migration is pending.

**Adding a migration.**
1. Create `003_description.sql`. Never edit a migration that has already shipped.
2. Make it backward-compatible with the previous app version, for rolling deploys.
3. Run `npm test` and `npm run test:pg`.

## Tables

| Table | Purpose | Ownership / key constraints |
|---|---|---|
| `users` | FootprintX accounts: email, bcrypt hash, role, lockout counters | `email` unique |
| `sessions` | Web and extension sessions; stores only the SHA-256 of the token and of the CSRF token | FK `users` cascade; `token_hash` unique |
| `password_reset_tokens` | Single-use, 30-minute reset tokens (hashed) | FK cascade |
| `oauth_states` | Single-use OAuth state (hashed) with the encrypted PKCE verifier, 10-minute TTL | FK cascade |
| `email_connections` | Connected mailboxes: encrypted email, HMAC blind index, masked email, encrypted refresh token, scope, status, revoke result | unique `(user_id, email_hash)` |
| `scan_jobs` | Durable job queue: status, progress, per-source results, attempts | partial unique index allows one queued/running job per connection |
| `discovered_accounts` | Inventory: status, provenance, confidence, MFA, exposure, state, risk | unique `NULLS NOT DISTINCT (user_id, connection_id, service_key)` |
| `account_evidence` | One row per evidence item: kind, strength, sender domain, authentication result, observed time. The message reference is stored only as an HMAC. | unique `(account_id, source_ref_hash)` |
| `consents` | Breach-lookup consent, bound to the provider and the policy version | unique `(user_id, kind)` |
| `breach_checks` | Every provider check and its outcome, including failures | FK cascade |
| `breach_findings` | Breach listings (historical; never deleted by remediation) | unique `(connection_id, provider, breach_name)` |
| `dasi_snapshots` | Versioned score history with reasons | FK cascade |
| `recommendations` | Action items, official link, status, verification evidence | unique `NULLS NOT DISTINCT (user_id, account_id, domain, action_type)` |
| `remediation_events` | Status transitions (user or system) | FK cascade |
| `alerts` | In-app alerts | unique `(user_id, dedup_key)`, where the key includes severity |
| `notification_preferences` / `notification_deliveries` | Email categories / delivery log (no content) | delivery unique `(user_id, channel, dedup_key)` |
| `subscriptions` | Server-side entitlement record | one per user |
| `extension_link_codes` | One-time linking codes (hashed) | FK cascade |
| `extension_events` | Opt-in synced warnings | unique `(user_id, client_event_id)` |
| `domain_checks` | Manual website checks (90-day retention) | FK cascade |
| `false_positive_reports` | Reports kept for review | FK set null |
| `threat_indicators` | Threat dataset: hostname, source, SHA-256 and its 8-hex prefix | PK `(hostname, source)`; partial indexes on prefix and full hash where `active` |
| `threat_feed_runs` | Sync history: counts and rejection reasons | |
| `audit_events` | Security audit trail with redacted details and an HMAC of the IP | FK set null, so entries survive account deletion pseudonymised |
| `privacy_requests` | Export and deletion log, keyed by an HMAC of the user ID | |
| `scheduled_tasks` | Leases for periodic jobs | |
| `synthetic_messages` | **Development only**: messages injected into synthetic mailboxes | FK cascade |

## Sensitive data placement

| Data | Stored as |
|---|---|
| Refresh tokens, connected mailbox addresses, PKCE verifiers | AES-256-GCM with AAD tied to the row (`crypto.js`) |
| Email uniqueness, message references, IPs | HMAC-SHA-256 with purpose-specific subkeys derived from `INDEX_KEY` by HKDF |
| Session, reset, link and CSRF tokens | SHA-256 hash only |
| Message subjects and bodies | Never stored |

## Backup and recovery

Backups are an operator responsibility; this repository provides no backup automation. Recommended setup:

- Use a managed PostgreSQL with point-in-time recovery, or schedule `pg_dump --format=custom` nightly to encrypted object storage with **35-day expiry**. That expiry is the backup window stated in [PRIVACY.md](PRIVACY.md).
- **Back up the encryption keys separately from the database.** A database backup is useless without `ENCRYPTION_KEYS`, and leaking both together defeats the encryption.
- **Restore drill:** `pg_restore` into a fresh database, start the API with the same keys, and confirm `/api/ready` returns ready and that a test account can log in.
- **Deletions and backups:** account deletion removes data from the live database immediately. Copies in backups disappear as those backups expire, and the UI states this.
