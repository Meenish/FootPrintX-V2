# Privacy and data governance

FootprintX **does process personal data**: email metadata you authorize, breach listings for your addresses, and security warnings you choose to share. Its aim is to process as little as possible. This document states what the code actually does. If code and document ever disagree, treat it as a bug.

## What is collected and why

| Data | Why | Where | Retention |
|---|---|---|---|
| Your FootprintX email, name, password hash | Sign-in | `users` | Until you delete your account |
| Connected mailbox address | Display, breach checks, de-duplication | `email_connections` (AES-GCM encrypted, plus a masked copy and an HMAC) | Until you delete the connection or your account |
| Google refresh token | Scanning with your permission | `email_connections.token_enc` (encrypted) | **Deleted and revoked at Google on disconnect** |
| Per message: sender domain, the *kind* of email (sign-up, security alert …), its date, sender-authentication result | Evidence for each account | `account_evidence` | With the account record |
| Message subjects, snippets, bodies, attachments | **Not stored.** Subjects are classified in memory and discarded. Bodies are never fetched (the metadata scope makes them inaccessible). | — | — |
| Discovered services, risk scores, recommendations, your actions | The product itself | various | Until you delete them or your account |
| Breach listings for your address | Exposure assessment | `breach_findings` | Kept as history, even after remediation |
| In-app alerts; email delivery outcomes (category and status, **no content**) | Notifications | `alerts`, `notification_deliveries` | Deliveries: 180 days |
| Website checks you run in the web app | Your history | `domain_checks` | 90 days |
| Extension warnings you chose to share (domain, warning type, time) | Dashboard | `extension_events` | 365 days, or until you delete them in Settings |
| Audit log (event names, redacted details, HMAC of your IP) | Security | `audit_events` | 365 days; pseudonymised when you delete your account |
| Scan job records | Status and history | `scan_jobs` | 180 days |
| Contact name, reply address and message | Deliver your support request | `contact_submissions` (encrypted), configured support mailbox | Database: 90 days; mailbox: operator policy |

Retention is enforced hourly by `backend/src/services/maintenance.js` (`RETENTION`) and exposed at `GET /api/privacy/retention`.

## Who receives data

- **Google**: through the OAuth permission you grant (headers only by default).
- **Breach provider** (XposedOrNot or Have I Been Pwned): only your connected email address, only after explicit consent, which is tied to that provider and policy version. You can withdraw consent at any time.
- **Threat feeds**: FootprintX downloads lists. Nothing about you is sent to them.
- **SMTP provider** (if configured): the emails you opted into, essential password-reset emails, and contact messages you submit to the support mailbox.
- **Nobody else.** FootprintX does not sell data, build advertising profiles, or track you across websites.

## What the browser extension checks

- For every top-level page you open, it reads only the hostname.
- It computes SHA-256 hashes of the hostname and its parent domains and sends only **8-hex-character prefixes** to FootprintX. Matching is done on your device.
- Separately, account awareness sends the normalized hostname to the authenticated inventory endpoint. It is looked up against your own account records and is not stored as browsing history. Results have a one-minute in-memory cache. Paths, queries and fragments are not sent.
- Routine clean results expire after six hours; saved known-threat results may warn for seven days during an outage. The local cache is capped at 300 entries. "Clear local history" removes it.
- It never reads page content, form fields, passwords, cookies or session tokens. It has no content scripts and no access to sites (its only host permission is the FootprintX API).
- **Optional sync:** off by default, Premium only, enabled per browser. When on, it sends only warnings (domain, warning type, reason codes, time). Routine visits and full URLs are never sent.

## Disconnecting a mailbox

1. Future scans stop. Queued scans are cancelled and running scans stop at the next batch.
2. The refresh token is revoked at Google (result recorded: `revoked`, `already_invalid` or `failed`) and deleted from the database.
3. Pending verifications for that mailbox fall back to "reported by you".
4. Findings remain as history **unless** you choose "also delete the accounts and breach results found through this mailbox". You can later delete the disconnected connection together with all its findings.

## Exporting and deleting

- **Export:** `Settings → Privacy & data → Download my data` downloads a JSON file of everything held about you, excluding secrets (password hash, encrypted tokens, internal hashes).
- **Account deletion** requires your password and typing DELETE, then:
  1. Google refresh tokens are revoked (best effort; results recorded).
  2. All user-owned rows are deleted through foreign-key cascades: connections, accounts, evidence, findings, scores, recommendations, alerts, preferences, subscriptions, sessions (including extension sessions) and extension events.
  3. Audit events are kept with `user_id = NULL`. A deletion record keyed by an HMAC of the user ID is kept for compliance.
  4. **Backups:** data in database backups expires on the backup retention schedule (35 days is recommended in [DATABASE.md](DATABASE.md)). It is not removed from existing backups immediately, and the UI says so.

## Email notifications

- Categories: security alerts, reminders, weekly summary and product updates. All default **off** for new users; existing choices are preserved. Change them in Settings.
- Every optional email carries an HMAC-signed one-click unsubscribe link and a `List-Unsubscribe` header.
- In-app alerts and extension warnings keep working when email is off.
- Password-reset emails are essential and always sent; the UI explains this.
- A routine scan never sends an email. Unchanged findings are never re-sent. Security emails are capped per day (`SECURITY_EMAILS_PER_DAY`, default 5).
