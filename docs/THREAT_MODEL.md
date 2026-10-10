# Threat model

**Assets**

- Users' FootprintX accounts.
- Gmail refresh tokens, which are the most valuable secret held.
- The inventory of which services a user has accounts with (sensitive in aggregate).
- Breach findings.
- Browsing-derived warnings.
- Entitlements.

**Adversaries**

- Internet attackers.
- A malicious FootprintX user targeting other users.
- Malicious websites, including ones the extension visits.
- Malicious email senders.
- An attacker with a copy of the database.
- A careless operator, for example someone who logs secrets.

Encryption alone does not make the system secure. The table below lists each threat, how it is mitigated, and the risk that remains.

| # | Threat | Mitigations (where) | Residual risk |
|---|---|---|---|
| 1 | **Account takeover of FootprintX users** | bcrypt (cost 12); minimum 12 characters plus a common-password deny-list (`services/auth.js`); per-IP rate limit (10 per 15 min) and per-account lockout (10 failures → 15 min); constant-time login for unknown emails; opaque, revocable sessions with 24 h idle / 7 day absolute expiry; password change and reset revoke other sessions | No MFA for FootprintX itself yet; no breached-password (k-anonymity) check; lockout can be used to annoy a known user for 15 minutes |
| 2 | **OAuth token theft** | Refresh tokens AES-256-GCM-encrypted with row-bound AAD; key ring held outside the database; never returned by the API or logged (redacting logger); PKCE plus a single-use, user-bound state; least-privilege `gmail.metadata` scope; tokens revoked at Google on disconnect and on account deletion | Server memory compromise exposes decrypted tokens in use; no KMS/HSM integration (keys come from environment variables) |
| 3 | **Cross-user data access (IDOR)** | Every query is scoped `WHERE user_id = $n`; IDs are UUIDs; other users' resources return 404; a test covers 12 endpoints (`api.security.test.js`) | New endpoints must follow the same pattern; enforced by code review and tests |
| 4 | **CSRF / cross-site requests** | SameSite=Lax HttpOnly cookies; synchronizer CSRF token on unsafe methods; JSON-only bodies; refusal of cross-origin unsafe requests; strict CORS | Same-site subdomain takeover could weaken SameSite |
| 5 | **XSS in the web app** | React escaping; no `dangerouslySetInnerHTML` (lint rule `react/no-danger`); strict CSP (`script-src 'self'`, no inline scripts); tokens never readable by scripts | A supply-chain compromise of an npm dependency |
| 6 | **Malicious extension messages** | No content scripts and no `web_accessible_resources`, so web pages cannot reach extension pages; `onMessage` accepts only our own extension origin and a fixed handler allow-list; warning details come from the background, never from URL parameters; all DOM is built with `textContent` | A compromised browser profile or another malicious extension with broad permissions |
| 7 | **Spoofed or forged extension events** | Bearer token of an extension session (revocable, scoped); Premium plus per-session opt-in enforced on the server; zod-validated event types, domains and timestamps (±7 days); de-duplication by client event ID; rate limit 120/h per session | A user can submit false events about *their own* account (it affects only their own dashboard) |
| 8 | **Entitlement spoofing** | Entitlement computed server-side from `subscriptions` on every Premium request (`402` otherwise); the extension's cached plan only drives UI text; tests cover client "premium" flags and expired subscriptions | Development billing mode grants Premium without payment, so production configuration rejects it |
| 9 | **False positives (threat warnings)** | Exact or parent-domain matching only; rejection of public suffixes, protected multi-tenant platforms and shared-content hosts (`shared/src/threat.js`); feed-shrink protection; heuristics produce amber only; "Continue anyway" and false-positive reporting; evaluation script (0/169 benign flagged) | Feed entries for a legitimate site's subdomain will warn; heuristics can flag an unusual legitimate brand-like domain |
| 10 | **False negatives** | Hash-prefix lookups against a regularly refreshed feed; look-alike heuristics; re-checks of cached results when the dataset changes; threat-update alerts | New or unlisted phishing sites will pass. Heuristics flag only about 0.4% of a real phishing feed by themselves, so the list is the primary control. Stated in the UI. |
| 11 | **Errors reported as safe** | `combineVerdict`: green only after a completed lookup with a usable dataset; stale or empty dataset → `unknown`; timeouts, offline and 5xx → `unavailable` (grey); breach provider errors → `unavailable` and accounts stay `unknown` | None known; covered by unit, integration and end-to-end tests |
| 12 | **Spoofed security emails poisoning discovery** | DMARC/DKIM results parsed from `Authentication-Results`; failing senders are downgraded to weak evidence (they can't confirm accounts or trigger alerts); mail from personal mailbox domains is ignored | Senders with no authentication result count as "unknown" (medium confidence) |
| 13 | **Malicious email content** | Only headers are fetched; subjects are classified with bounded regexes over at most 600 characters and discarded; display names are sanitized and length-capped; nothing from email is rendered as HTML | None significant |
| 14 | **API abuse / denial of service** | Global and per-route rate limits; 64 KB body limit; bounded list sizes (10 prefixes, 20 events); scan de-duplication; per-user scan limits; breach recheck freshness window | Rate limiting is in memory per process; multi-instance deployments need a shared store |
| 15 | **Provider outage or abuse of providers** | Timeouts (Gmail 15 s, breach 10 s, feeds 90 s); retries with backoff on transient errors; respects `Retry-After`; XposedOrNot throttled and free-tier limits surfaced to the user | Free XposedOrNot tier (25 lookups/hour per IP) is unsuitable for many users; needs a paid plan |
| 16 | **Database compromise** | Tokens and mailbox addresses encrypted; sessions, codes and tokens stored as hashes; HMAC blind indexes; keys outside the database; least-data design (no message content) | Login emails, service names and risk data are stored in plaintext (needed for querying); use encrypted storage and restricted access |
| 17 | **Sensitive logging** | Single logger with key-based and pattern-based redaction (tokens, Bearer headers, emails, long hex); request logs carry only route patterns; a test asserts no secrets appear in captured logs | Third-party libraries writing to stdout directly |
| 18 | **SSRF** | No server-side fetch of user-supplied URLs; feed URLs come from a fixed registry; breach APIs are fixed hosts with `redirect: 'error'` | — |
| 19 | **Account enumeration** | Identical login errors; reset request always returns 202 | Registration returns a generic 409 for existing emails (unavoidable without email verification); mitigated by rate limits |

## Key management and rotation

| Key | Format | Purpose |
|---|---|---|
| `ENCRYPTION_KEYS` | `k2:<hex>,k1:<hex>` | The first key encrypts. Every listed key can decrypt (records store their `kid`). |
| `INDEX_KEY` | hex | HMAC key for blind indexes. Rotating it requires re-indexing, so treat it as long-lived. |

**Rotating the encryption key:**

1. Generate a new key and prepend it to `ENCRYPTION_KEYS`.
2. Deploy.
3. Re-encrypt records whose `kid` is old: `needsReencryption()` exists in `crypto.js`; a re-encryption script is a listed follow-up.
4. Remove the old key.

**Production:** load keys from a secret manager (AWS Secrets Manager, GCP Secret Manager or Vault) into the environment. Integrating a KMS for envelope encryption is listed under remaining limitations.
