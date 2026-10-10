# External providers

| Provider | Purpose | Status in this build |
|---|---|---|
| Google OAuth + Gmail API | Account discovery | **Implemented. Live test blocked**: no OAuth credentials in this environment. Tested with a simulated Gmail provider and synthetic mailbox fixtures (`api.gmail.test.js`, `api.flow.test.js`). |
| XposedOrNot | Breach intelligence (free) | **Implemented. Live test blocked**: the sandbox's egress proxy refuses `api.xposedornot.com`. Real response parsing is tested with stubbed HTTP responses. |
| Have I Been Pwned v3 | Breach intelligence (paid) | **Implemented. Live test blocked**: no API key. Normalization is unit-tested. |
| Phishing.Database (GitHub) | Website threat feed | **Implemented and tested live**: 392,178 lines fetched, 391,458 accepted, 620 rejected (public suffixes, protected platforms, invalid), synced into PostgreSQL 16 in about 18 s. Prefix lookups took 65 ms. |
| Local threat file (`THREAT_FEED_FILE`) | Offline/testing feed | Implemented and tested with the end-to-end fixture. |
| SMTP (nodemailer) | Optional email | **Implemented. Live test blocked**: no SMTP server. Tested with a capturing transport (delivery, failure recording, de-duplication, cap, unsubscribe). |
| Google Safe Browsing / Web Risk | — | **Not implemented.** The provider interface in `reputation.js` allows it. Web Risk is the commercial option, and its hash-prefix API maps directly onto the extension's protocol. |
| Stripe / Razorpay | Payments | **Not implemented.** See [PLANS.md](PLANS.md). |

## Google OAuth setup

1. **Create a project.** In Google Cloud Console, create a project and enable the **Gmail API**.
2. **Configure the OAuth consent screen.**
   - User type: External. App name: FootprintX.
   - Add the scope `https://www.googleapis.com/auth/gmail.metadata`. Add `…/gmail.readonly` too only if you plan to use `GMAIL_SCOPE_MODE=readonly`.
   - Add test users while the app is in "Testing".
3. **Create credentials.**
   - Go to Credentials → Create OAuth client ID → **Web application**.
   - Authorized redirect URI: `http://localhost:5000/api/connections/google/callback`. In production, use `${API_PUBLIC_URL}/api/connections/google/callback`, or set `GOOGLE_REDIRECT_URI` to match exactly.
4. **Configure the backend.** Put `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in `backend/.env`. The secret never leaves the server: it isn't in any frontend or extension bundle.
5. **Before public launch.** Gmail scopes are *restricted*, so Google requires app verification and a CASA security assessment. Until then, at most 100 test users can connect.

**Scope modes**

| Mode | Behaviour |
|---|---|
| `metadata` (default) | Headers only. Gmail search isn't available with this scope, so the scan reads the most recent `SCAN_MAX_MESSAGES` messages. Older signups beyond the cap can be missed; the UI says so. |
| `readonly` | Four time-windowed search queries over the whole mailbox. Fetches metadata and Google's snippet only (never bodies). Deeper discovery, but a broader grant. |

## Breach intelligence setup

```
BREACH_PROVIDER=xposedornot     # or hibp (+ HIBP_API_KEY) or none
BREACH_RECHECK_MIN_HOURS=24     # cached results inside this window
BREACH_INCLUDE_SENSITIVE=false  # HIBP "sensitive" breaches hidden by default
```

- **Consent is required per user.** It is bound to the provider name and `CONSENT_POLICY_VERSION`. Changing either requires fresh consent.
- **XposedOrNot terms:** the free API is for "personal and low-volume use", limited to 25/hour and 100/day per IP. A product needs their paid plan.
- **HIBP** requires a paid API key and attribution.

**What results mean** (also shown in the UI):

- A listing means the address appears in that breach dataset. It does not prove the current password is compromised or reused.
- No listing means no evidence was found by that provider at that time.
- Provider errors and unexpected response shapes are recorded as `unavailable`, never as clean.

## Threat feeds

```
THREAT_FEEDS=phishing_database          # built-in registry in services/reputation.js
THREAT_FEED_FILE=/path/to/hosts.txt     # optional local list (one host per line, # comments)
THREAT_SYNC_INTERVAL_HOURS=12
THREAT_DATASET_MAX_AGE_HOURS=72         # older dataset → results "unknown", never green
```

- Only fixed, registered feed URLs are fetched, so user input cannot trigger server-side requests (no SSRF).
- **Safety on ingest:** invalid and local hosts, public suffixes, protected platforms and shared-content hosts are rejected. If a feed shrinks below 50% of its previous size, existing entries are kept active.
- Run `npm run threat:sync -w backend` to sync manually, or use `POST /api/admin/threat-sync` (admin).
- **Licensing:** review each feed's terms before commercial use. Phishing.Database is published on GitHub by its maintainers. Confirm its license for your use case.
