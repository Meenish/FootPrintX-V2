# FootprintX browser extension

A Manifest V3 browser extension that gives Premium users warnings about known-threat and look-alike websites, while keeping their browsing private.

**Supported browsers**

| Browser | Status |
|---|---|
| Chromium build (manifest minimum Chrome 116) | Automated tests on Windows Chromium 156; Chrome/Edge branded releases and minimum versions not separately tested |
| Firefox 121+ (Firefox build) | Builds and manifest validated; **not tested in a real Firefox** in this environment |
| Safari, other browsers | Not supported |

The extension is **not published to any store**.

## Build and install (developer build)

```bash
npm install                                    # at the repository root
FX_API_BASE=http://localhost:5000 FX_APP_URL=http://localhost:5173 npm run build -w extension
# → extension/dist/chromium  and  extension/dist/firefox
npm run package -w extension                   # also writes dist/footprintx-<target>-<version>.zip
```

`FX_API_BASE` must be `https://` except for `localhost`. It is compiled into the bundle and into `host_permissions`.

**Chrome / Edge**

1. Open `chrome://extensions` (or `edge://extensions`).
2. Turn on Developer mode.
3. Click **Load unpacked** and choose `extension/dist/chromium`.

**Firefox**

1. Open `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on** and choose `extension/dist/firefox/manifest.json`.
3. If the options page shows "Allow access to the FootprintX server", click it. Firefox may treat MV3 host permissions as optional.

**Linking**

1. Sign in to the web app and open **Settings → Browser extension → Create link code**.
2. The extension's options page opens automatically after install. Enter the code there.
3. You never type your password into the extension.

For production, configure APP_URL and API_PUBLIC_URL to the same real HTTPS origin and run `npm run build:production`. Optionally configure FX_GECKO_ID. Keep build-info.json beside each build and ZIP. Browser-store publication requires the relevant reviews and signing.

## How a check works

```
navigation (top frame) ─▶ hostname only ─▶ local / internal / API host? → grey "not checked"
   ─▶ linked & Premium? (server-verified entitlement, cached ≤ 1 h) ── no → grey "protection off (Premium)"
   ─▶ fresh cached result? → use it
   ─▶ local look-alike heuristics (no network)
   ─▶ SHA-256 of host + parent domains → send 8-hex prefixes → server returns full hashes
   ─▶ compare locally → verdict:
        malicious (red + warning notification; interstitial only if opted in) │ suspicious (amber + notification)
        no_known_threat (green, only after a completed lookup with a usable dataset)
        unknown (grey: dataset missing/stale) │ unavailable (grey: offline/timeout/error)
```

**Matching rules** (shared with the server, `shared/src/domain.js`):

- A listing for `evil.example` matches `evil.example` and any subdomain of it.
- It never matches a parent (`example`), a sibling, or a substring (`notevil.example`).
- Listings for public suffixes (`github.io`), major platforms (`google.com`, `weebly.com` …) and shared-content hosts (`sites.google.com`) are rejected when the feed is loaded.
- Internationalized names are compared in punycode. Look-alike (homograph) detection compares the Unicode form against brand names.

**Heuristics** (amber only, never red):

- Homograph or mixed-script names.
- A brand domain embedded in a subdomain (`paypal.com.verify.example`).
- One character away from a brand name of six or more letters (`paypa1.com`).

Being new or unfamiliar is never treated as suspicious.

## Toolbar states

| State | Colour | Badge | Title example |
|---|---|---|---|
| Known threat | red | `!` | FootprintX — Known threat detected: site |
| Suspicious | amber | `?` | FootprintX — Suspicious indicators: site |
| No known threat | green | `✓` | FootprintX — No known threat detected: site |
| Checking | grey | `…` | FootprintX — Checking…: site |
| Unavailable / unknown / not checked / off | grey | (none) | FootprintX — Check unavailable (offline): site |

Each state has a different icon glyph and title text, so colour is never the only signal. The popup explains the state in words.

## Independent account and login awareness

The popup separately queries the signed-in user's inventory using the normalized hostname. Confirmed and possible associations are distinct. No match does not prove there is no account. Current website login detection is unavailable: the extension does not read website cookies, credentials or session tokens. Association never changes the safety verdict. The request sends the domain only and the one-minute cache is cleared on unlink/relink.

## Warning page

- Shows the domain, the reason (which list matched, exact or parent domain, when it was last confirmed), what the risk could mean, and safe next steps.
- Redirecting known threats to this page is off by default; enable it explicitly in extension settings.
- **Go back to safety** returns to the last checked origin. Paths and queries are not retained. Continue opens the warned origin.
- **Continue anyway** sets a one-hour bypass for that hostname in this browser.
- **Report a mistake** sends a false-positive report for review.
- Warning details come from the background script, keyed by a random ID. URL parameters are never trusted.

## Offline, outage and entitlement behaviour

| Condition | What happens |
|---|---|
| Server unreachable | `unavailable` (grey). A threat seen in the last 7 days still warns, shown as a saved result. |
| Threat dataset stale or empty | `unknown` (grey), never green. |
| Entitlement can't be verified | The UI says the plan couldn't be confirmed. Lookups are refused by the server anyway. |
| Premium expired | "Premium ended" (distinct from an outage). |
| Unlinked or revoked token | Forgotten; the extension asks to link again. |

## Permissions

| Permission | Why |
|---|---|
| `webNavigation` | Read the URL of top-level navigations to get the hostname. The browser shows this as "read your browsing history". The extension does not upload history. |
| `storage` | Settings, link token, results cache (max 300 entries; clean results six hours, saved known threats up to seven days), local warning log (max 100) |
| `alarms` | 30-minute refresh: entitlement, dataset change → re-check cached results, flush the sync queue, purge the cache |
| `notifications` | Suspicious-site and threat-update notices |
| host permission: the FootprintX API origin only | Talk to FootprintX. No access to the websites you visit. |

**Not requested:** `tabs`, `cookies`, `<all_urls>`, content scripts, `scripting`, `webRequest`.

The extension-page CSP is `script-src 'self'; object-src 'none'; base-uri 'none'`. There is no remote code, `eval`, or `innerHTML`; the package test enforces this.

## Detection quality

Run `npm run eval:detection` (from `shared/`). Optionally pass a phishing-domain feed file as the first argument.

Last run (Oct 2026):

| Measure | Result |
|---|---|
| Benign reference set (169 popular domains, incl. near-miss words like "finance", "stripes") | 0 flagged (0.0% false-positive rate) |
| Crafted look-alike set (39) | 35 detected (89.7% recall) |
| Missed look-alikes | `netflix-account.com` (brand plus a word), `instagrarn.com` (`rn` → `m`), `walrnart.com`, `hdfcbank.com-netbanking.example` |
| Real Phishing.Database sample (100k hosts) | Heuristics alone flag 0.39%. Most real phishing is hosted on free-hosting subdomains, so the **threat list is the primary control** and heuristics are a secondary signal. |
| Matching semantics (6 fixed cases), protected-listing rejection (5/5) | All correct |

**Release gate:** the script exits non-zero if the benign false-positive rate exceeds 2% or any matching case fails.

## Tests

| Suite | Coverage |
|---|---|
| `extension/test/extension.test.js` (13 tests) | Checker states, privacy of lookups, caching and de-duplication, offline behaviour, entitlement handling, events, toolbar, API client, and the package policy: permissions, no content scripts, no unsafe DOM APIs or remote code |
| `extension/test/awareness.test.js` (2 tests) | Independent association, unavailable login, failure states, bounded cache and relinking |
| `e2e/extension.test.mjs` (11 tests) | Loads the real extension in Chromium against a real API, with test hosts mapped to a local page server: linking, Free (no checks), red warning page, parent-domain match, leave / continue, green, independent account recognition, amber, opt-in sync, popup, offline grey with a cached red warning |
