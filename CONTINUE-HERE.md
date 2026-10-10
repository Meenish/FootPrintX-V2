# FootprintX — handoff: state of the work and what to do next

Date: 2026-10-10. Archive: `footprintx-v2.1.zip`.

---

## 1. What changed since the version you were running

Five defects were fixed. All 120 automated tests pass and lint is clean, but
**none of these five were tested on Windows or in a real browser** — that is the
first thing the next session must do.

| # | Problem you reported | Root cause found | Fix made | Verified how |
|---|---|---|---|---|
| 1 | `npm run dev` crashed with `spawn EINVAL` | `scripts/dev.mjs` spawned `npm.cmd`; Node ≥ 20.12 refuses that on Windows without a shell | Spawns the API and Vite with the current Node binary directly | Ran on Linux; **not run on Windows** |
| 2 | Extension and Premium "not working"; Website check said *"Threat data isn't available"* | The threat-feed sync only runs when `THREAT_FEEDS` is set, and `npm run setup` never set it. The dataset was empty, so every lookup answered "unknown" and the toolbar could never leave grey | `THREAT_FEEDS=phishing_database` is now written by `npm run setup`, and `config.js` falls back to it outside production so existing `.env` files recover too. Opt out with `THREAT_FEEDS=none` | **391,458 indicators synced automatically on first startup.** The website-check and extension lookup paths were *not* re-tested after the sync — see Task A |
| 3 | No way to download the extension | Never built | `GET /api/extension/package` (status) and `GET /api/extension/package/:target` (zip). Builds on demand outside production, cached, rebuilt when sources change. Settings → Browser extension now has a browser picker, a download button and per-browser install steps | New test in `api.protection.test.js`; package built and served (83 KB) |
| 4 | Recommendation links went nowhere for most services | The verified-link registry only covered 18 services; the other ~19 of your 29 accounts correctly showed "No verified official link" | Added 4 verified services (Pinterest, Canva, Netflix, fixed a stale Dropbox URL) **and** a `domain_root` fallback: any service with no registry entry now links to its own bare origin, labelled in the UI as "home page — not a verified deep link". Migration `003` widens the CHECK constraint | Unit + flow tests updated to assert no invented paths |
| 5 | "I've done this" appeared to do nothing | Verification reads security emails already in the database, so it could not succeed until the next monitoring scan (up to 24 h) | Reporting a verifiable action now queues a `verification` scan immediately; the UI says "checking your mailbox now" only when a scan actually started | New assertions in `api.flow.test.js` |

### Files touched

```
scripts/dev.mjs                                  rewritten (Windows spawn)
backend/scripts/setup-env.mjs                    writes THREAT_FEEDS
backend/src/config.js                            threat-feed fallback + 'none' opt-out
backend/src/services/extensionPackage.js         NEW — build/cache/serve the extension
backend/src/routes/protection.js                 2 new download routes
backend/src/services/catalog.js                  4 services + domain_root fallback
backend/src/services/risk.js                     startVerificationScan()
backend/src/routes/core.js                       exposes verification_scan_started
backend/migrations/003_official_link_domain_root.sql   NEW
frontend/src/pages/Settings.jsx                  ExtensionDownload component
frontend/src/pages/Recommendations.jsx           domain_root label, verification copy
frontend/src/components.jsx                      domain_root badge
frontend/src/lib/api.js                          download() surfaces server errors
backend/test/api.protection.test.js              NEW test: package download
backend/test/api.flow.test.js                    verification-scan assertions
backend/test/unit.scoring.test.js                domain_root assertions
```

---

## 2. Still open — what the next session must do

**Task A — the one that matters most.** Nothing in fix #2 or #3 has been seen in a
real browser. Run the app on Windows, load the extension from the new in-app
download, and confirm the toolbar actually reaches red, amber, green and grey.
If the toolbar stays grey, that is the remaining bug and it is the whole Premium
demo.

**Task B.** Confirm complaint (f). The video showed `accounts.google.com` asking
for a passkey, which is Google's own re-auth on `myaccount.google.com`, not
necessarily a FootprintX session problem. Reproduce it and decide which it is
before changing session handling.

**Task C.** The official-link registry still covers only 22 services. Expanding it
is slow because most help centres block automated fetching; every URL in
`catalog.js` was checked against the provider's live help page and one candidate
(Spotify) was caught as a 404 during this session. Do not add a URL without
checking it.

**Task D.** Known-and-unchanged limitations, all pre-existing: real payments are
not implemented (development checkout only), Firefox has never been run, the
Docker image has never been built, and live XposedOrNot/HIBP and SMTP have never
been exercised.

---

## 3. Prompt to start the next session

> I'm continuing work on FootprintX, attached as `footprintx-v2.1.zip`. Read
> `CONTINUE-HERE.md` in the archive root first — it records what was fixed in the
> last session and what is still open.
>
> I am on Windows 11 using PowerShell, with Node 22. The repo lives at
> `E:\japan\footprintx-v2\footprintx`. My Google OAuth credentials are already in
> `backend\.env` and a real Gmail scan works (29 accounts discovered).
>
> Work in this order:
>
> 1. **Verify the extension end to end, because it has never been run in a
>    browser.** Start the app, sign in, go to Settings → Browser extension,
>    download the Chromium build from the new in-app button, load it unpacked,
>    and link it with a link code. Then confirm the toolbar reaches all four
>    states: red on a domain from the threat list, green on a clean domain after
>    a completed lookup, amber on a look-alike, and grey when the API is
>    unreachable. If it stays grey, diagnose and fix that first — it is the
>    entire Premium demo.
> 2. **Confirm the threat dataset loaded.** The server should sync ~390k
>    indicators on first startup. Check Website check returns a real verdict
>    rather than "not enough information".
> 3. **Reproduce the Google re-login complaint** and determine whether it is the
>    FootprintX session expiring or Google's own passkey re-auth on
>    `myaccount.google.com`. Fix it only if it is ours.
> 4. **Expand the official-link registry** in `backend/src/services/catalog.js`
>    beyond the current 22 services, prioritising the services actually in my
>    account list. Verify every URL against the provider's own live help page
>    before adding it — a fabricated link is worse than no link. Services that
>    cannot be verified keep the `domain_root` fallback.
>
> Rules that still apply from the original build prompt: no fabricated findings,
> scores, links or integrations; unknown is never treated as safe; never claim a
> test passed unless you ran it; Premium stays enforced server-side; never
> collect passwords, cookies, OTPs or MFA secrets.
>
> Tell me plainly which of these you verified in a browser and which you only
> reasoned about.

---

## 4. Running it

```powershell
cd E:\japan\footprintx-v2\footprintx
npm install
npm run setup       # only if backend\.env does not exist — it will not overwrite
npm run dev
```

Keep your existing `backend\.env`; it has your Google credentials. The threat
feed turns on by itself even for an `.env` written before this change.

Tests: `npm test` (120 tests), `npm run lint`.
