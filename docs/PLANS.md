# Free and Premium

Free helps you understand and reduce the risk you already have. Premium adds proactive browsing protection. Basic discovery has no artificial limits on mailbox count or scan count on any plan.

| Feature | Free | Premium | Enforced by |
|---|---|---|---|
| Multiple Gmail connections, unlimited rescans (rate limits only) | ✓ | ✓ | — |
| Account inventory with evidence, corrections, manual tracking | ✓ | ✓ | — |
| Breach checks (consent-based) | ✓ | ✓ | — |
| DASI, explanations, history, recommendations, remediation and verification | ✓ | ✓ | — |
| In-app alerts, optional email alerts | ✓ | ✓ | — |
| On-demand website check (web app, or "Check this site once" in the extension) | ✓ | ✓ | — |
| Data export, deletion, privacy controls | ✓ | ✓ | — |
| Activity / security-event history | 30 days | 365 days | `GET /activity` caps `days` using the server-side entitlement |
| **Automatic checks of every site opened in the extension** | — | ✓ | `POST /extension/lookup` returns `402` without Premium |
| **Independent extension account association** | — | ✓ | `POST /extension/account-awareness` requires server-verified Premium; current login remains unavailable |
| **Known-threat warnings and amber look-alike warnings in context** | — | ✓ | as above (the extension only checks after a successful lookup) |
| **Re-check of cached results when threat data updates; threat-update alerts** | — | ✓ | the extension's periodic refresh uses the same Premium lookup API |
| **Opt-in sync of warnings to the dashboard** | — | ✓ | `PUT /extension/settings` and `POST /extension/events` require Premium plus per-session opt-in |

Premium means **proactive protection against known and look-alike threats while the extension is installed, enabled and online**. It is not complete protection: unlisted malicious sites can get through, and a green result means only "no known threat found by the available checks".

## Pricing

All pricing is configuration (`.env`). Nothing about price is hard-coded.

| Variable | Default | Meaning |
|---|---|---|
| `PREMIUM_PRICE_MINOR` | `14900` (₹149.00) | Price in minor units |
| `PREMIUM_CURRENCY` | `INR` | ISO currency code |
| `PREMIUM_INTERVAL` | `month` | Billing interval |
| `PREMIUM_PRICE_STATUS` | `proposed` | While `proposed`, the UI labels the price "proposed" |

## Billing modes

| `BILLING_MODE` | Behaviour |
|---|---|
| `disabled` (default) | The Plans page says payment isn't available yet. `dev-checkout` returns `503 BILLING_NOT_CONFIGURED`. Nothing is charged and no subscription can be created. |
| `development` | A labelled test checkout grants Premium for `DEV_PREMIUM_DAYS` with `provider = 'development'`. The response includes `paymentProcessed: false`, and the UI says "No payment was taken". Includes cancel, resume and "end now" (to test the downgrade). **Rejected when `NODE_ENV=production`.** |

### Connecting a real payment provider (not implemented)

1. Create a checkout session with Stripe or Razorpay from a new `POST /billing/checkout`.
2. Add a webhook endpoint that verifies the provider signature and upserts `subscriptions` (`provider`, `provider_ref`, `status`, `current_period_start` / `current_period_end`, `cancel_at_period_end`).
3. Map provider states: `active` / `trialing` → `active` / `trialing`; `past_due` → `past_due` (3-day grace); `canceled` / `unpaid` → `canceled`.
4. Everything else, including entitlement checks, expiry and downgrade alerts, already keys off the `subscriptions` row.

## Downgrade and expiry

- The hourly maintenance job marks lapsed subscriptions `expired`, or `canceled` if cancellation was scheduled, and creates an in-app alert ("Premium has ended…").
- No data is deleted on downgrade.
- The extension shows "Premium ended", which is distinct from a temporary outage ("could not confirm your subscription").
- Automatic checks stop because the server refuses lookups.

## Costs and quotas to consider

| Service | Limits and cost |
|---|---|
| Gmail API | Per-user quota of 250 units/second; `messages.get` costs 5 units. The scanner paces itself to about 40 messages per second. Restricted-scope apps need Google verification and a CASA security assessment before public launch, which costs time and money. |
| XposedOrNot (free) | 25 lookups/hour and 100/day **per server IP**. Fine for a demo; a product needs the paid plan or HIBP. |
| Have I Been Pwned | Paid API key, rate-limited by subscription tier. |
| Threat feed | Phishing.Database is free from GitHub, about 11 MB and 390k hosts. A full sync takes about 18 s on PostgreSQL. |
