# DASI — Digital Attack Surface Index (model `dasi-2.0.0`)

> DASI is **FootprintX's own index**. It is not an industry standard, and it isn't comparable to scores from other products. It summarizes the evidence FootprintX has. It cannot see accounts or risks it has no evidence for.

- **Implementation:** `backend/src/services/dasi.js` (pure functions)
- **Pipeline:** `backend/src/services/risk.js`
- **Tests:** `backend/test/unit.scoring.test.js`, `backend/test/api.flow.test.js`

Any change to the weights, thresholds or aggregation below must also bump `MODEL_VERSION` and update this file. Historical snapshots keep the model version they were computed with, so they stay interpretable.

## Range and direction

- **Scale:** 0–100. Higher means more observed risk.
- **Not assessed:** `score = null` until at least one scan has completed or the user has added an account manually. It is never shown as 0.
- **Upper bound:** what the score would be if every unknown factor turned out unfavourable. The UI shows the band between the score and the upper bound.
- **Confidence:** how complete the underlying evidence is (see below). This is separate from severity.

## Account score

Only accounts with status `confirmed` are scored. Possible and dismissed accounts are excluded. Closed accounts (user-reported or shown by a closure email) score 0.

```
account_score = clamp(round( (Σ points_i × confidence_i × remediation_i × mfa_dampening_i) × impact ), 0, 100)
```

| Factor (code) | Points | Evidence | Confidence |
|---|---|---|---|
| `BASE_EXPOSURE` | 3 | The account exists (each account is attack surface) | high |
| `CREDENTIAL_EXPOSURE_PASSWORD` | 40, +5 per further breach, max +10 | Breach listing whose data includes passwords. Password *hints* don't count. | high if the provider verified the breach, otherwise medium |
| `CREDENTIAL_EXPOSURE` | 15, +5 per further breach, max +10 | Breach listing without passwords | as above |
| `RECENT_SECURITY_ALERT` | 30 (≤30 days), 20 (≤90 days), 8 (≤365 days), 0 after that | Security-alert email from the service's own domain | high if the sender passed DMARC/DKIM, otherwise medium |
| `MFA_DISABLED` | 12 | Latest evidence says two-step verification is off (an email, or the user's own report) | medium |
| `DORMANT` | 6 | No mailbox evidence for over 2 years. Inactivity is *not* confirmed by this. | low |
| `THREAT_LISTED` | 35 | Service domain exactly matches an active threat-dataset entry | medium |

**Confidence multipliers:** high ×1.0, medium ×0.7, low ×0.5.

**Impact multiplier by category** (from the service catalog):

| Category | Multiplier |
|---|---|
| Email & identity | ×1.3 |
| Finance & payments | ×1.3 |
| Cloud storage | ×1.2 |
| Developer | ×1.15 |
| Work, social, shopping | ×1.1 |
| Other | ×1.0 |

### Correlated evidence (no double counting)

- Multiple breaches of one account produce a single credential factor: the maximum base, plus a small capped increment. They are never summed as independent risks.
- Recommendations are derived *from* factors and are not scored themselves, so "unresolved recommendation" is not a second penalty for the same evidence.
- Login notices ("new sign-in on Linux") are evidence that the account is active. They are not alerts and add no risk.

### Remediation (only the *current* component changes)

These apply to the credential component (password change) and the alert component (session review), and only when the remediation happened *after* the evidence it addresses:

| Remediation state | Multiplier |
|---|---|
| Verified (a "password changed" security email from the service, observed after the breach) | ×0.2 |
| User-reported (`user_reported`, `verification_pending`, `unable_to_verify`) | ×0.5 |

- If the breach date is year-precision, the change must be after the end of that year.
- The breach record itself is never removed. The factor stays visible with a "reduced because…" note.
- MFA dampening applies to the credential component when two-step verification is known to be on: ×0.6 from email evidence, ×0.8 if user-reported.
- A newer breach or a newer alert re-opens the matching recommendation.

### Unknowns

Unknown MFA status adds **0 to the score** but adds the full MFA penalty (12 × 0.7 × impact) to the **upper bound**. It is also listed in the account's `unknowns`.

"Breach exposure not checked" is listed as an unknown and lowers confidence. It doesn't widen the bound, because a breach's size can't be estimated without a check.

### Account levels

| Level | Score |
|---|---|
| Critical | ≥ 70 |
| High | ≥ 45 |
| Medium | ≥ 20 |
| Low | < 20 |

## Overall DASI

Account scores are sorted from highest to lowest (s₁ ≥ s₂ ≥ …):

```
core    = Σ s_i × 0.5^(i−1)            (geometric decay)
breadth = min(15, 2.5 × ln(1 + n))     (n = number of scored accounts)
DASI    = clamp(round(0.6 × core + breadth), 0, 100)
upper   = same formula applied to the account upper bounds
```

**Rationale:**

- The worst account dominates, so one serious problem is visible.
- Each additional bad account adds progressively less, which avoids runaway scores.
- Many harmless accounts add only a little through the breadth term. The number of accounts is real attack surface, but it shouldn't masquerade as danger.

**Worked examples** (from the unit tests and the synthetic fixture):

- A single identity account with an unremediated password breach: account score ≈ 56, DASI ≈ 35 (Guarded).
- The synthetic demo mailbox: 9 scored accounts, 4 critical findings, DASI 59 (Elevated), upper bound 69, medium confidence.

| DASI level | Score |
|---|---|
| Severe | ≥ 80 |
| High | ≥ 60 |
| Elevated | ≥ 40 |
| Guarded | ≥ 20 |
| Low | < 20 |

## Critical findings (shown regardless of the aggregate)

- `UNREMEDIATED_PASSWORD_EXPOSURE`: a password-exposing breach with no change recorded since it.
- `RECENT_ALERT_UNREVIEWED`: a security alert in the last 30 days that hasn't been reviewed.
- `MFA_OFF_HIGH_IMPACT`: two-step verification off on an identity or finance account.
- `THREAT_LISTED`: the service domain is on a threat list.

Each new critical finding creates one in-app alert. At most three of these are emailed per recalculation, and all emails are subject to the user's preferences and the daily cap.

## Confidence and coverage

| Confidence | Requires |
|---|---|
| High | Every active mailbox scanned successfully in the last 30 days, the latest scans complete (not partial), every mailbox breach-checked in the last 30 days, and MFA known for ≥ 50% of accounts |
| Medium | Every mailbox scanned recently, plus (breach-checked **or** MFA known for ≥ 25%) |
| Low | Anything less |

The UI lists the specific gaps (for example "breach exposure not checked recently") so the user knows how to improve confidence.

## Recalculation and history

**Triggers** (stored on each snapshot): `scan`, `breach_check`, `remediation_update`, `user_correction`, `threat_update`, `connection_change`, `verification_deadline`, `model_change`, `initial`, `manual`.

A new snapshot is written only when something changed: the score, upper bound or confidence, any account's score or factor set, or the model version. Each snapshot stores:

- `previous_score` and `delta`
- `change_reasons`: the largest per-account movements, with the factors added or removed
- `contributors`: per account, its score and factor contributions
- `coverage`, `critical_findings`, `model_version`

If the stored model version differs from the running one, the next read recalculates automatically (`trigger = model_change`) and the change reason says so.

## Never collected or inferred

- Passwords and password strength. FootprintX cannot know them and never asks.
- Password reuse. This is never guessed. Recommendations say "if you reused it".
- MFA secrets, one-time codes or recovery codes.
