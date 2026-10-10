// Plans and entitlements. Premium is enforced here, on the server, for every
// Premium API; nothing the browser or extension stores can grant it.
//
// BILLING_MODE:
//   disabled     — no checkout; the Upgrade page explains billing is not yet
//                  available. (Production default until a payment provider is wired.)
//   development  — a clearly labelled test checkout grants Premium for
//                  DEV_PREMIUM_DAYS without any payment. Rejected in production.
// Production billing (Stripe/Razorpay) plugs in by writing the same
// `subscriptions` row from a signature-verified webhook (docs/PLANS.md).
import { query, queryOne } from '../db.js';
import { getConfig } from '../config.js';
import { HttpError } from '../http.js';

const DAY = 864e5;
const PAST_DUE_GRACE_MS = 3 * DAY;

export const FEATURES = Object.freeze({
  free: {
    activeBrowserProtection: false,
    automaticDomainChecks: false,
    extensionEventSync: false,
    threatUpdateAlerts: false,
    advancedHistoryDays: 30,
  },
  premium: {
    activeBrowserProtection: true,
    automaticDomainChecks: true,
    extensionEventSync: true,
    threatUpdateAlerts: true,
    advancedHistoryDays: 365,
  },
});

export function planCatalog() {
  const b = getConfig().billing;
  return {
    billingMode: b.mode,
    checkoutAvailable: b.mode === 'development',
    currency: b.currency,
    premium: {
      priceMinor: b.priceMinor,
      interval: b.interval,
      priceStatus: b.priceStatus, // "proposed" until pricing is approved
      display: `${new Intl.NumberFormat('en-IN', { style: 'currency', currency: b.currency, maximumFractionDigits: 2 }).format(b.priceMinor / 100)}/${b.interval}`,
    },
    developmentNotice: b.mode === 'development' ? `Development billing: checkout grants Premium for ${b.devPremiumDays} days without any payment. No money is taken.` : null,
  };
}

/** Server-side entitlement. The only source of truth for Premium. */
export async function getEntitlement(userId) {
  const sub = await queryOne('SELECT * FROM subscriptions WHERE user_id = $1', [userId]);
  const now = Date.now();
  let premium = false;
  let state = 'none';
  if (sub) {
    const end = new Date(sub.current_period_end).getTime();
    if ((sub.status === 'active' || sub.status === 'trialing') && end > now) {
      premium = true;
      state = sub.cancel_at_period_end ? 'canceling' : sub.status;
    } else if (sub.status === 'past_due' && end + PAST_DUE_GRACE_MS > now) {
      premium = true;
      state = 'past_due_grace';
    } else {
      state = sub.status === 'canceled' ? 'canceled' : 'expired';
    }
  }
  const plan = premium ? 'premium' : 'free';
  return {
    plan,
    state,
    features: FEATURES[plan],
    subscription: sub
      ? {
          status: sub.status,
          provider: sub.provider,
          isDevelopment: sub.provider === 'development',
          currentPeriodStart: sub.current_period_start,
          currentPeriodEnd: sub.current_period_end,
          cancelAtPeriodEnd: sub.cancel_at_period_end,
          canceledAt: sub.canceled_at,
        }
      : null,
    checkedAt: new Date().toISOString(),
  };
}

export async function requirePremium(userId) {
  const ent = await getEntitlement(userId);
  if (ent.plan !== 'premium') {
    throw new HttpError(402, ent.state === 'expired' || ent.state === 'canceled' ? 'PREMIUM_EXPIRED' : 'PREMIUM_REQUIRED', ent.state === 'expired' || ent.state === 'canceled' ? 'Your Premium subscription has ended. Active browser protection is paused.' : 'This feature is part of FootprintX Premium.');
  }
  return ent;
}

/** Development-only checkout. Never claims a payment happened. */
export async function devCheckout(userId) {
  const b = getConfig().billing;
  if (b.mode !== 'development' || getConfig().isProduction) throw new HttpError(503, 'BILLING_NOT_CONFIGURED', 'Online payment is not available yet. Premium cannot be purchased on this server.');
  const start = new Date();
  const end = new Date(Date.now() + b.devPremiumDays * DAY);
  await query(
    `INSERT INTO subscriptions (user_id, plan, status, provider, current_period_start, current_period_end) VALUES ($1, 'premium', 'active', 'development', $2, $3)
     ON CONFLICT (user_id) DO UPDATE SET status = 'active', provider = 'development', current_period_start = $2, current_period_end = $3, cancel_at_period_end = false, canceled_at = NULL, updated_at = now()`,
    [userId, start, end]
  );
  return getEntitlement(userId);
}

export async function cancelSubscription(userId) {
  const sub = await queryOne('SELECT * FROM subscriptions WHERE user_id = $1', [userId]);
  if (!sub || !['active', 'trialing', 'past_due'].includes(sub.status)) throw new HttpError(409, 'NO_ACTIVE_SUBSCRIPTION', 'There is no active subscription to cancel.');
  if (sub.provider !== 'development') throw new HttpError(503, 'BILLING_NOT_CONFIGURED', 'Cancellation must be handled by the billing provider, which is not configured.');
  await query('UPDATE subscriptions SET cancel_at_period_end = true, canceled_at = now(), updated_at = now() WHERE user_id = $1', [userId]);
  return getEntitlement(userId);
}

export async function resumeSubscription(userId) {
  const sub = await queryOne('SELECT * FROM subscriptions WHERE user_id=$1', [userId]);
  if (!sub || sub.provider !== 'development' || getConfig().billing.mode !== 'development' || getConfig().isProduction) throw new HttpError(409, 'BILLING_NOT_CONFIGURED', 'Purchases and renewals are disabled.');
  await query("UPDATE subscriptions SET cancel_at_period_end = false, canceled_at = NULL, updated_at = now() WHERE user_id = $1 AND status IN ('active','trialing')", [userId]);
  return getEntitlement(userId);
}

/** Development helper to exercise the downgrade path immediately. */
export async function devExpire(userId) {
  if (getConfig().billing.mode !== 'development' || getConfig().isProduction) throw new HttpError(404, 'NOT_FOUND', 'Not available.');
  await query(`UPDATE subscriptions SET status = 'expired', current_period_end = now() - interval '1 second', updated_at = now() WHERE user_id = $1`, [userId]);
  return getEntitlement(userId);
}

/** Maintenance: mark lapsed subscriptions expired (data is never deleted on downgrade). */
export async function expireLapsedSubscriptions() {
  const rows = await query(
    `UPDATE subscriptions SET status = CASE WHEN cancel_at_period_end THEN 'canceled' ELSE 'expired' END, updated_at = now()
      WHERE (status IN ('active','trialing') AND current_period_end < now())
         OR (status = 'past_due' AND current_period_end < now() - interval '3 days')
      RETURNING user_id`
  );
  return rows.map((r) => r.user_id);
}
