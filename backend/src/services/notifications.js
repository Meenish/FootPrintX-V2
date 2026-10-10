// In-app alerts and optional email notifications.
//
//  * In-app alerts are always created (they are the source of truth for the
//    dashboard) and de-duplicated by (user, dedup_key). The dedup key encodes
//    the subject AND its severity, so the same unchanged finding never alerts
//    twice, while a material change (e.g. severity rising) does.
//  * Email is optional and per category (security alerts, remediation
//    reminders, periodic summaries, product updates). Essential messages
//    (password reset) are not optional and are sent regardless.
//  * Every email attempt is recorded in notification_deliveries with its
//    status and a reason code — never the message content.
//  * A per-user daily cap stops a burst of findings from flooding the inbox;
//    capped items still appear in-app and in the next summary.
import nodemailer from 'nodemailer';
import { getConfig } from '../config.js';
import { query, queryOne } from '../db.js';
import { keyedHash, timingSafeEqualHex } from '../crypto.js';
import { log } from '../logger.js';

export const EMAIL_CATEGORIES = Object.freeze({
  security_alerts: 'security_alerts_email',
  remediation_reminders: 'remediation_reminders_email',
  periodic_summary: 'periodic_summary_email',
  product_updates: 'product_updates_email',
});

let transportOverride = null;
/** Test hook: replace the SMTP transport (e.g. with a capturing stub). */
export function setMailTransport(t) {
  transportOverride = t;
}

export function mailTransport() {
  if (transportOverride) return transportOverride;
  const s = getConfig().smtp;
  if (!s.configured) return null;
  return nodemailer.createTransport({
    host: s.host,
    port: s.port,
    secure: s.secure,
    auth: s.user ? { user: s.user, pass: s.password } : undefined,
    connectionTimeout: 10000,
    socketTimeout: 15000,
  });
}

export function unsubscribeToken(userId, category) {
  return keyedHash('unsubscribe', `${userId}:${category}`);
}
export function verifyUnsubscribeToken(userId, category, token) {
  return timingSafeEqualHex(unsubscribeToken(userId, category), String(token || ''));
}

export async function getPreferences(userId) {
  await query('INSERT INTO notification_preferences (user_id) VALUES ($1) ON CONFLICT DO NOTHING', [userId]);
  return queryOne('SELECT security_alerts_email, remediation_reminders_email, periodic_summary_email, product_updates_email, updated_at FROM notification_preferences WHERE user_id = $1', [userId]);
}

export async function updatePreferences(userId, changes) {
  await getPreferences(userId);
  const cols = Object.entries(changes).filter(([k, v]) => Object.values(EMAIL_CATEGORIES).includes(k) && typeof v === 'boolean');
  for (const [col, value] of cols) {
    // Column names come from the fixed allow-list above, never from input.
    await query(`UPDATE notification_preferences SET ${col} = $2, updated_at = now() WHERE user_id = $1`, [userId, value]);
  }
  return getPreferences(userId);
}

async function recordDelivery(userId, category, dedupKey, status, reason) {
  const rows = await query(
    `INSERT INTO notification_deliveries (user_id, category, dedup_key, status, reason) VALUES ($1, $2, $3, $4, $5)
     ON CONFLICT (user_id, channel, dedup_key) DO NOTHING RETURNING id`,
    [userId, category, dedupKey, status, reason]
  );
  return rows.length > 0;
}

/**
 * Sends an email if the user's preferences allow it and it has not been sent
 * before (dedupKey). Returns { status, reason }.
 */
export async function sendEmail(userId, { category, dedupKey, subject, text, essential = false }) {
  const user = await queryOne('SELECT id, email FROM users WHERE id = $1', [userId]);
  if (!user) return { status: 'skipped', reason: 'no_user' };
  const already = await queryOne('SELECT status FROM notification_deliveries WHERE user_id = $1 AND channel = $2 AND dedup_key = $3', [userId, 'email', dedupKey]);
  if (already) return { status: 'skipped', reason: 'duplicate' };

  if (!essential) {
    const prefs = await getPreferences(userId);
    const col = EMAIL_CATEGORIES[category];
    if (!col || !prefs[col]) {
      await recordDelivery(userId, category, dedupKey, 'skipped', 'preference_off');
      return { status: 'skipped', reason: 'preference_off' };
    }
    if (category === 'security_alerts') {
      const recent = await queryOne(
        `SELECT count(*)::int AS n FROM notification_deliveries WHERE user_id = $1 AND category = 'security_alerts' AND status = 'sent' AND created_at > now() - interval '24 hours'`,
        [userId]
      );
      if (recent.n >= getConfig().smtp.securityEmailsPerDay) {
        await recordDelivery(userId, category, dedupKey, 'skipped', 'daily_cap');
        return { status: 'skipped', reason: 'daily_cap' };
      }
    }
  }

  const t = mailTransport();
  if (!t) {
    await recordDelivery(userId, category, dedupKey, 'skipped', 'smtp_not_configured');
    return { status: 'skipped', reason: 'smtp_not_configured' };
  }
  const cfg = getConfig();
  const unsub = essential ? null : `${cfg.appUrl}/unsubscribe?u=${userId}&c=${category}&t=${unsubscribeToken(userId, category)}`;
  const footer = essential
    ? '\n\nThis is an essential account message and cannot be turned off.'
    : `\n\nYou are receiving this because "${category.replace('_', ' ')}" emails are on in FootprintX settings.\nTurn these emails off: ${unsub}`;
  // Claim before talking to SMTP so simultaneous requests cannot send the same
  // notification twice. A crash leaves an explicit failed/pending record;
  // SMTP has no universal idempotency contract, so we never replay ambiguity.
  if (!(await recordDelivery(userId, category, dedupKey, 'failed', 'delivery_pending'))) return { status: 'skipped', reason: 'duplicate' };
  const finish = (status, reason) => query('UPDATE notification_deliveries SET status=$4, reason=$5 WHERE user_id=$1 AND category=$2 AND dedup_key=$3', [userId, category, dedupKey, status, reason]);
  try {
    const message = {
      from: cfg.smtp.from,
      to: user.email,
      subject,
      text: `${text}${footer}`,
      headers: unsub ? { 'List-Unsubscribe': `<${unsub}>` } : undefined,
    };
    for (let attempt = 0; ; attempt++) {
      try {
        const result = await t.sendMail(message);
        if (!result?.accepted?.length || result.rejected?.length) throw Object.assign(new Error('Recipient not accepted'), { code: 'RECIPIENT_REJECTED' });
        break;
      } catch (err) {
        // These failures occur before SMTP can accept a message. Do not retry
        // timeouts or lost connections after DATA: acceptance may be ambiguous.
        const safeToRetry = ['ECONNREFUSED','ENOTFOUND','EAI_AGAIN'].includes(err.code);
        if (!safeToRetry || attempt >= 2) throw err;
        await new Promise((resolve) => setTimeout(resolve, cfg.isTest ? 0 : 500 * (2 ** attempt)));
      }
    }
    await finish('sent', null);
    return { status: 'sent' };
  } catch (err) {
    log.warn('email delivery failed', { category, err });
    await finish('failed', String(err.code || 'send_failed').slice(0, 40));
    return { status: 'failed', reason: 'send_failed' };
  }
}

/**
 * Creates an in-app alert (idempotent per dedupKey). Emails high-severity
 * alerts when the user has security emails on. Returns the alert row, or null
 * if an identical alert already existed.
 */
export async function createAlert(userId, { kind, severity, title, body, accountId = null, domain = null, dedupKey, email = true }) {
  const key = `${dedupKey}:${severity}`;
  const rows = await query(
    `INSERT INTO alerts (user_id, kind, severity, title, body, account_id, domain, dedup_key)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
     ON CONFLICT (user_id, dedup_key) DO NOTHING RETURNING *`,
    [userId, kind, severity, title, body, accountId, domain, key]
  );
  const alert = rows[0] || null;
  if (alert && email && (severity === 'critical' || severity === 'high')) {
    const cfg = getConfig();
    await sendEmail(userId, {
      category: 'security_alerts',
      dedupKey: `alert:${key}`,
      subject: `[FootprintX] ${title}`,
      text: `${body}\n\nReview it in FootprintX: ${cfg.appUrl}/activity\n\nFootprintX will never ask for your passwords, one-time codes or recovery codes.`,
    });
  }
  return alert;
}

export async function listAlerts(userId, { limit = 50, status } = {}) {
  return query(
    `SELECT id, kind, severity, title, body, account_id, domain, status, created_at FROM alerts
      WHERE user_id = $1 AND ($2::text IS NULL OR status = $2) ORDER BY created_at DESC LIMIT $3`,
    [userId, status || null, limit]
  );
}

export async function setAlertStatus(userId, alertId, status) {
  return queryOne('UPDATE alerts SET status = $3, updated_at = now() WHERE id = $1 AND user_id = $2 RETURNING id, status', [alertId, userId, status]);
}
