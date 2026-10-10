// Hourly maintenance: retention enforcement, expiry, verification deadlines.
// Retention periods are documented in docs/PRIVACY.md; change both together.
import { query } from '../db.js';
import { log } from '../logger.js';
import { expireLapsedSubscriptions } from './billing.js';
import { recalculate } from './risk.js';
import { createAlert } from './notifications.js';

export const RETENTION = Object.freeze({
  contactDays: 90,
  expiredSessionsDays: 7,
  extensionEventsDays: 365,
  domainChecksDays: 90,
  scanJobsDays: 180,
  notificationDeliveriesDays: 180,
  auditEventsDays: 365,
  threatFeedRunsDays: 90,
  falsePositiveReportsDays: 365,
});

export async function runMaintenance() {
  const r = RETENTION;
  const purge = async (sql, days) => (await query(sql, [days])).length;
  const counts = {
    contacts: await purge('DELETE FROM contact_submissions WHERE created_at < now() - make_interval(days => $1) RETURNING id', r.contactDays),
    sessions: await purge(`DELETE FROM sessions WHERE (revoked_at IS NOT NULL OR expires_at < now() OR idle_expires_at < now()) AND last_seen_at < now() - make_interval(days => $1) RETURNING id`, r.expiredSessionsDays),
    oauthStates: (await query('DELETE FROM oauth_states WHERE expires_at < now() RETURNING state_hash')).length,
    linkCodes: (await query('DELETE FROM extension_link_codes WHERE expires_at < now() RETURNING code_hash')).length,
    passwordResets: (await query("DELETE FROM password_reset_tokens WHERE expires_at < now() - interval '1 day' RETURNING id")).length,
    extensionEvents: await purge('DELETE FROM extension_events WHERE occurred_at < now() - make_interval(days => $1) RETURNING id', r.extensionEventsDays),
    domainChecks: await purge('DELETE FROM domain_checks WHERE checked_at < now() - make_interval(days => $1) RETURNING id', r.domainChecksDays),
    scanJobs: await purge("DELETE FROM scan_jobs WHERE status NOT IN ('queued','running') AND created_at < now() - make_interval(days => $1) RETURNING id", r.scanJobsDays),
    deliveries: await purge('DELETE FROM notification_deliveries WHERE created_at < now() - make_interval(days => $1) RETURNING id', r.notificationDeliveriesDays),
    audit: await purge('DELETE FROM audit_events WHERE created_at < now() - make_interval(days => $1) RETURNING id', r.auditEventsDays),
    feedRuns: await purge('DELETE FROM threat_feed_runs WHERE started_at < now() - make_interval(days => $1) RETURNING id', r.threatFeedRunsDays),
    fpReports: await purge('DELETE FROM false_positive_reports WHERE created_at < now() - make_interval(days => $1) RETURNING id', r.falsePositiveReportsDays),
  };

  // Lapsed subscriptions → downgrade (data kept) and tell the user in-app.
  for (const userId of await expireLapsedSubscriptions()) {
    await createAlert(userId, {
      kind: 'subscription',
      severity: 'info',
      title: 'Premium has ended',
      body: 'Active browser protection is paused. Your accounts, history and settings are kept, and all Free features continue.',
      dedupKey: `premium_ended:${new Date().toISOString().slice(0, 10)}`,
      email: false,
    });
  }

  // Verification windows that elapsed → recompute (moves them to unable_to_verify).
  const due = await query("SELECT DISTINCT user_id FROM recommendations WHERE status = 'verification_pending' AND verification_deadline < now()");
  for (const { user_id: userId } of due) await recalculate(userId, 'verification_deadline').catch((err) => log.error('deadline recalculation failed', { err }));
  log.info('maintenance completed', counts);
  return counts;
}
