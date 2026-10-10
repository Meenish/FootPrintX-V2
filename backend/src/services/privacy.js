// Data export and account deletion (docs/PRIVACY.md).
import { query, queryOne, transaction } from '../db.js';
import { keyedHash, decrypt } from '../crypto.js';
import { log } from '../logger.js';
import { connectionRefreshToken, revokeTokenViaProvider } from './connections.js';

/** Everything FootprintX holds about the user, minus secrets (tokens, hashes). */
export async function exportUserData(userId) {
  const q = (sql) => query(sql, [userId]);
  const data = {
    contacts: (await q('SELECT id, content_enc, status, created_at FROM contact_submissions WHERE user_id=$1')).map((r) => ({ id: r.id, ...JSON.parse(decrypt(r.content_enc, `contact:${r.id}`)), status: r.status, createdAt: r.created_at })),
    exportedAt: new Date().toISOString(),
    format: 'footprintx-export-v1',
    user: await queryOne('SELECT id, email, display_name, role, created_at, password_changed_at FROM users WHERE id = $1', [userId]),
    connections: await q('SELECT id, provider, email_masked, scope_mode, status, is_synthetic, connected_at, disconnected_at, token_revoke_result, last_scan_at, last_successful_scan_at FROM email_connections WHERE user_id = $1'),
    accounts: await q('SELECT id, connection_id, service_name, service_domain, category, status, discovery_source, confidence, manually_added, user_corrected, dismissed_reason, first_observed_at, last_observed_at, mfa_status, mfa_source, exposure_status, account_state, risk_score, risk_level, risk_model_version, is_synthetic FROM discovered_accounts WHERE user_id = $1'),
    evidence: await q('SELECT account_id, kind, strength, source, sender_domain, sender_authenticated, observed_at, is_synthetic FROM account_evidence WHERE user_id = $1'),
    breachChecks: await q('SELECT connection_id, provider, status, result_count, checked_at FROM breach_checks WHERE user_id = $1'),
    breachFindings: await q('SELECT connection_id, account_id, provider, breach_title, breach_domain, breach_date, data_classes, password_exposed, first_seen_at, last_seen_at FROM breach_findings WHERE user_id = $1'),
    dasiSnapshots: await q('SELECT model_version, score, upper_bound, level, confidence, trigger, delta, change_reasons, created_at FROM dasi_snapshots WHERE user_id = $1 ORDER BY created_at'),
    recommendations: await q('SELECT account_id, action_type, severity, title, status, reported_at, verified_at, dismissed_reason, created_at FROM recommendations WHERE user_id = $1'),
    remediationEvents: await q('SELECT recommendation_id, from_status, to_status, actor, note, created_at FROM remediation_events WHERE user_id = $1'),
    alerts: await q('SELECT kind, severity, title, body, domain, status, created_at FROM alerts WHERE user_id = $1'),
    notificationPreferences: await queryOne('SELECT security_alerts_email, remediation_reminders_email, periodic_summary_email, product_updates_email FROM notification_preferences WHERE user_id = $1', [userId]),
    notificationDeliveries: await q('SELECT category, status, reason, created_at FROM notification_deliveries WHERE user_id = $1'),
    subscription: await queryOne('SELECT plan, status, provider, current_period_start, current_period_end, cancel_at_period_end FROM subscriptions WHERE user_id = $1', [userId]),
    extensionEvents: await q('SELECT type, domain, status, reason_codes, occurred_at FROM extension_events WHERE user_id = $1'),
    websiteChecks: await q('SELECT domain, status, reasons, checked_at FROM domain_checks WHERE user_id = $1'),
    consents: await q('SELECT kind, provider, policy_version, granted_at, revoked_at FROM consents WHERE user_id = $1'),
    auditTrail: await q('SELECT event, created_at FROM audit_events WHERE user_id = $1 ORDER BY created_at'),
  };
  await query("INSERT INTO privacy_requests (user_ref_hash, kind, status) VALUES ($1, 'export', 'completed')", [keyedHash('user-ref', userId)]);
  return data;
}

/**
 * Deletes the user. Google tokens are revoked first (best effort, outcome
 * recorded). Rows cascade from users; audit events keep the event name and
 * time with user_id set to NULL. Backups age out per the documented
 * retention window; deletion from existing backups is not immediate.
 */
export async function deleteUserAccount(userId) {
  const conns = await query("SELECT * FROM email_connections WHERE user_id = $1 AND provider = 'gmail' AND token_enc IS NOT NULL", [userId]);
  const revocations = [];
  for (const c of conns) {
    try {
      revocations.push(await revokeTokenViaProvider(connectionRefreshToken(c)));
    } catch (err) {
      log.warn('token revocation during deletion failed', { err });
      revocations.push('failed');
    }
  }
  const ref = keyedHash('user-ref', userId);
  await transaction(async (tx) => {
    await query("INSERT INTO audit_events (user_id, event, detail) VALUES ($1, 'account_deleted', $2::jsonb)", [userId, JSON.stringify({ revocations })], tx);
    await query('DELETE FROM users WHERE id = $1', [userId], tx);
    await query("INSERT INTO privacy_requests (user_ref_hash, kind, status, detail) VALUES ($1, 'deletion', 'completed', $2::jsonb)", [ref, JSON.stringify({ revocations })], tx);
  });
  return { revocations };
}
