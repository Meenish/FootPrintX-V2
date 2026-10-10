// Discovered-account inventory: persistence of discovery results, user
// corrections, manual tracking. Re-scans are idempotent: accounts are keyed by
// (user, mailbox connection, service key) and evidence by a keyed hash of the
// source message id, so retries never create duplicates.
import { query, queryOne, transaction } from '../db.js';
import { keyedHash } from '../crypto.js';
import { normalizeHost } from '@footprintx/shared/domain';
import { categoryFor, canonicalServiceDomain, officialServiceName } from './catalog.js';
import { HttpError } from '../http.js';

const CONF_RANK = { low: 0, medium: 1, high: 2 };

export const ACCOUNT_COLUMNS = `id, connection_id, service_key, service_name, service_domain, category, identifier_masked, status, discovery_source,
  confidence, manually_added, user_corrected, dismissed_reason, weak_signal_count, first_observed_at, last_observed_at, last_checked_at,
  mfa_status, mfa_source, mfa_observed_at, exposure_status, exposure_checked_at, account_state, risk_score, risk_upper, risk_level,
  risk_factors, risk_model_version, risk_assessed_at, is_synthetic, created_at, updated_at`;

/** The mailbox provider's own account (e.g. the Google account behind a Gmail connection). */
export function mailboxAccountCandidate(connection) {
  if (connection.provider !== 'gmail' && connection.provider !== 'synthetic') return null;
  return {
    serviceKey: 'google.com',
    serviceName: 'Google Account',
    serviceDomain: 'google.com',
    category: 'identity_email',
    status: 'confirmed',
    confidence: 'high',
    discoverySource: 'mailbox_connection',
    firstObservedAt: new Date(connection.connected_at),
    lastObservedAt: new Date(),
    weakSignalCount: 0,
    mfa: null,
    closedAt: null,
    evidence: [{ kind: 'mailbox_connection', strength: 'strong', observedAt: new Date(connection.connected_at).getTime(), refHash: keyedHash('evidence-ref', `connection:${connection.id}`), auth: 'pass', senderDomain: null }],
  };
}

/**
 * Upserts discovery candidates for one connection inside `tx`.
 * Returns { created, updated, accountIds }.
 */
export async function persistCandidates(tx, connection, candidates, { source }) {
  let created = 0;
  let updated = 0;
  const accountIds = [];
  for (const c of candidates) {
    const existing = await queryOne(
      'SELECT * FROM discovered_accounts WHERE user_id = $1 AND connection_id = $2 AND service_key = $3',
      [connection.user_id, connection.id, c.serviceKey],
      tx
    );
    let accountId;
    if (!existing) {
      const row = await queryOne(
        `INSERT INTO discovered_accounts (user_id, connection_id, service_key, service_name, service_domain, category, identifier_masked, status,
           discovery_source, confidence, weak_signal_count, first_observed_at, last_observed_at, last_checked_at, mfa_status, mfa_source, mfa_observed_at,
           account_state, is_synthetic)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13, now(), $14, $15, $16, $17, $18) RETURNING id`,
        [
          connection.user_id, connection.id, c.serviceKey, c.serviceName, c.serviceDomain, c.category, connection.email_masked, c.status,
          c.discoverySource || source, c.confidence, c.weakSignalCount || 0, c.firstObservedAt, c.lastObservedAt,
          c.mfa ? c.mfa.status : 'unknown', c.mfa ? 'mailbox_evidence' : null, c.mfa ? c.mfa.observedAt : null,
          c.closedAt && c.closedAt >= c.lastObservedAt ? 'closed_evidence' : 'unknown', !!connection.is_synthetic,
        ],
        tx
      );
      accountId = row.id;
      created += 1;
    } else {
      accountId = existing.id;
      const status = existing.status === 'dismissed' ? 'dismissed' : existing.status === 'confirmed' || c.status === 'confirmed' ? 'confirmed' : 'possible';
      const confidence = CONF_RANK[c.confidence] > CONF_RANK[existing.confidence] ? c.confidence : existing.confidence;
      // MFA: newest evidence wins, whether it came from the mailbox or the user.
      let mfa = { status: existing.mfa_status, source: existing.mfa_source, at: existing.mfa_observed_at };
      if (c.mfa && (!mfa.at || new Date(c.mfa.observedAt) > new Date(mfa.at))) mfa = { status: c.mfa.status, source: 'mailbox_evidence', at: c.mfa.observedAt };
      const lastObserved = new Date(Math.max(new Date(existing.last_observed_at || 0).getTime(), new Date(c.lastObservedAt).getTime()));
      let accountState = existing.account_state;
      if (c.closedAt && c.closedAt >= lastObserved && accountState === 'unknown') accountState = 'closed_evidence';
      // New activity after a closure notice means the account was reopened or re-created.
      if (accountState === 'closed_evidence' && c.closedAt && c.lastObservedAt > c.closedAt) accountState = 'unknown';
      await query(
        `UPDATE discovered_accounts SET status = $2, confidence = $3, service_name = CASE WHEN user_corrected THEN service_name ELSE $4 END,
           first_observed_at = LEAST(first_observed_at, $5), last_observed_at = $6, last_checked_at = now(),
           weak_signal_count = GREATEST(weak_signal_count, $7), mfa_status = $8, mfa_source = $9, mfa_observed_at = $10, account_state = $11, updated_at = now()
         WHERE id = $1`,
        [existing.id, status, confidence, c.serviceName, c.firstObservedAt, lastObserved, c.weakSignalCount || 0, mfa.status, mfa.source, mfa.at, accountState],
        tx
      );
      updated += 1;
    }
    accountIds.push(accountId);
    for (const e of c.evidence) {
      await query(
        `INSERT INTO account_evidence (account_id, user_id, connection_id, kind, strength, source, sender_domain, sender_authenticated, source_ref_hash, observed_at, is_synthetic)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (account_id, source_ref_hash) DO NOTHING`,
        [accountId, connection.user_id, connection.id, e.kind, e.strength, source, e.senderDomain, e.auth || 'unknown', e.refHash, new Date(e.observedAt), !!connection.is_synthetic],
        tx
      );
    }
  }
  // Every account on this connection was "checked" by this scan, even if no new evidence arrived.
  await query('UPDATE discovered_accounts SET last_checked_at = now() WHERE connection_id = $1 AND user_id = $2', [connection.id, connection.user_id], tx);
  return { created, updated, accountIds };
}

export async function listAccounts(userId, { status } = {}) {
  return query(
    `SELECT a.${ACCOUNT_COLUMNS.split(',').map((c) => c.trim()).join(', a.')}, c.email_masked AS connection_email, c.status AS connection_status
       FROM discovered_accounts a LEFT JOIN email_connections c ON c.id = a.connection_id
      WHERE a.user_id = $1 AND ($2::text IS NULL OR a.status = $2)
      ORDER BY a.risk_score DESC NULLS LAST, a.service_name`,
    [userId, status || null]
  );
}

export async function getAccount(userId, accountId) {
  const account = await queryOne(
    `SELECT a.*, c.email_masked AS connection_email, c.status AS connection_status, c.provider AS connection_provider
       FROM discovered_accounts a LEFT JOIN email_connections c ON c.id = a.connection_id WHERE a.id = $1 AND a.user_id = $2`,
    [accountId, userId]
  );
  if (!account) return null;
  const evidence = await query(
    `SELECT id, kind, strength, source, sender_domain, sender_authenticated, observed_at, recorded_at, is_synthetic
       FROM account_evidence WHERE account_id = $1 AND user_id = $2 ORDER BY observed_at DESC LIMIT 50`,
    [accountId, userId]
  );
  const breaches = await query(
    `SELECT id, provider, breach_title, breach_domain, breach_date, breach_date_precision, data_classes, password_exposed, provider_verified, first_seen_at, last_seen_at, is_synthetic
       FROM breach_findings WHERE account_id = $1 AND user_id = $2 ORDER BY breach_date DESC NULLS LAST`,
    [accountId, userId]
  );
  const recommendations = await query('SELECT * FROM recommendations WHERE account_id = $1 AND user_id = $2 ORDER BY priority DESC', [accountId, userId]);
  delete account.user_id;
  return { account, evidence, breaches, recommendations };
}

/** Manual tracking. Manual entries are always labelled and never "verified". */
export async function addManualAccount(userId, { serviceName, domain, identifier }) {
  let serviceDomain = null;
  if (domain) {
    const n = normalizeHost(domain);
    if (!n || !n.registrableDomain || n.isLocal) throw new HttpError(400, 'INVALID_DOMAIN', 'Enter a valid website domain, e.g. example.com.');
    serviceDomain = canonicalServiceDomain(n.registrableDomain);
  }
  const name = (serviceName || officialServiceName(serviceDomain) || serviceDomain || '').trim();
  if (!name) throw new HttpError(400, 'NAME_REQUIRED', 'Enter a service name or domain.');
  const key = serviceDomain || `manual:${name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;
  const masked = identifier ? String(identifier).slice(0, 3) + '***' : null;
  const rows = await query(
    `INSERT INTO discovered_accounts (user_id, connection_id, service_key, service_name, service_domain, category, identifier_masked, status,
       discovery_source, confidence, manually_added, user_corrected, first_observed_at, last_observed_at)
     VALUES ($1, NULL, $2, $3, $4, $5, $6, 'confirmed', 'manual', 'high', true, true, now(), now())
     ON CONFLICT (user_id, connection_id, service_key) DO NOTHING RETURNING id`,
    [userId, key, name.slice(0, 80), serviceDomain, categoryFor(serviceDomain), masked]
  );
  if (!rows.length) throw new HttpError(409, 'DUPLICATE', 'You are already tracking this service manually.');
  return rows[0].id;
}

/**
 * User corrections. Dismissed accounts stay dismissed on future scans (they
 * are not re-created), so a false positive only has to be corrected once.
 */
export async function correctAccount(userId, accountId, patch) {
  return transaction(async (tx) => {
    const a = await queryOne('SELECT * FROM discovered_accounts WHERE id = $1 AND user_id = $2 FOR UPDATE', [accountId, userId], tx);
    if (!a) return null;
    const changes = {};
    if (patch.action === 'dismiss') Object.assign(changes, { status: 'dismissed', dismissed_reason: patch.reason || 'not_mine' });
    if (patch.action === 'confirm') Object.assign(changes, { status: 'confirmed', dismissed_reason: null });
    if (patch.action === 'restore') Object.assign(changes, { status: a.confidence === 'low' ? 'possible' : 'confirmed', dismissed_reason: null });
    if (patch.serviceName) Object.assign(changes, { service_name: patch.serviceName.trim().slice(0, 80), user_corrected: true });
    if (patch.mfaStatus) Object.assign(changes, { mfa_status: patch.mfaStatus, mfa_source: patch.mfaStatus === 'unknown' ? null : 'user_reported', mfa_observed_at: patch.mfaStatus === 'unknown' ? null : new Date() });
    if (patch.accountState) Object.assign(changes, { account_state: patch.accountState === 'closed' ? 'closed_user_reported' : 'unknown' });
    if (patch.action || patch.serviceName || patch.mfaStatus || patch.accountState) changes.user_corrected = true;
    const cols = Object.keys(changes);
    if (!cols.length) return a;
    // Column names come from the fixed set above, never from user input.
    const set = cols.map((c, i) => `${c} = $${i + 3}`).join(', ');
    await query(`UPDATE discovered_accounts SET ${set}, updated_at = now() WHERE id = $1 AND user_id = $2`, [accountId, userId, ...cols.map((c) => changes[c])], tx);
    return { ...a, ...changes };
  });
}

/** Removes a manually added record (discovered records are dismissed instead). */
export async function deleteManualAccount(userId, accountId) {
  const rows = await query('DELETE FROM discovered_accounts WHERE id = $1 AND user_id = $2 AND manually_added = true RETURNING id', [accountId, userId]);
  return rows.length > 0;
}
