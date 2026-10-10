// Browser-extension account linking, status, and opt-in security-event sync.
//
// Linking: the signed-in web app creates a short-lived one-time code; the
// user types it into the extension, which exchanges it for an extension
// session token (Bearer). The token is scoped to extension endpoints only and
// can be revoked from Settings. No password ever passes through the extension.
import { query, queryOne } from '../db.js';
import { humanCode, sha256 } from '../crypto.js';
import { normalizeHost, maskEmail } from '@footprintx/shared/domain';
import { HttpError } from '../http.js';
import { createSession, revokeSession } from './auth.js';
import { getEntitlement, requirePremium } from './billing.js';
import { datasetStatus } from './reputation.js';
import { createAlert } from './notifications.js';

const CODE_TTL_MS = 10 * 60e3;
const normalizeCode = (c) => String(c || '').toUpperCase().replace(/[^A-Z0-9]/g, '');

export async function createLinkCode(userId) {
  const code = humanCode();
  await query('DELETE FROM extension_link_codes WHERE user_id = $1 OR expires_at < now()', [userId]);
  await query('INSERT INTO extension_link_codes (code_hash, user_id, expires_at) VALUES ($1, $2, $3)', [sha256(normalizeCode(code)), userId, new Date(Date.now() + CODE_TTL_MS)]);
  return { code, expiresAt: new Date(Date.now() + CODE_TTL_MS).toISOString() };
}

export async function linkExtension(code, label) {
  const row = await queryOne(
    'UPDATE extension_link_codes SET used_at = now() WHERE code_hash = $1 AND used_at IS NULL AND expires_at > now() RETURNING user_id',
    [sha256(normalizeCode(code))]
  );
  if (!row) throw new HttpError(400, 'LINK_CODE_INVALID', 'This code is invalid, expired or already used. Create a new code in FootprintX Settings → Browser extension.');
  const { token, session } = await createSession(row.user_id, 'extension', { label: String(label || 'Browser extension').slice(0, 60) });
  return { token, sessionId: session.id, userId: row.user_id, expiresAt: session.expires_at };
}

export async function extensionStatus(auth) {
  const [entitlement, dataset] = await Promise.all([getEntitlement(auth.user.id), datasetStatus()]);
  return {
    linked: true,
    account: { emailMasked: maskEmail(auth.user.email) },
    session: { id: auth.session.id, label: auth.session.label, expiresAt: auth.session.expiresAt, syncEnabled: auth.session.extensionSyncEnabled },
    entitlement: { plan: entitlement.plan, state: entitlement.state, features: entitlement.features, currentPeriodEnd: entitlement.subscription?.currentPeriodEnd || null, checkedAt: entitlement.checkedAt },
    dataset: { usable: dataset.usable, reason: dataset.reason, version: dataset.version, updatedAt: dataset.updatedAt, ageHours: dataset.ageHours },
    serverTime: new Date().toISOString(),
  };
}

export async function setExtensionSync(auth, enabled) {
  if (enabled) await requirePremium(auth.user.id);
  await query('UPDATE sessions SET extension_sync_enabled = $3 WHERE id = $1 AND user_id = $2', [auth.session.id, auth.user.id, !!enabled]);
  return { syncEnabled: !!enabled };
}

const MAX_PAST_MS = 7 * 864e5;
const MAX_FUTURE_MS = 5 * 60e3;

/**
 * Stores opt-in security events. Requires: an extension session, Premium,
 * sync enabled on that session, valid types/domains/timestamps. Duplicate
 * client event ids are ignored (idempotent retries).
 */
export async function ingestEvents(auth, events) {
  await requirePremium(auth.user.id);
  if (!auth.session.extensionSyncEnabled) throw new HttpError(403, 'SYNC_NOT_ENABLED', 'Security-event sync is turned off for this browser.');
  let accepted = 0;
  let duplicates = 0;
  const rejected = [];
  const now = Date.now();
  for (const e of events) {
    const n = normalizeHost(e.domain);
    const at = new Date(e.occurredAt).getTime();
    if (!n || n.isLocal) {
      rejected.push({ clientEventId: e.clientEventId, reason: 'invalid_domain' });
      continue;
    }
    if (!Number.isFinite(at) || at < now - MAX_PAST_MS || at > now + MAX_FUTURE_MS) {
      rejected.push({ clientEventId: e.clientEventId, reason: 'invalid_timestamp' });
      continue;
    }
    const rows = await query(
      `INSERT INTO extension_events (user_id, session_id, client_event_id, type, domain, status, reason_codes, dataset_version, occurred_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9) ON CONFLICT (user_id, client_event_id) DO NOTHING RETURNING id`,
      [auth.user.id, auth.session.id, e.clientEventId, e.type, n.hostname, e.status, JSON.stringify(e.reasonCodes || []), e.datasetVersion || null, new Date(at)]
    );
    if (!rows.length) {
      duplicates += 1;
      continue;
    }
    accepted += 1;
    if (e.status === 'malicious') {
      await createAlert(auth.user.id, {
        kind: 'extension',
        severity: 'medium',
        title: `Browser extension blocked a known threat: ${n.hostname}`,
        body: `The FootprintX extension showed a warning for ${n.hostname} because it is listed in a threat dataset. If you continued and entered information there, change the affected password on the real site.`,
        domain: n.hostname,
        dedupKey: `ext_block:${n.hostname}:${new Date(at).toISOString().slice(0, 10)}`,
        email: false,
      });
    }
  }
  return { accepted, duplicates, rejected };
}

export async function listExtensionSessions(userId) {
  return query(
    "SELECT id, label, created_at, last_seen_at, expires_at, extension_sync_enabled FROM sessions WHERE user_id = $1 AND kind = 'extension' AND revoked_at IS NULL AND expires_at > now() ORDER BY last_seen_at DESC",
    [userId]
  );
}

export async function unlinkExtensionSession(userId, sessionId) {
  const s = await queryOne("SELECT id FROM sessions WHERE id = $1 AND user_id = $2 AND kind = 'extension'", [sessionId, userId]);
  if (!s) return false;
  await revokeSession(sessionId, userId);
  return true;
}

export async function listExtensionEvents(userId, { days = 30, limit = 200 } = {}) {
  return query(
    `SELECT id, type, domain, status, reason_codes, dataset_version, occurred_at, received_at FROM extension_events
      WHERE user_id = $1 AND occurred_at > now() - make_interval(days => $2) ORDER BY occurred_at DESC LIMIT $3`,
    [userId, days, limit]
  );
}
