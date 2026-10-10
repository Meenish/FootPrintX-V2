// Mailbox connections: OAuth connect, disconnect/revoke, token access.
import crypto from 'node:crypto';
import { query, queryOne, transaction } from '../db.js';
import { getConfig } from '../config.js';
import { encrypt, decrypt, keyedHash, generatePkce, randomToken, sha256, canonicalEmail } from '../crypto.js';
import { maskEmail } from '@footprintx/shared/domain';
import { HttpError } from '../http.js';
import { buildAuthUrl, exchangeCode, revokeRefreshToken } from './gmail.js';
import { syntheticFixture, assertSyntheticEnabled } from './synthetic.js';

const STATE_TTL_MS = 10 * 60e3;

// Provider calls are indirected so tests can simulate Google without network.
let oauth = { exchangeCode, revokeRefreshToken };
export function setOAuthProvider(overrides) {
  oauth = { ...oauth, ...overrides };
}

export const CONNECTION_COLUMNS = `id, provider, email_masked, scope_mode, granted_scopes, status, is_synthetic, connected_at, disconnected_at,
  token_revoked_at, token_revoke_result, last_scan_at, last_successful_scan_at`;

const tokenAad = (connectionId) => `connection:${connectionId}:refresh_token`;
const emailAad = (connectionId) => `connection:${connectionId}:email`;

export async function listConnections(userId) {
  return query(`SELECT ${CONNECTION_COLUMNS} FROM email_connections WHERE user_id = $1 ORDER BY connected_at`, [userId]);
}

export async function getOwnedConnection(userId, connectionId, client) {
  return queryOne('SELECT * FROM email_connections WHERE id = $1 AND user_id = $2', [connectionId, userId], client);
}

export function connectionEmail(connection) {
  return decrypt(connection.email_enc, emailAad(connection.id));
}

export const revokeTokenViaProvider = (token) => oauth.revokeRefreshToken(token);

export function connectionRefreshToken(connection) {
  if (!connection.token_enc) throw new HttpError(409, 'NOT_CONNECTED', 'This mailbox is not connected. Reconnect it to continue.');
  return decrypt(connection.token_enc, tokenAad(connection.id));
}

/** Starts the Google OAuth flow; returns the consent URL. */
export async function startGoogleConnect(userId) {
  const cfg = getConfig();
  if (!cfg.google.configured) {
    throw new HttpError(503, 'GOOGLE_NOT_CONFIGURED', 'Gmail connection is not set up on this server. An administrator must configure GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET (see docs/PROVIDERS.md).');
  }
  const state = randomToken(32);
  const pkce = generatePkce();
  const stateHash = sha256(state);
  await query("DELETE FROM oauth_states WHERE user_id = $1 OR expires_at < now()", [userId]);
  await query('INSERT INTO oauth_states (state_hash, user_id, pkce_verifier_enc, scope_mode, expires_at) VALUES ($1, $2, $3::jsonb, $4, $5)', [
    stateHash,
    userId,
    JSON.stringify(encrypt(pkce.verifier, `oauth_state:${stateHash}`)),
    cfg.google.scopeMode,
    new Date(Date.now() + STATE_TTL_MS),
  ]);
  return { url: buildAuthUrl({ state, pkce, scopeMode: cfg.google.scopeMode }), scopeMode: cfg.google.scopeMode };
}

/**
 * Completes the OAuth callback. The state is single-use (deleted on read) and
 * bound to the user who started the flow; when the browser also carries a
 * session, it must belong to that same user.
 */
export async function completeGoogleConnect({ state, code, sessionUserId }) {
  if (typeof state !== 'string' || typeof code !== 'string' || state.length > 200 || code.length > 2000) throw new HttpError(400, 'OAUTH_INVALID', 'Authorization was not completed.');
  const stateHash = sha256(state);
  const record = await queryOne('DELETE FROM oauth_states WHERE state_hash = $1 AND expires_at > now() RETURNING *', [stateHash]);
  if (!record) throw new HttpError(400, 'OAUTH_STATE_INVALID', 'This authorization link expired or was already used. Start again.');
  if (sessionUserId && sessionUserId !== record.user_id) throw new HttpError(400, 'OAUTH_USER_MISMATCH', 'This authorization was started by a different FootprintX user.');
  const verifier = decrypt(record.pkce_verifier_enc, `oauth_state:${stateHash}`);
  const { email, refreshToken, grantedScopes } = await oauth.exchangeCode({ code, verifier, scopeMode: record.scope_mode });
  return upsertConnection(record.user_id, { provider: 'gmail', email, refreshToken, scopeMode: record.scope_mode, grantedScopes });
}

async function upsertConnection(userId, { provider, email, refreshToken, scopeMode, grantedScopes, isSynthetic = false }) {
  const emailHash = keyedHash('email', canonicalEmail(email));
  return transaction(async (tx) => {
    const existing = await queryOne('SELECT id, token_enc, status FROM email_connections WHERE user_id = $1 AND email_hash = $2', [userId, emailHash], tx);
    const id = existing?.id || crypto.randomUUID();
    const tokenEnc = refreshToken ? JSON.stringify(encrypt(refreshToken, tokenAad(id))) : null;
    if (existing) {
      await query(
        `UPDATE email_connections SET status = 'active', token_enc = $3::jsonb, scope_mode = $4, granted_scopes = $5, disconnected_at = NULL,
           token_revoked_at = NULL, token_revoke_result = NULL, connected_at = CASE WHEN status = 'disconnected' THEN now() ELSE connected_at END, updated_at = now()
         WHERE id = $1 AND user_id = $2`,
        [id, userId, tokenEnc, scopeMode, grantedScopes || null],
        tx
      );
    } else {
      await query(
        `INSERT INTO email_connections (id, user_id, provider, email_hash, email_enc, email_masked, scope_mode, granted_scopes, token_enc, is_synthetic)
         VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8, $9::jsonb, $10)`,
        [id, userId, provider, emailHash, JSON.stringify(encrypt(email, emailAad(id))), maskEmail(email), scopeMode, grantedScopes || null, tokenEnc, isSynthetic],
        tx
      );
    }
    return { connectionId: id, userId, reconnected: !!existing };
  });
}

export async function connectSynthetic(userId) {
  assertSyntheticEnabled();
  return upsertConnection(userId, { provider: 'synthetic', email: syntheticFixture().mailbox, refreshToken: null, scopeMode: 'synthetic', grantedScopes: 'synthetic', isSynthetic: true });
}

/**
 * Disconnects a mailbox: revokes the Google token (best effort, result
 * recorded), deletes the stored token, cancels queued scans. Findings remain
 * unless deleteFindings is true.
 */
export async function disconnectConnection(userId, connectionId, { deleteFindings = false } = {}) {
  const conn = await getOwnedConnection(userId, connectionId);
  if (!conn) return null;
  let revokeResult = conn.provider === 'synthetic' ? 'not_applicable' : 'no_token';
  if (conn.provider === 'gmail' && conn.token_enc) {
    let token = null;
    try {
      token = connectionRefreshToken(conn);
    } catch {
      revokeResult = 'token_unreadable';
    }
    if (token) revokeResult = await oauth.revokeRefreshToken(token);
  }
  await transaction(async (tx) => {
    await query(
      `UPDATE email_connections SET status = 'disconnected', token_enc = NULL, disconnected_at = now(), token_revoked_at = CASE WHEN $3 IN ('revoked','already_invalid') THEN now() ELSE NULL END,
         token_revoke_result = $3, updated_at = now() WHERE id = $1 AND user_id = $2`,
      [connectionId, userId, revokeResult],
      tx
    );
    await query(`UPDATE scan_jobs SET status = 'cancelled', finished_at = now(), error_code = 'DISCONNECTED' WHERE connection_id = $1 AND status = 'queued'`, [connectionId], tx);
    await query(`UPDATE scan_jobs SET cancel_requested = true WHERE connection_id = $1 AND status = 'running'`, [connectionId], tx);
    await query(`UPDATE recommendations SET status = 'user_reported', verification_deadline = NULL, updated_at = now()
                  WHERE user_id = $1 AND status = 'verification_pending' AND account_id IN (SELECT id FROM discovered_accounts WHERE connection_id = $2)`, [userId, connectionId], tx);
    if (deleteFindings) {
      await query('DELETE FROM discovered_accounts WHERE connection_id = $1 AND user_id = $2', [connectionId, userId], tx);
      await query('DELETE FROM breach_findings WHERE connection_id = $1 AND user_id = $2', [connectionId, userId], tx);
      await query('DELETE FROM breach_checks WHERE connection_id = $1 AND user_id = $2', [connectionId, userId], tx);
      await query('DELETE FROM synthetic_messages WHERE connection_id = $1 AND user_id = $2', [connectionId, userId], tx);
    }
  });
  return { revokeResult, deletedFindings: deleteFindings };
}

/** Permanently removes a disconnected connection record and all its findings. */
export async function deleteConnection(userId, connectionId) {
  const conn = await getOwnedConnection(userId, connectionId);
  if (!conn) return null;
  if (conn.status !== 'disconnected') throw new HttpError(409, 'STILL_CONNECTED', 'Disconnect the mailbox before deleting it.');
  await query('DELETE FROM email_connections WHERE id = $1 AND user_id = $2', [connectionId, userId]);
  return true;
}

export async function markReauthRequired(connectionId) {
  await query(`UPDATE email_connections SET status = 'reauth_required', updated_at = now() WHERE id = $1 AND status = 'active'`, [connectionId]);
}
