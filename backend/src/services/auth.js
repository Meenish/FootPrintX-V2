// Users, passwords and sessions.
//
// Sessions are opaque random tokens. The browser receives the token in an
// HttpOnly cookie (never readable by page scripts); the database stores only
// its SHA-256 hash, so a database leak does not leak usable sessions. Each web
// session also has a CSRF token (synchronizer pattern): its hash is stored on
// the session and the value must be echoed in the X-CSRF-Token header on every
// state-changing request. The browser extension uses a separate session kind
// presented as a Bearer token; it cannot be used as a web cookie and vice versa.
import bcrypt from 'bcryptjs';
import { query, queryOne, transaction } from '../db.js';
import { randomToken, sha256 } from '../crypto.js';
import { HttpError } from '../http.js';

const HOUR = 3600e3;
const DAY = 24 * HOUR;
export const SESSION_POLICY = Object.freeze({
  web: { absoluteMs: 7 * DAY, idleMs: 24 * HOUR },
  extension: { absoluteMs: 90 * DAY, idleMs: 30 * DAY },
});
const TOUCH_INTERVAL_MS = 5 * 60e3;
const BCRYPT_COST = 12;
const MAX_FAILED_LOGINS = 10;
const LOCK_MS = 15 * 60e3;

// A small deny-list of the most common passwords; length (>= 12) does most of
// the work. Production deployments can add a breached-password check here.
const COMMON = new Set([
  'password1234', 'password12345', '123456789012', 'qwertyuiop12', 'iloveyou1234', 'administrator', 'passwordpassword',
  '111111111111', '000000000000', 'abcdefghijkl', 'letmein12345', 'welcome12345', 'qwerty123456', 'footprintx123',
]);

export function passwordProblems(password, email) {
  const problems = [];
  if (typeof password !== 'string' || password.length < 12) problems.push('Use at least 12 characters.');
  if (typeof password === 'string' && password.length > 128) problems.push('Use at most 128 characters.');
  if (typeof password === 'string' && COMMON.has(password.toLowerCase())) problems.push('This password is too common.');
  if (typeof password === 'string' && email && password.toLowerCase().includes(String(email).split('@')[0].toLowerCase()) && String(email).split('@')[0].length >= 4) {
    problems.push('Do not include your email name in the password.');
  }
  return problems;
}

// Pre-computed hash so logins for unknown emails take as long as real ones.
const DUMMY_HASH = bcrypt.hashSync('footprintx-timing-equalizer', BCRYPT_COST);

export const normalizeLoginEmail = (email) => String(email).trim().toLowerCase();

export async function registerUser({ email, password, displayName }) {
  const normalized = normalizeLoginEmail(email);
  const problems = passwordProblems(password, normalized);
  if (problems.length) throw new HttpError(400, 'WEAK_PASSWORD', problems.join(' '), problems.map((message) => ({ path: 'password', message })));
  const hash = await bcrypt.hash(password, BCRYPT_COST);
  const rows = await query(
    `INSERT INTO users (email, password_hash, display_name) VALUES ($1, $2, $3)
     ON CONFLICT (email) DO NOTHING RETURNING id, email, display_name, role, created_at`,
    [normalized, hash, displayName || null]
  );
  if (!rows.length) {
    // Deliberately generic: see docs/THREAT_MODEL.md (account enumeration).
    throw new HttpError(409, 'REGISTRATION_FAILED', 'We could not create an account with these details. If you already have an account, sign in or reset your password.');
  }
  await query('INSERT INTO notification_preferences (user_id) VALUES ($1) ON CONFLICT DO NOTHING', [rows[0].id]);
  return rows[0];
}

export async function verifyLogin(email, password) {
  const user = await queryOne('SELECT * FROM users WHERE email = $1', [normalizeLoginEmail(email)]);
  if (!user) {
    await bcrypt.compare(String(password), DUMMY_HASH);
    return { ok: false };
  }
  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    await bcrypt.compare(String(password), DUMMY_HASH);
    return { ok: false, locked: true, userId: user.id };
  }
  const ok = await bcrypt.compare(String(password), user.password_hash);
  if (!ok) {
    const failed = user.failed_login_count + 1;
    await query('UPDATE users SET failed_login_count = $2, locked_until = $3 WHERE id = $1', [
      user.id,
      failed >= MAX_FAILED_LOGINS ? 0 : failed,
      failed >= MAX_FAILED_LOGINS ? new Date(Date.now() + LOCK_MS) : null,
    ]);
    return { ok: false, userId: user.id, lockedNow: failed >= MAX_FAILED_LOGINS };
  }
  if (user.failed_login_count || user.locked_until) await query('UPDATE users SET failed_login_count = 0, locked_until = NULL WHERE id = $1', [user.id]);
  return { ok: true, user };
}

export async function verifyPasswordForUser(userId, password) {
  const user = await queryOne('SELECT password_hash FROM users WHERE id = $1', [userId]);
  return !!user && (await bcrypt.compare(String(password), user.password_hash));
}

export async function setPassword(userId, newPassword, email, client) {
  const problems = passwordProblems(newPassword, email);
  if (problems.length) throw new HttpError(400, 'WEAK_PASSWORD', problems.join(' '));
  const hash = await bcrypt.hash(newPassword, BCRYPT_COST);
  await query('UPDATE users SET password_hash = $2, password_changed_at = now(), updated_at = now(), failed_login_count = 0, locked_until = NULL WHERE id = $1', [userId, hash], client);
}

export async function createSession(userId, kind, { label = null } = {}, client) {
  const policy = SESSION_POLICY[kind];
  const token = randomToken(32);
  const csrfToken = kind === 'web' ? randomToken(24) : null;
  const now = Date.now();
  const session = await queryOne(
    `INSERT INTO sessions (user_id, token_hash, csrf_hash, kind, label, idle_expires_at, expires_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, user_id, kind, label, created_at, expires_at`,
    [userId, sha256(token), csrfToken ? sha256(csrfToken) : null, kind, label, new Date(now + policy.idleMs), new Date(now + policy.absoluteMs)],
    client
  );
  return { token, csrfToken, session };
}

/** Resolves a presented token to { session, user } or null. Slides the idle window. */
export async function resolveSession(token) {
  if (typeof token !== 'string' || token.length < 20 || token.length > 200) return null;
  const row = await queryOne(
    `SELECT s.id AS session_id, s.kind, s.csrf_hash, s.label, s.last_seen_at, s.expires_at, s.idle_expires_at, s.extension_sync_enabled,
            u.id, u.email, u.display_name, u.role, u.created_at
       FROM sessions s JOIN users u ON u.id = s.user_id
      WHERE s.token_hash = $1 AND s.revoked_at IS NULL AND s.expires_at > now() AND s.idle_expires_at > now()`,
    [sha256(token)]
  );
  if (!row) return null;
  if (Date.now() - new Date(row.last_seen_at).getTime() > TOUCH_INTERVAL_MS) {
    const idleMs = SESSION_POLICY[row.kind].idleMs;
    await query('UPDATE sessions SET last_seen_at = now(), idle_expires_at = LEAST(expires_at, $2) WHERE id = $1', [row.session_id, new Date(Date.now() + idleMs)]);
  }
  return {
    session: { id: row.session_id, kind: row.kind, csrfHash: row.csrf_hash, label: row.label, expiresAt: row.expires_at, extensionSyncEnabled: row.extension_sync_enabled },
    user: { id: row.id, email: row.email, displayName: row.display_name, role: row.role, createdAt: row.created_at },
  };
}

export async function revokeSession(sessionId, userId) {
  await query('UPDATE sessions SET revoked_at = now() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL', [sessionId, userId]);
}

export async function revokeAllSessions(userId, { exceptSessionId = null, kind = null } = {}, client) {
  await query(
    `UPDATE sessions SET revoked_at = now()
      WHERE user_id = $1 AND revoked_at IS NULL AND ($2::uuid IS NULL OR id <> $2) AND ($3::text IS NULL OR kind = $3)`,
    [userId, exceptSessionId, kind],
    client
  );
}

export async function listSessions(userId) {
  return query(
    `SELECT id, kind, label, created_at, last_seen_at, expires_at, extension_sync_enabled
       FROM sessions WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now() AND idle_expires_at > now()
      ORDER BY last_seen_at DESC`,
    [userId]
  );
}

// ---- Password reset ---------------------------------------------------------
const RESET_TTL_MS = 30 * 60e3;

/** Returns a raw token for the caller to email, or null if the email is unknown. */
export async function createPasswordReset(email) {
  const user = await queryOne('SELECT id, email FROM users WHERE email = $1', [normalizeLoginEmail(email)]);
  if (!user) return null;
  const token = randomToken(32);
  await query('UPDATE password_reset_tokens SET used_at = now() WHERE user_id = $1 AND used_at IS NULL', [user.id]);
  await query('INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)', [user.id, sha256(token), new Date(Date.now() + RESET_TTL_MS)]);
  return { user, token };
}

export async function consumePasswordReset(token, newPassword) {
  return transaction(async (tx) => {
    const row = await queryOne(
      `UPDATE password_reset_tokens SET used_at = now()
        WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
        RETURNING user_id`,
      [sha256(String(token))],
      tx
    );
    if (!row) throw new HttpError(400, 'RESET_INVALID', 'This reset link is invalid or has expired. Request a new one.');
    const user = await queryOne('SELECT id, email FROM users WHERE id = $1', [row.user_id], tx);
    await setPassword(user.id, newPassword, user.email, tx);
    // A password reset signs out every existing session, including extensions.
    await revokeAllSessions(user.id, {}, tx);
    return user;
  });
}
