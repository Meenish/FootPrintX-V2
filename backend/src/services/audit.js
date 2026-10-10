// Audit trail for security-sensitive actions. Details are redacted before
// storage and IP addresses are stored only as a keyed hash.
import { query } from '../db.js';
import { keyedHash } from '../crypto.js';
import { redact, log } from '../logger.js';

export async function audit(event, { userId = null, sessionId = null, req = null, detail = {} } = {}, client) {
  try {
    const ip = req?.ip ? keyedHash('ip', req.ip) : null;
    await query(
      'INSERT INTO audit_events (user_id, session_id, event, detail, ip_hash) VALUES ($1, $2, $3, $4::jsonb, $5)',
      [userId, sessionId, event, JSON.stringify(redact(detail)), ip],
      client
    );
  } catch (err) {
    // Auditing must never break the user-facing action, but failures are visible.
    log.error('audit write failed', { event, err });
  }
}

export async function listAudit(userId, limit = 100) {
  return query(
    'SELECT event, detail, created_at FROM audit_events WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2',
    [userId, limit]
  );
}
