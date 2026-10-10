// Scan jobs: a durable PostgreSQL-backed queue (no Redis needed).
//
// Lifecycle: queued → running → completed | partial | failed | cancelled.
//  * Progress fields reflect real work (messages listed / processed / failed).
//  * Transient provider failures are retried with backoff (job re-queued).
//  * Whatever was gathered before a failure or cancellation is persisted and
//    the job is marked partial/cancelled with the failing sources listed.
//  * Persistence is idempotent, so retries never duplicate accounts/evidence.
//  * A partial unique index allows at most one queued/running job per mailbox.
import { query, queryOne, transaction } from '../db.js';
import { getConfig } from '../config.js';
import { keyedHash } from '../crypto.js';
import { log } from '../logger.js';
import { HttpError } from '../http.js';
import { addMessage, finalize } from './discovery.js';
import { persistCandidates, mailboxAccountCandidate } from './accounts.js';
import { iterateMailbox, classifyGoogleError } from './gmail.js';
import { iterateSynthetic } from './synthetic.js';
import { connectionRefreshToken, markReauthRequired } from './connections.js';
import { recalculate } from './risk.js';
import { createAlert } from './notifications.js';

const STALE_MS = 5 * 60e3;
const PUBLIC_JOB_COLUMNS = 'id, connection_id, trigger, status, stage, progress, source_results, summary, error_code, error_message, attempts, created_at, started_at, finished_at';

// Provider registry (tests may override to simulate Gmail behaviour).
const providers = {
  gmail: ({ connection }) => iterateMailbox({ refreshToken: connectionRefreshToken(connection), scopeMode: connection.scope_mode, maxMessages: getConfig().scan.maxMessages }),
  synthetic: ({ connection }) => iterateSynthetic({ connection }),
};
export function setScanProvider(name, fn) {
  providers[name] = fn;
}

export async function enqueueScan(userId, connectionId, trigger = 'manual') {
  const conn = await queryOne('SELECT id, status FROM email_connections WHERE id = $1 AND user_id = $2', [connectionId, userId]);
  if (!conn) throw new HttpError(404, 'NOT_FOUND', 'Mailbox connection not found.');
  if (conn.status !== 'active') throw new HttpError(409, 'CONNECTION_INACTIVE', conn.status === 'reauth_required' ? 'Reconnect this mailbox before scanning.' : 'This mailbox is disconnected; FootprintX will not scan it.');
  const rows = await query(
    `INSERT INTO scan_jobs (user_id, connection_id, trigger, stage) VALUES ($1, $2, $3, 'Waiting to start')
     ON CONFLICT (connection_id) WHERE status IN ('queued','running') DO NOTHING RETURNING ${PUBLIC_JOB_COLUMNS}`,
    [userId, connectionId, trigger]
  );
  if (rows.length) return { job: rows[0], deduplicated: false };
  const active = await queryOne(`SELECT ${PUBLIC_JOB_COLUMNS} FROM scan_jobs WHERE connection_id = $1 AND status IN ('queued','running')`, [connectionId]);
  return { job: active, deduplicated: true };
}

export async function getJob(userId, jobId) {
  return queryOne(`SELECT ${PUBLIC_JOB_COLUMNS} FROM scan_jobs WHERE id = $1 AND user_id = $2`, [jobId, userId]);
}

export async function listJobs(userId, limit = 30) {
  return query(
    `SELECT j.id, j.connection_id, j.trigger, j.status, j.stage, j.progress, j.source_results, j.summary, j.error_code, j.error_message, j.attempts, j.created_at, j.started_at, j.finished_at, c.email_masked
       FROM scan_jobs j JOIN email_connections c ON c.id = j.connection_id WHERE j.user_id = $1 ORDER BY j.created_at DESC LIMIT $2`,
    [userId, limit]
  );
}

export async function requestCancel(userId, jobId) {
  const job = await queryOne(
    `UPDATE scan_jobs SET cancel_requested = true,
       status = CASE WHEN status = 'queued' THEN 'cancelled' ELSE status END,
       finished_at = CASE WHEN status = 'queued' THEN now() ELSE finished_at END
     WHERE id = $1 AND user_id = $2 AND status IN ('queued','running') RETURNING ${PUBLIC_JOB_COLUMNS}`,
    [jobId, userId]
  );
  return job;
}

/** Claims the next runnable job (safe with multiple workers). */
export async function claimNextJob() {
  return queryOne(
    `UPDATE scan_jobs SET status = 'running', attempts = attempts + 1, started_at = COALESCE(started_at, now()), heartbeat_at = now(), stage = 'Starting'
      WHERE id = (SELECT id FROM scan_jobs WHERE status = 'queued' AND next_attempt_at <= now() ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1)
      RETURNING *`
  );
}

/** Re-queues jobs whose worker died (no heartbeat), or fails them after max attempts. */
export async function recoverStaleJobs() {
  const cutoff = new Date(Date.now() - STALE_MS);
  await query(
    `UPDATE scan_jobs SET status = CASE WHEN attempts >= max_attempts THEN 'failed' ELSE 'queued' END,
       error_code = CASE WHEN attempts >= max_attempts THEN 'WORKER_LOST' ELSE error_code END,
       error_message = CASE WHEN attempts >= max_attempts THEN 'The scan stopped unexpectedly. Please start it again.' ELSE error_message END,
       finished_at = CASE WHEN attempts >= max_attempts THEN now() ELSE NULL END, next_attempt_at = now()
     WHERE status = 'running' AND (heartbeat_at IS NULL OR heartbeat_at < $1)`,
    [cutoff]
  );
}

async function updateProgress(jobId, stage, progress, sourceResults) {
  const row = await queryOne(
    'UPDATE scan_jobs SET stage = $2, progress = $3::jsonb, source_results = $4::jsonb, heartbeat_at = now() WHERE id = $1 RETURNING cancel_requested',
    [jobId, stage, JSON.stringify(progress), JSON.stringify(sourceResults)]
  );
  return !!row?.cancel_requested;
}

const SAFE_MESSAGES = {
  AUTH_REVOKED: 'Gmail access was revoked or has expired. Reconnect this mailbox to scan it again.',
  SCOPE_MISSING: 'The mailbox permission FootprintX needs was not granted. Reconnect and approve access.',
  RATE_LIMITED: 'Gmail is temporarily limiting requests. FootprintX will retry automatically.',
  PROVIDER_UNAVAILABLE: 'Gmail was temporarily unavailable.',
  NETWORK_ERROR: 'FootprintX could not reach Gmail.',
  PROVIDER_ERROR: 'Gmail returned an unexpected error.',
  NOT_CONNECTED: 'This mailbox is not connected.',
  CONNECTION_INACTIVE: 'This mailbox is no longer connected.',
};

/** Executes one claimed job end-to-end. Never throws. */
export async function runJob(job) {
  const conn = await queryOne('SELECT * FROM email_connections WHERE id = $1 AND user_id = $2', [job.connection_id, job.user_id]);
  const found = new Map();
  const progress = { messagesListed: 0, messagesProcessed: 0, messagesFailed: 0, servicesSeen: 0 };
  const sources = new Map();
  let cancelled = false;
  let failure = null;

  if (!conn || conn.status !== 'active') {
    await finishJob(job, { status: 'cancelled', errorCode: 'CONNECTION_INACTIVE', progress, sources: [] });
    return;
  }
  try {
    const iterate = providers[conn.provider];
    if (!iterate) throw Object.assign(new Error('Unsupported mailbox provider'), { code: 'PROVIDER_ERROR' });
    for await (const chunk of iterate({ connection: conn })) {
      for (const msg of chunk.messages) {
        // Subjects are classified here and immediately discarded.
        addMessage(found, msg, keyedHash('evidence-ref', `${conn.id}:${msg.id}`));
      }
      sources.set(chunk.source, chunk.outcome);
      const all = [...sources.values()];
      progress.messagesListed = all.reduce((s, o) => s + (o.listed || 0), 0);
      progress.messagesProcessed = all.reduce((s, o) => s + (o.fetched || 0), 0);
      progress.messagesFailed = all.reduce((s, o) => s + (o.failed || 0), 0);
      progress.servicesSeen = found.size;
      const stage = `Reading ${chunk.source.replace(/_/g, ' ')}`;
      if (await updateProgress(job.id, stage, progress, [...sources.values()])) {
        cancelled = true;
        break;
      }
    }
  } catch (raw) {
    failure = raw?.code === 'NOT_CONNECTED' ? raw : classifyGoogleError(raw);
  }

  const outcomes = [...sources.values()].map(({ inProgress: _inProgress, ...o }) => o);
  if (failure?.transient && job.attempts < job.max_attempts && !cancelled) {
    const delayMs = Math.min(15 * 60e3, 30e3 * 2 ** (job.attempts - 1));
    await query(
      `UPDATE scan_jobs SET status = 'queued', next_attempt_at = $2, stage = 'Waiting to retry', error_code = $3, error_message = $4, progress = $5::jsonb, source_results = $6::jsonb WHERE id = $1`,
      [job.id, new Date(Date.now() + delayMs), failure.code, SAFE_MESSAGES[failure.code] || 'Temporary problem; retrying.', JSON.stringify(progress), JSON.stringify(outcomes)]
    );
    log.warn('scan retry scheduled', { jobId: job.id, code: failure.code, attempt: job.attempts });
    return;
  }

  let status;
  if (cancelled) status = 'cancelled';
  else if (failure) status = found.size ? 'partial' : 'failed';
  else status = outcomes.some((o) => o.status !== 'ok') ? 'partial' : 'completed';

  let summary = null;
  try {
    summary = await persistResults(conn, found, status);
  } catch (err) {
    log.error('scan persistence failed', { jobId: job.id, err });
    status = 'failed';
    failure = { code: 'PERSISTENCE_FAILED' };
  }
  await finishJob(job, { status, errorCode: failure?.code || null, progress, sources: outcomes, summary });

  if (failure?.code === 'AUTH_REVOKED' || failure?.code === 'SCOPE_MISSING') {
    await markReauthRequired(conn.id);
    await createAlert(job.user_id, {
      kind: 'scan',
      severity: 'medium',
      title: `Reconnect ${conn.email_masked}`,
      body: SAFE_MESSAGES[failure.code],
      dedupKey: `reauth:${conn.id}:${new Date().toISOString().slice(0, 10)}`,
      email: false,
    });
  }
  if (status === 'completed' || status === 'partial' || status === 'cancelled') {
    try {
      await recalculate(job.user_id, 'scan');
    } catch (err) {
      log.error('recalculation after scan failed', { jobId: job.id, err });
    }
  }
}

async function persistResults(conn, found, status) {
  const candidates = finalize(found);
  const mailboxAccount = mailboxAccountCandidate(conn);
  const all = mailboxAccount ? [mailboxAccount, ...candidates.filter((c) => c.serviceKey !== mailboxAccount.serviceKey)] : candidates;
  // Merge mailbox-provider evidence (e.g. Google security mail) into the mailbox account.
  if (mailboxAccount) {
    const providerEvidence = candidates.find((c) => c.serviceKey === mailboxAccount.serviceKey);
    if (providerEvidence) {
      mailboxAccount.evidence.push(...providerEvidence.evidence);
      mailboxAccount.mfa = providerEvidence.mfa;
      mailboxAccount.firstObservedAt = new Date(Math.min(mailboxAccount.firstObservedAt, providerEvidence.firstObservedAt));
    }
  }
  const source = conn.provider === 'synthetic' ? 'synthetic' : conn.scope_mode === 'readonly' ? 'gmail_search' : 'gmail_metadata';
  const result = await transaction((tx) => persistCandidates(tx, conn, all, { source }));
  await query(
    `UPDATE email_connections SET last_scan_at = now(), last_successful_scan_at = CASE WHEN $2 THEN now() ELSE last_successful_scan_at END, updated_at = now() WHERE id = $1`,
    [conn.id, status === 'completed' || status === 'partial']
  );
  return {
    confirmed: candidates.filter((c) => c.status === 'confirmed').length + (mailboxAccount ? 1 : 0),
    possible: candidates.filter((c) => c.status === 'possible').length,
    newAccounts: result.created,
    updatedAccounts: result.updated,
  };
}

async function finishJob(job, { status, errorCode, progress, sources, summary = null }) {
  await query(
    `UPDATE scan_jobs SET status = $2, stage = $3, error_code = $4, error_message = $5, progress = $6::jsonb, source_results = $7::jsonb, summary = $8::jsonb, finished_at = now(), heartbeat_at = now()
      WHERE id = $1`,
    [
      job.id,
      status,
      { completed: 'Completed', partial: 'Partially completed', failed: 'Failed', cancelled: 'Cancelled' }[status],
      errorCode,
      errorCode ? SAFE_MESSAGES[errorCode] || 'The scan could not be completed.' : null,
      JSON.stringify(progress),
      JSON.stringify(sources),
      summary ? JSON.stringify(summary) : null,
    ]
  );
}

/** Enqueues scheduled re-scans for mailboxes not scanned within the interval. */
export async function enqueueDueMonitoringScans() {
  const hours = getConfig().scan.monitorIntervalHours;
  if (!hours) return 0;
  const due = await query(
    `SELECT id, user_id FROM email_connections WHERE status = 'active' AND provider = 'gmail'
       AND (last_scan_at IS NULL OR last_scan_at < now() - make_interval(hours => $1))`,
    [hours]
  );
  let n = 0;
  for (const c of due) {
    const { deduplicated } = await enqueueScan(c.user_id, c.id, 'scheduled');
    if (!deduplicated) n += 1;
  }
  return n;
}
