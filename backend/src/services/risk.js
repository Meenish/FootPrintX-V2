// Risk recalculation pipeline: verification → account assessment →
// recommendation sync → DASI snapshot → alerts for new critical findings.
// Triggered after scans, breach checks, threat-intel updates, user
// corrections, remediation updates and scoring-model changes.
import { query, queryOne, transaction, dbKind } from '../db.js';
import { assessAccount, computeDasi, explainChange, MODEL_VERSION } from './dasi.js';
import { recommendationsFor, VERIFIABLE_ACTIONS } from './recommendationRules.js';
import { createAlert } from './notifications.js';
import { HttpError } from '../http.js';
import { log } from '../logger.js';

const DAY = 864e5;
const VERIFICATION_WINDOW_DAYS = 14;
const MAX_ALERT_EMAILS_PER_RECALC = 3;

async function loadInputs(userId, tx) {
  const accounts = await query(
    `SELECT a.*, c.status AS connection_status FROM discovered_accounts a
       LEFT JOIN email_connections c ON c.id = a.connection_id WHERE a.user_id = $1`,
    [userId],
    tx
  );
  const breaches = await query(
    'SELECT account_id, provider, breach_title, breach_date, password_exposed, provider_verified FROM breach_findings WHERE user_id = $1 AND account_id IS NOT NULL',
    [userId],
    tx
  );
  const alerts = await query(
    `SELECT account_id, max(observed_at) AS latest, bool_or(sender_authenticated = 'pass') AS authenticated
       FROM account_evidence WHERE user_id = $1 AND kind = 'security_alert' AND strength = 'strong' GROUP BY account_id`,
    [userId],
    tx
  );
  const recs = await query('SELECT * FROM recommendations WHERE user_id = $1', [userId], tx);
  const domains = [...new Set(accounts.map((a) => a.service_domain).filter(Boolean))];
  const threats = domains.length
    ? await query('SELECT hostname, source FROM threat_indicators WHERE active AND hostname = ANY($1::text[])', [domains], tx)
    : [];
  return { accounts, breaches, alerts, recs, threats };
}

function buildAccountInput(a, ctx) {
  const recFor = (type) => {
    const r = ctx.recs.find((x) => x.account_id === a.id && x.action_type === type);
    return r ? { status: r.status, at: r.verified_at || r.reported_at || r.status_changed_at } : null;
  };
  const alert = ctx.alerts.find((x) => x.account_id === a.id);
  const threats = ctx.threats.filter((t) => t.hostname === a.service_domain);
  return {
    id: a.id,
    serviceName: a.service_name,
    serviceDomain: a.service_domain,
    category: a.category,
    status: a.status,
    accountState: a.account_state,
    discoverySource: a.discovery_source,
    exposureStatus: a.exposure_status,
    mfa: { status: a.mfa_status, source: a.mfa_source },
    breaches: ctx.breaches.filter((b) => b.account_id === a.id).map((b) => ({ provider: b.provider, title: b.breach_title, date: b.breach_date, passwordExposed: b.password_exposed, providerVerified: b.provider_verified })),
    latestAlertAt: alert?.latest || null,
    alertAuthenticated: !!alert?.authenticated,
    lastObservedAt: a.last_observed_at,
    threatListed: threats.length > 0,
    threatSources: threats.map((t) => `Threat dataset: ${t.source}`),
    remediation: { change_password: recFor('change_password'), review_sessions: recFor('review_sessions'), enable_mfa: recFor('enable_mfa') },
    manual: a.manually_added,
  };
}

async function coverageFor(userId, accounts, tx) {
  const conns = await query("SELECT id, last_successful_scan_at FROM email_connections WHERE user_id = $1 AND status = 'active'", [userId], tx);
  const cutoff = Date.now() - 30 * DAY;
  const latestJobs = await query(
    `SELECT DISTINCT ON (connection_id) connection_id, status FROM scan_jobs
      WHERE user_id = $1 AND status IN ('completed','partial','failed','cancelled') ORDER BY connection_id, finished_at DESC NULLS LAST`,
    [userId],
    tx
  );
  const breachOk = await query(
    `SELECT DISTINCT connection_id FROM breach_checks WHERE user_id = $1 AND status = 'ok' AND checked_at > now() - interval '30 days'`,
    [userId],
    tx
  );
  const ever = await queryOne("SELECT 1 AS x FROM scan_jobs WHERE user_id = $1 AND status IN ('completed','partial') LIMIT 1", [userId], tx);
  const activeIds = new Set(conns.map((c) => c.id));
  const confirmed = accounts.filter((a) => a.status === 'confirmed');
  const lastScan = await queryOne("SELECT max(finished_at) AS at FROM scan_jobs WHERE user_id = $1 AND status IN ('completed','partial')", [userId], tx);
  return {
    activeConnections: conns.length,
    connectionsScannedRecently: conns.filter((c) => c.last_successful_scan_at && new Date(c.last_successful_scan_at).getTime() > cutoff).length,
    lastScanComplete: latestJobs.filter((j) => activeIds.has(j.connection_id)).every((j) => j.status === 'completed'),
    connectionsBreachCheckedRecently: breachOk.filter((b) => activeIds.has(b.connection_id)).length,
    confirmedAccounts: confirmed.length,
    possibleAccounts: accounts.filter((a) => a.status === 'possible').length,
    dismissedAccounts: accounts.filter((a) => a.status === 'dismissed').length,
    accountsWithKnownMfa: confirmed.filter((a) => a.mfa_status !== 'unknown').length,
    everScanned: !!ever,
    lastScanAt: lastScan?.at || null,
  };
}

/**
 * Independent verification of user-reported remediation using mailbox
 * security notifications. A notification is evidence that an event happened;
 * it does not prove the setting is still in that state today, and the UI says so.
 */
async function runVerification(userId, tx) {
  const pending = await query(
    `SELECT r.*, (SELECT max(CASE WHEN b.breach_date_precision = 'year' THEN b.breach_date + interval '1 year' - interval '1 day' ELSE b.breach_date END)
                    FROM breach_findings b WHERE b.account_id = r.account_id) AS latest_breach
       FROM recommendations r WHERE r.user_id = $1 AND r.action_type = ANY($2::text[]) AND r.status NOT IN ('verified', 'dismissed') AND r.account_id IS NOT NULL`,
    [userId, Object.keys(VERIFIABLE_ACTIONS)],
    tx
  );
  const changes = [];
  for (const r of pending) {
    const spec = VERIFIABLE_ACTIONS[r.action_type];
    // A password change only counts if it happened after the breach it addresses;
    // otherwise the evidence must post-date the recommendation itself.
    const after =
      r.action_type === 'change_password' && r.latest_breach ? new Date(r.latest_breach) : new Date(new Date(r.created_at).getTime() - DAY);
    const ev = await queryOne(
      `SELECT id, observed_at, sender_domain, sender_authenticated FROM account_evidence
        WHERE account_id = $1 AND user_id = $2 AND kind = $3 AND strength = 'strong' AND sender_authenticated <> 'fail' AND observed_at >= $4
        ORDER BY observed_at DESC LIMIT 1`,
      [r.account_id, userId, spec.evidenceKind, after],
      tx
    );
    if (ev) {
      const evidence = { kind: spec.evidenceKind, evidenceId: ev.id, observedAt: ev.observed_at, senderDomain: ev.sender_domain, senderAuthenticated: ev.sender_authenticated };
      await query(
        `UPDATE recommendations SET status = 'verified', verified_at = now(), verification_evidence = $2::jsonb, status_changed_at = now(), updated_at = now() WHERE id = $1`,
        [r.id, JSON.stringify(evidence)],
        tx
      );
      await query(
        `INSERT INTO remediation_events (user_id, recommendation_id, from_status, to_status, actor, note, evidence) VALUES ($1, $2, $3, 'verified', 'system', $4, $5::jsonb)`,
        [userId, r.id, r.status, 'Verified by a security-notification email from the service. This is evidence the change happened; it does not prove the current setting.', JSON.stringify(evidence)],
        tx
      );
      changes.push({ id: r.id, to: 'verified' });
    } else if (r.status === 'verification_pending' && r.verification_deadline && new Date(r.verification_deadline) < new Date()) {
      await query(`UPDATE recommendations SET status = 'unable_to_verify', status_changed_at = now(), updated_at = now() WHERE id = $1`, [r.id], tx);
      await query(
        `INSERT INTO remediation_events (user_id, recommendation_id, from_status, to_status, actor, note) VALUES ($1, $2, 'verification_pending', 'unable_to_verify', 'system', $3)`,
        [userId, r.id, `No confirming security email was found within ${VERIFICATION_WINDOW_DAYS} days. Your report is kept as user-reported.`],
        tx
      );
      changes.push({ id: r.id, to: 'unable_to_verify' });
    }
  }
  return changes;
}

async function syncRecommendations(userId, assessed, existing, tx) {
  const seen = new Set();
  for (const { input, risk } of assessed) {
    for (const r of recommendationsFor(input, risk)) {
      const prior = existing.find((x) => x.account_id === r.accountId && x.action_type === r.actionType && !x.domain);
      seen.add(`${r.accountId}:${r.actionType}`);
      if (!prior) {
        await query(
          `INSERT INTO recommendations (user_id, account_id, action_type, severity, priority, title, explanation, why_it_matters, next_step, evidence,
             official_url, official_url_kind, expected_effect, verification_method)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13,$14)`,
          [userId, r.accountId, r.actionType, r.severity, r.priority, r.title, r.explanation, r.whyItMatters, r.nextStep, JSON.stringify(r.evidence), r.officialUrl, r.officialUrlKind, r.expectedEffect, r.verificationMethod],
          tx
        );
        continue;
      }
      // Re-open a completed item only when new evidence post-dates the remediation.
      const factor = risk.factors.find((f) => (r.actionType === 'change_password' && f.code.startsWith('CREDENTIAL_EXPOSURE')) || (r.actionType === 'review_sessions' && f.code === 'RECENT_SECURITY_ALERT'));
      const remediatedStates = ['verified', 'user_reported', 'verification_pending', 'unable_to_verify'];
      const reopen = factor && remediatedStates.includes(prior.status) && factor.remediation == null;
      await query(
        `UPDATE recommendations SET severity = $2, priority = $3, title = $4, explanation = $5, why_it_matters = $6, next_step = $7, evidence = $8::jsonb,
           official_url = $9, official_url_kind = $10, expected_effect = $11, applicable = true,
           status = CASE WHEN $12 THEN 'recommended' ELSE status END,
           status_changed_at = CASE WHEN $12 THEN now() ELSE status_changed_at END, updated_at = now()
         WHERE id = $1`,
        [prior.id, r.severity, r.priority, r.title, r.explanation, r.whyItMatters, r.nextStep, JSON.stringify(r.evidence), r.officialUrl, r.officialUrlKind, r.expectedEffect, !!reopen],
        tx
      );
      if (reopen) {
        await query(
          `INSERT INTO remediation_events (user_id, recommendation_id, from_status, to_status, actor, note) VALUES ($1, $2, $3, 'recommended', 'system', $4)`,
          [userId, prior.id, prior.status, 'Re-opened: new evidence appeared after your last action.'],
          tx
        );
      }
    }
  }
  // Open items whose triggering factor no longer applies are hidden, not deleted.
  for (const x of existing) {
    if (x.account_id && !seen.has(`${x.account_id}:${x.action_type}`) && x.applicable && ['recommended', 'in_progress'].includes(x.status)) {
      await query('UPDATE recommendations SET applicable = false, updated_at = now() WHERE id = $1', [x.id], tx);
    }
  }
}

/**
 * Recalculates every account score and the user's DASI. Creates a snapshot
 * only when something changed (score, bound, confidence, contributing
 * factors or model version). Returns the current DASI result.
 */
export async function recalculate(userId, trigger = 'manual') {
  const { result, newCritical } = await transaction(async (tx) => {
    if (dbKind() === 'postgres') await tx.query('SELECT pg_advisory_xact_lock(hashtext($1))', [`dasi:${userId}`]);
    await runVerification(userId, tx);
    const ctx = await loadInputs(userId, tx);
    const now = Date.now();
    const assessed = ctx.accounts.map((a) => {
      const input = buildAccountInput(a, ctx);
      return { row: a, input, risk: assessAccount(input, now) };
    });
    for (const { row, risk } of assessed) {
      const factors = JSON.stringify({ factors: risk.factors, unknowns: risk.unknowns, critical: risk.critical, excluded: risk.excluded, impact: risk.impact });
      await query(
        `UPDATE discovered_accounts SET risk_score = $2, risk_upper = $3, risk_level = $4, risk_factors = $5::jsonb, risk_model_version = $6, risk_assessed_at = now(),
           exposure_status = CASE WHEN EXISTS (SELECT 1 FROM breach_findings b WHERE b.account_id = discovered_accounts.id) THEN 'confirmed_evidence' ELSE exposure_status END
         WHERE id = $1`,
        [row.id, risk.score, risk.upper, risk.level, factors, MODEL_VERSION],
        tx
      );
    }
    await syncRecommendations(userId, assessed.map(({ input, risk }) => ({ input, risk })), ctx.recs, tx);

    const coverage = await coverageFor(userId, ctx.accounts, tx);
    const dasi = computeDasi(
      assessed.map(({ input, risk }) => ({ id: input.id, serviceName: input.serviceName, manual: input.manual, risk })),
      coverage
    );
    const prev = await queryOne('SELECT * FROM dasi_snapshots WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1', [userId], tx);
    const sig = (s) => JSON.stringify([s.score, s.upper, s.confidence, (s.contributors || []).map((c) => [c.accountId, c.score, c.factors.map((f) => f.code)])]);
    const prevSig = prev ? JSON.stringify([prev.score, prev.upper_bound, prev.confidence, (prev.contributors || []).map((c) => [c.accountId, c.score, c.factors.map((f) => f.code)])]) : null;
    const changed = !prev || prev.model_version !== dasi.modelVersion || prevSig !== sig(dasi);
    let snapshot = prev;
    if (changed) {
      const reasons = explainChange(prev, dasi);
      snapshot = await queryOne(
        `INSERT INTO dasi_snapshots (user_id, model_version, score, upper_bound, level, confidence, coverage, contributors, critical_findings, trigger, previous_score, delta, change_reasons)
         VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9::jsonb,$10,$11,$12,$13::jsonb) RETURNING *`,
        [
          userId, dasi.modelVersion, dasi.score, dasi.upper, dasi.level, dasi.confidence, JSON.stringify(dasi.coverage), JSON.stringify(dasi.contributors),
          JSON.stringify(dasi.criticalFindings), trigger, prev?.score ?? null, prev && prev.score != null && dasi.score != null ? dasi.score - prev.score : null, JSON.stringify(reasons),
        ],
        tx
      );
    }
    const prevCritical = new Set((prev?.critical_findings || []).map((c) => `${c.code}:${c.accountId}`));
    const newCritical = dasi.criticalFindings.filter((c) => !prevCritical.has(`${c.code}:${c.accountId}`));
    return { result: { ...dasi, snapshotId: snapshot?.id || null, assessedAt: new Date().toISOString(), changed }, newCritical };
  });

  // Alerts are created after the transaction commits (they may send email).
  let emailed = 0;
  for (const c of newCritical) {
    const alert = await createAlert(userId, {
      kind: c.code.includes('THREAT') ? 'threat_intel' : c.code.includes('PASSWORD') ? 'breach' : 'account_security',
      severity: c.code === 'UNREMEDIATED_PASSWORD_EXPOSURE' || c.code === 'RECENT_ALERT_UNREVIEWED' ? 'critical' : 'high',
      title: c.code === 'UNREMEDIATED_PASSWORD_EXPOSURE' ? `${c.serviceName}: password exposed in a breach` : c.code === 'RECENT_ALERT_UNREVIEWED' ? `${c.serviceName}: recent security alert` : `${c.serviceName}: needs attention`,
      body: `${c.message} Open FootprintX to see the evidence and the recommended next step.`,
      accountId: c.accountId,
      dedupKey: `critical:${c.code}:${c.accountId}`,
      email: emailed < MAX_ALERT_EMAILS_PER_RECALC,
    });
    if (alert) emailed += 1;
  }
  return result;
}

// ---- Remediation (user-driven) ------------------------------------------------

const USER_TRANSITIONS = {
  recommended: ['in_progress', 'user_reported', 'dismissed'],
  in_progress: ['user_reported', 'dismissed', 'recommended'],
  user_reported: ['recommended', 'dismissed'],
  verification_pending: ['recommended', 'dismissed'],
  unable_to_verify: ['recommended', 'dismissed'],
  dismissed: ['recommended'],
  verified: [],
};

export async function updateRemediation(userId, recId, { status, note, dismissedReason }) {
  const out = await transaction(async (tx) => {
    const r = await queryOne('SELECT r.*, c.status AS connection_status FROM recommendations r LEFT JOIN discovered_accounts a ON a.id = r.account_id LEFT JOIN email_connections c ON c.id = a.connection_id WHERE r.id = $1 AND r.user_id = $2', [recId, userId], tx);
    if (!r) return null;
    if (!USER_TRANSITIONS[r.status]?.includes(status)) {
      throw new HttpError(409, 'INVALID_TRANSITION', r.status === 'verified' ? 'This action is already verified.' : `Cannot change status from ${r.status} to ${status}.`);
    }
    let to = status;
    let deadline = null;
    if (status === 'user_reported' && VERIFIABLE_ACTIONS[r.action_type] && r.connection_status === 'active') {
      to = 'verification_pending';
      deadline = new Date(Date.now() + VERIFICATION_WINDOW_DAYS * DAY);
    }
    await query(
      `UPDATE recommendations SET status = $3, reported_at = CASE WHEN $3 IN ('user_reported','verification_pending') THEN now() ELSE reported_at END,
         verification_deadline = $4, dismissed_reason = CASE WHEN $3 = 'dismissed' THEN $5 ELSE NULL END, status_changed_at = now(), updated_at = now()
       WHERE id = $1 AND user_id = $2`,
      [recId, userId, to, deadline, dismissedReason || null],
      tx
    );
    await query(
      `INSERT INTO remediation_events (user_id, recommendation_id, from_status, to_status, actor, note) VALUES ($1, $2, $3, $4, 'user', $5)`,
      [userId, recId, r.status, to, note ? String(note).slice(0, 500) : null],
      tx
    );
    // Side effects of user reports on the account record (always labelled user-reported).
    if (to !== 'recommended' && to !== 'dismissed' && to !== 'in_progress' && r.account_id) {
      if (r.action_type === 'close_account') await query(`UPDATE discovered_accounts SET account_state = 'closed_user_reported', updated_at = now() WHERE id = $1 AND user_id = $2`, [r.account_id, userId], tx);
      if (r.action_type === 'enable_mfa') {
        await query(
          `UPDATE discovered_accounts SET mfa_status = 'enabled', mfa_source = 'user_reported', mfa_observed_at = now(), updated_at = now()
            WHERE id = $1 AND user_id = $2 AND (mfa_observed_at IS NULL OR mfa_observed_at < now())`,
          [r.account_id, userId],
          tx
        );
      }
    }
    if (to === 'recommended' && r.account_id && r.action_type === 'close_account') {
      await query(`UPDATE discovered_accounts SET account_state = 'unknown' WHERE id = $1 AND user_id = $2 AND account_state = 'closed_user_reported'`, [r.account_id, userId], tx);
    }
    return { id: recId, from: r.status, to };
  });
  if (!out) return null;
  const dasi = await recalculate(userId, 'remediation_update');
  // Verification reads security emails that are already in the database, so
  // without a fresh scan the check could not succeed until the next monitoring
  // run (up to MONITOR_INTERVAL_HOURS later) and "I've done this" would look
  // like it did nothing. Queue a scan now so the confirming email is picked up
  // within a minute. Best-effort: a failure here must not fail the user's
  // report, and enqueueScan de-duplicates against an in-flight scan.
  let verificationScan = null;
  if (out.to === 'verification_pending') {
    verificationScan = await startVerificationScan(userId, recId);
  }
  const rec = await queryOne('SELECT * FROM recommendations WHERE id = $1 AND user_id = $2', [recId, userId]);
  return { recommendation: rec, transition: out, dasi, verificationScan };
}

/**
 * Queues a scan of the mailbox that this recommendation's account came from, so
 * a just-performed change can be confirmed quickly. Returns a small status
 * object for the UI, or null when no scan could be started.
 */
async function startVerificationScan(userId, recId) {
  try {
    const { enqueueScan } = await import('./scanner.js');
    const row = await queryOne(
      `SELECT DISTINCT e.connection_id
         FROM recommendations r
         JOIN account_evidence e ON e.account_id = r.account_id AND e.user_id = r.user_id
         JOIN email_connections c ON c.id = e.connection_id
        WHERE r.id = $1 AND r.user_id = $2 AND c.status = 'active'
        ORDER BY e.connection_id LIMIT 1`,
      [recId, userId]
    );
    if (!row) return null;
    const { job, deduplicated } = await enqueueScan(userId, row.connection_id, 'verification');
    return { jobId: job?.id || null, connectionId: row.connection_id, deduplicated };
  } catch (err) {
    // A disconnected or rate-limited mailbox is normal here; verification still
    // happens on the next scheduled scan, and the deadline job handles timeout.
    log.info('verification scan could not be queued', { recId, err: err.code || err.message });
    return null;
  }
}

export async function listRecommendations(userId, { includeInactive = false } = {}) {
  return query(
    `SELECT r.*, a.service_name, a.service_domain, a.is_synthetic FROM recommendations r LEFT JOIN discovered_accounts a ON a.id = r.account_id
      WHERE r.user_id = $1 AND ($2 OR r.applicable OR r.status NOT IN ('recommended','in_progress'))
        AND (a.id IS NULL OR a.status = 'confirmed')
      ORDER BY CASE r.status WHEN 'recommended' THEN 0 WHEN 'in_progress' THEN 1 WHEN 'verification_pending' THEN 2 WHEN 'user_reported' THEN 3 WHEN 'unable_to_verify' THEN 4 WHEN 'verified' THEN 5 ELSE 6 END, r.priority DESC`,
    [userId, includeInactive]
  );
}

export async function remediationHistory(userId, limit = 100) {
  return query(
    `SELECT e.id, e.recommendation_id, e.from_status, e.to_status, e.actor, e.note, e.evidence, e.created_at, r.title, r.action_type
       FROM remediation_events e JOIN recommendations r ON r.id = e.recommendation_id WHERE e.user_id = $1 ORDER BY e.created_at DESC LIMIT $2`,
    [userId, limit]
  );
}

export async function latestDasi(userId) {
  return queryOne('SELECT * FROM dasi_snapshots WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1', [userId]);
}

export async function dasiHistory(userId, limit = 90) {
  return query(
    'SELECT id, model_version, score, upper_bound, level, confidence, trigger, previous_score, delta, change_reasons, created_at FROM dasi_snapshots WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2',
    [userId, limit]
  );
}
