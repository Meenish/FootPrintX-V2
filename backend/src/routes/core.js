// Connections, scans, accounts, DASI, recommendations, alerts, activity, breaches.
import { Router } from 'express';
import { z } from 'zod';
import { ah, validate, notFound, HttpError } from '../http.js';
import { limits, requireAuth } from '../middleware.js';
import { getConfig } from '../config.js';
import { query, queryOne } from '../db.js';
import { audit } from '../services/audit.js';
import { log } from '../logger.js';
import {
  listConnections, startGoogleConnect, completeGoogleConnect, connectSynthetic, disconnectConnection, deleteConnection, getOwnedConnection,
} from '../services/connections.js';
import { injectSyntheticMessage } from '../services/synthetic.js';
import { enqueueScan, getJob, listJobs, requestCancel } from '../services/scanner.js';
import { listAccounts, getAccount, addManualAccount, correctAccount, deleteManualAccount } from '../services/accounts.js';
import { recalculate, updateRemediation, listRecommendations, remediationHistory, latestDasi, dasiHistory } from '../services/risk.js';
import { MODEL_VERSION, WEIGHTS, DASI_LEVELS, ACCOUNT_LEVELS, CONFIDENCE_WEIGHT, REMEDIATION_MULTIPLIER, MFA_DAMPENING, AGGREGATION } from '../services/dasi.js';
import { CATEGORY_IMPACT, CATEGORY_LABELS } from '../services/catalog.js';
import { listAlerts, setAlertStatus } from '../services/notifications.js';
import { runBreachCheck, getConsent, setConsent, breachOverview, configuredProvider, CONSENT_POLICY_VERSION } from '../services/breach.js';
import { getEntitlement } from '../services/billing.js';
import { listExtensionEvents, listExtensionSessions } from '../services/extension.js';

const uuidParam = z.object({ id: z.string().uuid() });
const web = requireAuth({ kinds: ['web'] });

export const coreRouter = Router();

// ---- Connections --------------------------------------------------------------------
coreRouter.get('/connections', web, ah(async (req, res) => {
  const items = await listConnections(req.user.id);
  const lastJobs = await query(
    `SELECT DISTINCT ON (connection_id) connection_id, id, status, stage, progress, finished_at, created_at, error_message FROM scan_jobs WHERE user_id = $1 ORDER BY connection_id, created_at DESC`,
    [req.user.id]
  );
  res.json({ items: items.map((c) => ({ ...c, latestScan: lastJobs.find((j) => j.connection_id === c.id) || null })), googleConfigured: getConfig().google.configured, scopeMode: getConfig().google.scopeMode, syntheticDataEnabled: getConfig().syntheticData });
}));

coreRouter.post('/connections/google/start', web, limits.sensitive, ah(async (req, res) => {
  const out = await startGoogleConnect(req.user.id);
  await audit('oauth_started', { userId: req.user.id, req, detail: { scopeMode: out.scopeMode } });
  res.json(out);
}));

// Google redirects the browser here. The response is always a redirect back
// to the web app with a short status code, never JSON or error details.
coreRouter.get('/connections/google/callback', limits.sensitive, ah(async (req, res) => {
  const app = getConfig().appUrl;
  const back = (params) => res.redirect(303, `${app}/settings?${new URLSearchParams({ tab: 'connections', ...params })}`);
  if (req.query.error) {
    await audit('oauth_denied', { req, detail: { error: String(req.query.error).slice(0, 40) } });
    return back({ oauth: 'denied' });
  }
  try {
    const result = await completeGoogleConnect({ state: req.query.state, code: req.query.code, sessionUserId: req.auth?.user.id });
    await audit('oauth_connected', { userId: result.userId, req, detail: { reconnected: result.reconnected } });
    const { job } = await enqueueScan(result.userId, result.connectionId, 'onboarding');
    return back({ oauth: 'connected', connection: result.connectionId, scan: job.id });
  } catch (err) {
    log.warn('oauth callback failed', { code: err.code, err });
    await audit('oauth_failed', { userId: req.auth?.user.id || null, req, detail: { code: err.code || 'UNKNOWN' } });
    return back({ oauth: 'error', reason: err.code || 'UNKNOWN' });
  }
}));

coreRouter.post('/connections/synthetic', web, ah(async (req, res) => {
  const result = await connectSynthetic(req.user.id);
  const { job } = await enqueueScan(req.user.id, result.connectionId, 'onboarding');
  await audit('synthetic_connected', { userId: req.user.id, req });
  res.status(201).json({ connectionId: result.connectionId, scanJob: job, synthetic: true });
}));

coreRouter.post('/connections/:id/disconnect', web, limits.sensitive, validate({ params: uuidParam, body: z.object({ deleteFindings: z.boolean().default(false) }).strict() }), ah(async (req, res) => {
  const out = await disconnectConnection(req.user.id, req.params.id, req.body);
  if (!out) throw notFound('Connection');
  await audit('connection_disconnected', { userId: req.user.id, req, detail: out });
  const dasi = await recalculate(req.user.id, 'connection_change');
  res.json({ ...out, dasi });
}));

coreRouter.delete('/connections/:id', web, validate({ params: uuidParam }), ah(async (req, res) => {
  const out = await deleteConnection(req.user.id, req.params.id);
  if (!out) throw notFound('Connection');
  await audit('connection_deleted', { userId: req.user.id, req });
  await recalculate(req.user.id, 'connection_change');
  res.status(204).end();
}));

coreRouter.post('/connections/:id/scan', web, limits.scans, validate({ params: uuidParam }), ah(async (req, res) => {
  const out = await enqueueScan(req.user.id, req.params.id, 'manual');
  await audit('scan_requested', { userId: req.user.id, req, detail: { deduplicated: out.deduplicated } });
  res.status(202).json(out);
}));

coreRouter.post('/connections/:id/breach-check', web, limits.breach, validate({ params: uuidParam, body: z.object({ force: z.boolean().default(false) }).strict() }), ah(async (req, res) => {
  const out = await runBreachCheck(req.user.id, req.params.id, req.body);
  await audit('breach_check', { userId: req.user.id, req, detail: { status: out.status, provider: out.provider, cached: out.cached, errorCode: out.errorCode } });
  res.json(out);
}));

coreRouter.post('/connections/:id/synthetic-events', web, validate({
  params: uuidParam,
  body: z.object({ kind: z.enum(['password_changed', 'mfa_enabled', 'security_alert', 'signup']), domain: z.string().regex(/^[a-z0-9.-]+\.[a-z]{2,}$/).max(100), serviceName: z.string().max(60).optional() }).strict(),
}), ah(async (req, res) => {
  const conn = await getOwnedConnection(req.user.id, req.params.id);
  if (!conn) throw notFound('Connection');
  await injectSyntheticMessage(req.user.id, conn, req.body);
  res.status(201).json({ ok: true, synthetic: true, note: 'Synthetic message added. Run a scan to process it.' });
}));

// ---- Scans -------------------------------------------------------------------------------
coreRouter.get('/scans', web, ah(async (req, res) => res.json({ items: await listJobs(req.user.id) })));
coreRouter.get('/scans/:id', web, validate({ params: uuidParam }), ah(async (req, res) => {
  const job = await getJob(req.user.id, req.params.id);
  if (!job) throw notFound('Scan');
  res.json(job);
}));
coreRouter.post('/scans/:id/cancel', web, validate({ params: uuidParam }), ah(async (req, res) => {
  const job = await requestCancel(req.user.id, req.params.id);
  if (!job) throw new HttpError(409, 'NOT_CANCELLABLE', 'This scan has already finished.');
  res.json(job);
}));

// ---- Accounts --------------------------------------------------------------------------
coreRouter.get('/accounts', web, validate({ query: z.object({ status: z.enum(['confirmed', 'possible', 'dismissed']).optional() }) }), ah(async (req, res) => {
  const items = await listAccounts(req.user.id, req.validQuery);
  res.json({ items });
}));

coreRouter.post('/accounts', web, validate({ body: z.object({ serviceName: z.string().trim().max(80).optional(), domain: z.string().trim().max(253).optional(), identifier: z.string().trim().max(120).optional() }).strict() }), ah(async (req, res) => {
  const id = await addManualAccount(req.user.id, req.body);
  await audit('account_added_manually', { userId: req.user.id, req });
  await recalculate(req.user.id, 'user_correction');
  res.status(201).json(await getAccount(req.user.id, id));
}));

coreRouter.get('/accounts/export.csv', web, ah(async (req, res) => {
  const rows = await listAccounts(req.user.id);
  const esc = (v) => {
    const s = v == null ? '' : v instanceof Date ? v.toISOString() : String(v);
    // Neutralize spreadsheet formula injection and quote every cell.
    return `"${(/^[=+\-@\t\r]/.test(s) ? `'${s}` : s).replace(/"/g, '""')}"`;
  };
  const cols = ['service_name', 'service_domain', 'category', 'status', 'discovery_source', 'confidence', 'manually_added', 'connection_email', 'mfa_status', 'mfa_source', 'exposure_status', 'account_state', 'risk_score', 'risk_level', 'first_observed_at', 'last_observed_at', 'last_checked_at', 'is_synthetic'];
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="footprintx-accounts.csv"');
  res.send([cols.join(','), ...rows.map((r) => cols.map((c) => esc(r[c])).join(','))].join('\r\n'));
}));

coreRouter.get('/accounts/:id', web, validate({ params: uuidParam }), ah(async (req, res) => {
  const detail = await getAccount(req.user.id, req.params.id);
  if (!detail) throw notFound('Account');
  res.json(detail);
}));

coreRouter.patch('/accounts/:id', web, validate({
  params: uuidParam,
  body: z.object({
    action: z.enum(['dismiss', 'confirm', 'restore']).optional(),
    reason: z.enum(['not_mine', 'duplicate', 'not_an_account', 'other']).optional(),
    serviceName: z.string().trim().min(1).max(80).optional(),
    mfaStatus: z.enum(['enabled', 'disabled', 'unknown']).optional(),
    accountState: z.enum(['closed', 'open']).optional(),
  }).strict().refine((b) => Object.keys(b).length > 0, 'Nothing to update.'),
}), ah(async (req, res) => {
  const out = await correctAccount(req.user.id, req.params.id, req.body);
  if (!out) throw notFound('Account');
  await audit('account_corrected', { userId: req.user.id, req, detail: { fields: Object.keys(req.body) } });
  await recalculate(req.user.id, 'user_correction');
  res.json(await getAccount(req.user.id, req.params.id));
}));

coreRouter.delete('/accounts/:id', web, validate({ params: uuidParam }), ah(async (req, res) => {
  if (!(await deleteManualAccount(req.user.id, req.params.id))) throw new HttpError(404, 'NOT_FOUND', 'Only manually added accounts can be deleted. Dismiss discovered accounts instead.');
  await recalculate(req.user.id, 'user_correction');
  res.status(204).end();
}));

// ---- DASI ---------------------------------------------------------------------------------
async function currentDasi(userId) {
  const latest = await latestDasi(userId);
  if (!latest || latest.model_version !== MODEL_VERSION) {
    await recalculate(userId, latest ? 'model_change' : 'initial');
    return latestDasi(userId);
  }
  return latest;
}

export const METHODOLOGY = Object.freeze({
  modelVersion: MODEL_VERSION,
  disclaimer: 'DASI is FootprintX’s own index, not an industry standard. It summarises the evidence FootprintX has; it cannot see accounts or risks it has no evidence for.',
  range: '0–100; higher means more observed risk.',
  weights: WEIGHTS,
  confidenceWeights: CONFIDENCE_WEIGHT,
  remediationMultipliers: REMEDIATION_MULTIPLIER,
  mfaDampening: MFA_DAMPENING,
  categoryImpact: Object.fromEntries(Object.entries(CATEGORY_IMPACT).map(([k, v]) => [k, { multiplier: v, label: CATEGORY_LABELS[k] }])),
  aggregation: AGGREGATION,
  levels: DASI_LEVELS,
  accountLevels: ACCOUNT_LEVELS,
  unknowns: 'Unknown values (e.g. two-step verification status) are never scored as safe. They raise the upper bound and lower the stated confidence.',
});

coreRouter.get('/dasi', web, ah(async (req, res) => {
  const snapshot = await currentDasi(req.user.id);
  res.json({ snapshot, methodology: METHODOLOGY });
}));
coreRouter.get('/dasi/history', web, ah(async (req, res) => res.json({ items: await dasiHistory(req.user.id) })));
coreRouter.post('/dasi/recalculate', web, limits.sensitive, ah(async (req, res) => res.json(await recalculate(req.user.id, 'manual'))));

// ---- Recommendations ---------------------------------------------------------------------
coreRouter.get('/recommendations', web, ah(async (req, res) => res.json({ items: await listRecommendations(req.user.id) })));
coreRouter.get('/recommendations/history', web, ah(async (req, res) => res.json({ items: await remediationHistory(req.user.id) })));
coreRouter.patch('/recommendations/:id', web, validate({
  params: uuidParam,
  body: z.object({
    status: z.enum(['recommended', 'in_progress', 'user_reported', 'dismissed']),
    note: z.string().trim().max(500).optional(),
    dismissedReason: z.enum(['not_relevant', 'already_done', 'accept_risk', 'not_my_account', 'other']).optional(),
  }).strict(),
}), ah(async (req, res) => {
  const out = await updateRemediation(req.user.id, req.params.id, req.body);
  if (!out) throw notFound('Recommendation');
  await audit('remediation_updated', { userId: req.user.id, req, detail: { from: out.transition.from, to: out.transition.to } });
  // Tells the UI whether a confirmation check actually started, so the
  // "we're looking now" line is only shown when it is true.
  if (out.recommendation) out.recommendation.verification_scan_started = Boolean(out.verificationScan);
  res.json(out);
}));

// ---- Alerts ----------------------------------------------------------------------------------
coreRouter.get('/alerts', web, validate({ query: z.object({ status: z.enum(['unread', 'read', 'dismissed']).optional() }) }), ah(async (req, res) => res.json({ items: await listAlerts(req.user.id, req.validQuery) })));
coreRouter.patch('/alerts/:id', web, validate({ params: uuidParam, body: z.object({ status: z.enum(['read', 'dismissed', 'unread']) }).strict() }), ah(async (req, res) => {
  const a = await setAlertStatus(req.user.id, req.params.id, req.body.status);
  if (!a) throw notFound('Alert');
  res.json(a);
}));
coreRouter.post('/alerts/read-all', web, ah(async (req, res) => {
  await query("UPDATE alerts SET status = 'read', updated_at = now() WHERE user_id = $1 AND status = 'unread'", [req.user.id]);
  res.json({ ok: true });
}));

// ---- Breach intelligence ------------------------------------------------------------------
coreRouter.get('/breaches', web, ah(async (req, res) => {
  const [overview, consent] = await Promise.all([breachOverview(req.user.id), getConsent(req.user.id)]);
  const provider = configuredProvider();
  res.json({
    provider,
    consent: consent ? { ...consent, current: !!consent.granted_at && !consent.revoked_at && consent.provider === provider?.name && consent.policy_version === CONSENT_POLICY_VERSION } : null,
    policyVersion: CONSENT_POLICY_VERSION,
    ...overview,
    limitations: [
      'A listing means your email address appeared in that breach dataset. It does not prove your current password is known, that you reused it, or that the account is compromised today.',
      'No listing means no evidence was found by this provider at that time — not that the address was never breached.',
      'Changing a password does not remove a historical breach record.',
    ],
  });
}));
coreRouter.post('/breaches/consent', web, validate({ body: z.object({ granted: z.boolean() }).strict() }), ah(async (req, res) => {
  const consent = await setConsent(req.user.id, req.body.granted);
  await audit(req.body.granted ? 'breach_consent_granted' : 'breach_consent_revoked', { userId: req.user.id, req, detail: { provider: consent.provider, policyVersion: consent.policy_version } });
  res.json(consent);
}));

// ---- Dashboard & activity ------------------------------------------------------------------
coreRouter.get('/dashboard', web, ah(async (req, res) => {
  const userId = req.user.id;
  const dasi = await currentDasi(userId);
  const [accounts, recs, alerts, connections, jobs, entitlement, extSessions, checks, synth] = await Promise.all([
    query("SELECT status, count(*)::int AS n FROM discovered_accounts WHERE user_id = $1 GROUP BY status", [userId]),
    listRecommendations(userId),
    listAlerts(userId, { limit: 8 }),
    listConnections(userId),
    listJobs(userId, 5),
    getEntitlement(userId),
    listExtensionSessions(userId),
    query('SELECT domain, status, checked_at FROM domain_checks WHERE user_id = $1 ORDER BY checked_at DESC LIMIT 5', [userId]),
    queryOne('SELECT bool_or(is_synthetic) AS any FROM email_connections WHERE user_id = $1', [userId]),
  ]);
  const count = (s) => accounts.find((a) => a.status === s)?.n || 0;
  const open = recs.filter((r) => r.applicable && ['recommended', 'in_progress'].includes(r.status));
  res.json({
    dasi,
    accounts: { confirmed: count('confirmed'), possible: count('possible'), dismissed: count('dismissed'), definitions: { confirmed: 'Services with strong evidence (e.g. a signup, verification or security email) or a breach listing for your address, plus accounts you added.', possible: 'Weak signals only (e.g. receipts). Not counted in DASI until you confirm them.' } },
    recommendations: { open: open.length, top: open.slice(0, 5), awaitingVerification: recs.filter((r) => r.status === 'verification_pending').length },
    alerts: { unread: alerts.filter((a) => a.status === 'unread').length, recent: alerts },
    connections,
    scans: jobs,
    entitlement,
    extension: { linkedBrowsers: extSessions.length, lastSeenAt: extSessions[0]?.last_seen_at || null },
    websiteChecks: checks,
    syntheticData: !!synth?.any,
  });
}));

coreRouter.get('/activity', web, validate({ query: z.object({ days: z.coerce.number().int().min(1).max(365).default(30) }) }), ah(async (req, res) => {
  const ent = await getEntitlement(req.user.id);
  const days = Math.min(req.validQuery.days, ent.features.advancedHistoryDays);
  const userId = req.user.id;
  const since = new Date(Date.now() - days * 864e5);
  const [scans, alerts, rem, dasi, ext, checks] = await Promise.all([
    query('SELECT j.id, j.status, j.trigger, j.summary, j.error_message, j.created_at, j.finished_at, c.email_masked FROM scan_jobs j JOIN email_connections c ON c.id = j.connection_id WHERE j.user_id = $1 AND j.created_at > $2 ORDER BY j.created_at DESC LIMIT 200', [userId, since]),
    query('SELECT id, kind, severity, title, body, status, domain, account_id, created_at FROM alerts WHERE user_id = $1 AND created_at > $2 ORDER BY created_at DESC LIMIT 200', [userId, since]),
    query('SELECT e.id, e.from_status, e.to_status, e.actor, e.note, e.created_at, r.title FROM remediation_events e JOIN recommendations r ON r.id = e.recommendation_id WHERE e.user_id = $1 AND e.created_at > $2 ORDER BY e.created_at DESC LIMIT 200', [userId, since]),
    query('SELECT id, score, previous_score, delta, level, confidence, trigger, change_reasons, created_at FROM dasi_snapshots WHERE user_id = $1 AND created_at > $2 ORDER BY created_at DESC LIMIT 200', [userId, since]),
    listExtensionEvents(userId, { days }),
    query('SELECT id, domain, status, reasons, checked_at FROM domain_checks WHERE user_id = $1 AND checked_at > $2 ORDER BY checked_at DESC LIMIT 200', [userId, since]),
  ]);
  res.json({ days, maxDays: ent.features.advancedHistoryDays, plan: ent.plan, scans, alerts, remediation: rem, scoreChanges: dasi, extensionEvents: ext, websiteChecks: checks });
}));
