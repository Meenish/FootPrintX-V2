// Integration: the core Free workflow end to end on the synthetic mailbox.
// Discover → Inventory → Assess → Prioritize → Secure → Verify → Monitor.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestApp, registerAndLogin, connectSyntheticAndScan, drain } from './helpers.js';
import { registeredOfficialDomains } from '../src/services/catalog.js';

const REGISTRY_DOMAINS = registeredOfficialDomains();

let t;
let client;
let connectionId;
before(async () => {
  t = await startTestApp();
  ({ client } = await registerAndLogin(t));
});
after(() => t.close());

const accountsByName = async () => Object.fromEntries((await client.get('/api/accounts')).body.items.map((a) => [a.service_name, a]));

test('before any scan, DASI is "not assessed" (never zero)', async () => {
  const d = await client.get('/api/dasi');
  assert.equal(d.status, 200);
  assert.equal(d.body.snapshot.score, null);
  assert.equal(d.body.snapshot.confidence, 'none');
  assert.match(d.body.methodology.disclaimer, /not an industry standard/);
});

test('synthetic scan discovers evidence-backed accounts, persists them and reports real progress', async () => {
  const out = await connectSyntheticAndScan(client);
  connectionId = out.connectionId;
  const job = (await client.get(`/api/scans/${out.scanJob.id}`)).body;
  assert.equal(job.status, 'completed');
  assert.equal(job.progress.messagesProcessed, 21);
  assert.equal(job.progress.messagesListed, 21);
  assert.deepEqual(job.source_results.map((s) => s.status), ['ok']);
  const acc = await accountsByName();
  for (const name of ['GitHub', 'Adobe', 'Spotify', 'Canva', 'Dropbox', 'LinkedIn', 'Swiggy', 'Google Account', 'Netflix']) assert.equal(acc[name]?.status, 'confirmed', name);
  assert.equal(acc.Zomato.status, 'possible', 'receipts alone are only a possible association');
  assert.equal(acc.PayPal, undefined, 'spoofed security mail does not create an account');
  assert.equal(acc.TechCrunch, undefined, 'newsletters do not create accounts');
  assert.equal(acc.Dropbox.mfa_status, 'disabled');
  assert.equal(acc.Canva.mfa_status, 'enabled');
  assert.equal(acc.Canva.mfa_source, 'mailbox_evidence');
  assert.equal(acc.Netflix.account_state, 'closed_evidence');
  assert.equal(acc.GitHub.exposure_status, 'unknown', 'not checked yet is unknown, not clean');
  assert.ok(Object.values(acc).every((a) => a.is_synthetic));
});

test('re-scanning is idempotent: no duplicate accounts or evidence', async () => {
  const before1 = (await client.get('/api/accounts')).body.items.length;
  const gh = (await accountsByName()).GitHub;
  const ev1 = (await client.get(`/api/accounts/${gh.id}`)).body.evidence.length;
  const r = await client.post(`/api/connections/${connectionId}/scan`, {});
  assert.equal(r.status, 202);
  const dup = await client.post(`/api/connections/${connectionId}/scan`, {});
  assert.equal(dup.body.deduplicated, true, 'a second trigger joins the queued job');
  await drain();
  assert.equal((await client.get('/api/accounts')).body.items.length, before1);
  assert.equal((await client.get(`/api/accounts/${gh.id}`)).body.evidence.length, ev1);
});

test('account detail exposes provenance without message content', async () => {
  const gh = (await accountsByName()).GitHub;
  const d = (await client.get(`/api/accounts/${gh.id}`)).body;
  assert.ok(d.evidence.some((e) => e.kind === 'security_alert' && e.sender_authenticated === 'pass'));
  const text = JSON.stringify(d);
  assert.ok(!/Unusual sign-in activity/i.test(text), 'subjects are never stored');
  assert.ok(!text.includes('syn-02'), 'message ids are stored only as keyed hashes');
});

test('breach check links findings by exact domain, adds breach-only accounts and marks others "no evidence found"', async () => {
  const r = await client.post(`/api/connections/${connectionId}/breach-check`, {});
  assert.equal(r.status, 200);
  assert.equal(r.body.status, 'ok');
  assert.equal(r.body.breachCount, 4);
  const acc = await accountsByName();
  assert.equal(acc.Adobe.exposure_status, 'confirmed_evidence');
  assert.equal(acc.Canva.exposure_status, 'confirmed_evidence');
  assert.equal(acc.Spotify.exposure_status, 'no_evidence_found');
  assert.equal(acc.Dailymotion.discovery_source, 'breach_record');
  assert.equal(acc.Dailymotion.status, 'confirmed');
  assert.equal(acc.ExampleComboList.status, 'possible', 'breach without a domain is only a possible association');
  const cached = await client.post(`/api/connections/${connectionId}/breach-check`, {});
  assert.equal(cached.body.cached, true, 'freshness window respected');
});

test('DASI is computed with coverage, confidence, contributors and critical findings', async () => {
  const d = (await client.get('/api/dasi')).body.snapshot;
  assert.ok(d.score > 0 && d.score <= 100);
  assert.ok(d.upper_bound >= d.score);
  assert.ok(['low', 'medium', 'high'].includes(d.confidence));
  assert.ok(d.coverage.accountsAssessed >= 9);
  assert.ok(d.critical_findings.some((c) => c.code === 'UNREMEDIATED_PASSWORD_EXPOSURE' && c.serviceName === 'Adobe'));
  assert.ok(d.critical_findings.some((c) => c.code === 'RECENT_ALERT_UNREVIEWED' && c.serviceName === 'GitHub'));
  const hist = (await client.get('/api/dasi/history')).body.items;
  assert.ok(hist.length >= 2);
  assert.ok(hist[0].change_reasons.length >= 1);
  const alerts = (await client.get('/api/alerts')).body.items;
  assert.ok(alerts.some((a) => a.severity === 'critical' && /Adobe/.test(a.title)));
});

test('recommendations are prioritized, evidence-based and link only to verified official pages', async () => {
  const recs = (await client.get('/api/recommendations')).body.items;
  assert.ok(recs.length >= 5);
  const sev = { critical: 4, high: 3, medium: 2, low: 1 };
  const open = recs.filter((r) => r.status === 'recommended');
  for (let i = 1; i < open.length; i += 1) assert.ok(open[i - 1].priority >= open[i].priority);
  assert.ok(sev[open[0].severity] >= 3);
  const adobe = recs.find((r) => r.service_name === 'Adobe' && r.action_type === 'change_password');
  assert.ok(adobe.evidence.length > 0);
  assert.ok(adobe.official_url?.startsWith('https://account.adobe.com/') || adobe.official_url_kind === 'none');
  // A service with no registry entry falls back to its own canonical home page
  // (kind 'domain_root'), never to an invented settings path. The distinction
  // matters: the UI labels this as a home page, not a verified deep link.
  const fallback = recs.find((r) => r.official_url_kind === 'domain_root');
  if (fallback) {
    assert.match(fallback.official_url, /^https:\/\/[a-z0-9.-]+\/$/, 'the fallback is a bare origin with no invented path');
    assert.ok(fallback.official_url.includes(fallback.service_domain), 'the fallback points at the service’s own domain');
  }
  // Nothing may claim to be a verified deep link unless it came from the registry.
  for (const r of recs) {
    if (r.official_url_kind === 'settings_page' || r.official_url_kind === 'help_page') {
      assert.ok(REGISTRY_DOMAINS.includes(r.service_domain), `${r.service_domain} has a verified link but is not in the registry`);
    }
  }
});

test('user-reported completion is not "verified"; a later security email verifies it independently', async () => {
  const adobeRec = (await client.get('/api/recommendations')).body.items.find((r) => r.service_name === 'Adobe' && r.action_type === 'change_password');
  const before1 = (await client.get('/api/dasi')).body.snapshot.score;
  const reported = await client.patch(`/api/recommendations/${adobeRec.id}`, { status: 'user_reported', note: 'Changed it' });
  assert.equal(reported.status, 200);
  assert.equal(reported.body.recommendation.status, 'verification_pending', 'verifiable action with active mailbox waits for evidence');
  assert.ok(reported.body.dasi.score < before1, 'user report gives partial credit');
  const bad = await client.patch(`/api/recommendations/${adobeRec.id}`, { status: 'verified' });
  assert.equal(bad.status, 400, 'users cannot mark items verified');

  // Reporting a verifiable action queues a scan immediately, so the confirming
  // email is looked for within a minute instead of at the next scheduled run.
  // Without this the user presses "I've done this" and nothing visibly happens.
  assert.ok(reported.body.verificationScan, 'a verification scan was started');
  assert.equal(reported.body.verificationScan.connectionId, connectionId);
  assert.equal(reported.body.recommendation.verification_scan_started, true);
  const queued = (await client.get('/api/scans')).body.items;
  assert.ok(queued.some((j) => j.trigger === 'verification'), 'the scan is recorded as a verification run');
  await drain();

  // The service's own security notification arrives (synthetic), then a scan runs.
  await client.post(`/api/connections/${connectionId}/synthetic-events`, { kind: 'password_changed', domain: 'adobe.com', serviceName: 'Adobe' });
  await client.post(`/api/connections/${connectionId}/scan`, {});
  await drain();
  const after1 = (await client.get('/api/recommendations')).body.items.find((r) => r.id === adobeRec.id);
  assert.equal(after1.status, 'verified');
  assert.equal(after1.verification_evidence.kind, 'password_changed');
  const score2 = (await client.get('/api/dasi')).body.snapshot.score;
  assert.ok(score2 < reported.body.dasi.score, 'verified change reduces risk further');

  const detail = (await client.get(`/api/accounts/${adobeRec.account_id}`)).body;
  assert.equal(detail.breaches.length, 1, 'historical breach record retained after remediation');
  const factors = detail.account.risk_factors.factors.map((f) => f.code);
  assert.ok(factors.includes('CREDENTIAL_EXPOSURE_PASSWORD'));
  const history = (await client.get('/api/recommendations/history')).body.items.filter((e) => e.recommendation_id === adobeRec.id);
  assert.deepEqual(history.map((h) => [h.actor, h.to_status]).reverse(), [['user', 'verification_pending'], ['system', 'verified']]);
});

test('non-verifiable actions stay "user_reported"; closing an account is recorded as user-reported', async () => {
  const recs = (await client.get('/api/recommendations')).body.items;
  const review = recs.find((r) => r.action_type === 'review_sessions');
  const r1 = await client.patch(`/api/recommendations/${review.id}`, { status: 'user_reported' });
  assert.equal(r1.body.recommendation.status, 'user_reported');
  const close = recs.find((r) => r.action_type === 'close_account' && r.service_name === 'Dropbox');
  await client.patch(`/api/recommendations/${close.id}`, { status: 'user_reported' });
  const dropbox = (await accountsByName()).Dropbox;
  assert.equal(dropbox.account_state, 'closed_user_reported');
  assert.equal(dropbox.risk_score, 0);
});

test('false positives can be dismissed and stay dismissed across re-scans; manual entries are labelled', async () => {
  const swiggy = (await accountsByName()).Swiggy;
  const dismissed = await client.patch(`/api/accounts/${swiggy.id}`, { action: 'dismiss', reason: 'not_mine' });
  assert.equal(dismissed.body.account.status, 'dismissed');
  await client.post(`/api/connections/${connectionId}/scan`, {});
  await drain();
  assert.equal((await accountsByName()).Swiggy.status, 'dismissed');
  const manual = await client.post('/api/accounts', { domain: 'https://www.github.com/login', serviceName: 'Work GitHub' });
  assert.equal(manual.status, 201);
  assert.equal(manual.body.account.discovery_source, 'manual');
  assert.equal(manual.body.account.manually_added, true);
  assert.equal(manual.body.account.service_domain, 'github.com');
  const dupe = await client.post('/api/accounts', { domain: 'github.com' });
  assert.equal(dupe.status, 409);
  const rename = await client.patch(`/api/accounts/${manual.body.account.id}`, { serviceName: 'GitHub (work)' });
  assert.equal(rename.body.account.service_name, 'GitHub (work)');
  assert.equal((await client.del(`/api/accounts/${manual.body.account.id}`)).status, 204);
  assert.equal((await client.del(`/api/accounts/${swiggy.id}`)).status, 404, 'discovered accounts are dismissed, not deleted');
});

test('inventory CSV export neutralises spreadsheet formulas', async () => {
  await client.post('/api/accounts', { serviceName: '=HYPERLINK("http://evil")' });
  const res = await client.req('GET', '/api/accounts/export.csv', undefined, { raw: true });
  const text = await res.text();
  assert.match(res.headers.get('content-type'), /text\/csv/);
  assert.ok(text.includes(`"'=HYPERLINK(""http://evil"")"`));
});

test('dashboard aggregates only persisted data and labels synthetic data', async () => {
  const d = (await client.get('/api/dashboard')).body;
  assert.equal(d.syntheticData, true);
  assert.ok(d.accounts.confirmed >= 9);
  assert.ok(d.accounts.possible >= 1);
  assert.ok(d.dasi.score != null);
  assert.ok(Array.isArray(d.recommendations.top));
  assert.equal(d.entitlement.plan, 'free');
});

test('activity timeline separates scans, alerts, remediation and score changes', async () => {
  const a = (await client.get('/api/activity?days=30')).body;
  assert.ok(a.scans.length >= 3);
  assert.ok(a.remediation.length >= 2);
  assert.ok(a.scoreChanges.length >= 2);
  assert.ok(Array.isArray(a.extensionEvents));
  assert.equal(a.maxDays, 30, 'Free history window');
  const capped = (await client.get('/api/activity?days=365')).body;
  assert.equal(capped.days, 30);
});

test('disconnecting stops future scans and keeps or deletes findings as chosen', async () => {
  const r = await client.post(`/api/connections/${connectionId}/disconnect`, { deleteFindings: false });
  assert.equal(r.status, 200);
  assert.equal(r.body.revokeResult, 'not_applicable');
  const scan = await client.post(`/api/connections/${connectionId}/scan`, {});
  assert.equal(scan.status, 409);
  assert.ok((await client.get('/api/accounts')).body.items.length > 0, 'findings kept');
  const conns = (await client.get('/api/connections')).body.items;
  assert.equal(conns[0].status, 'disconnected');
  const breach = await client.post(`/api/connections/${connectionId}/breach-check`, {});
  assert.equal(breach.status, 409);
  await client.post(`/api/connections/${connectionId}/disconnect`, { deleteFindings: true });
  const remaining = (await client.get('/api/accounts')).body.items.filter((a) => !a.manually_added);
  assert.equal(remaining.length, 0);
  assert.equal((await client.del(`/api/connections/${connectionId}`)).status, 204);
});
