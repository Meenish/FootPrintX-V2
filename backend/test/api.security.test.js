// Integration: authorization boundaries, breach-provider failure handling,
// notifications, privacy export/deletion, log hygiene, migrations.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { startTestApp, registerAndLogin, connectSyntheticAndScan, STRONG_PASSWORD, logLines } from './helpers.js';

let t;
let A; // victim
let B; // attacker
const sent = [];
before(async () => {
  t = await startTestApp({ SMTP_HOST: 'smtp.test', SMTP_FROM: 'no-reply@footprintx.test', SECURITY_EMAILS_PER_DAY: '2' });
  const { setMailTransport } = await import('../src/services/notifications.js');
  setMailTransport({
    sendMail: async (m) => {
      if (m.to === 'fail@example.com') throw Object.assign(new Error('smtp down'), { code: 'ECONNREFUSED' });
      sent.push(m);
      return { accepted: [m.to], rejected: [] };
    },
  });
  A = await registerAndLogin(t, 'victim@example.com');
  B = await registerAndLogin(t, 'attacker@example.com');
  A.conn = (await connectSyntheticAndScan(A.client)).connectionId;
  await A.client.post(`/api/connections/${A.conn}/breach-check`, {});
});
after(() => t.close());

test('authorization: another userâ€™s resources are invisible and immutable (no IDOR)', async () => {
  const acc = (await A.client.get('/api/accounts')).body.items[0];
  const rec = (await A.client.get('/api/recommendations')).body.items[0];
  const alert = (await A.client.get('/api/alerts')).body.items[0];
  const scan = (await A.client.get('/api/scans')).body.items[0];
  const probes = [
    ['GET', `/api/accounts/${acc.id}`],
    ['PATCH', `/api/accounts/${acc.id}`, { action: 'dismiss' }],
    ['DELETE', `/api/accounts/${acc.id}`],
    ['PATCH', `/api/recommendations/${rec.id}`, { status: 'dismissed' }],
    ['PATCH', `/api/alerts/${alert.id}`, { status: 'dismissed' }],
    ['GET', `/api/scans/${scan.id}`],
    ['POST', `/api/scans/${scan.id}/cancel`, {}],
    ['POST', `/api/connections/${A.conn}/scan`, {}],
    ['POST', `/api/connections/${A.conn}/breach-check`, {}],
    ['POST', `/api/connections/${A.conn}/disconnect`, {}],
    ['POST', `/api/connections/${A.conn}/synthetic-events`, { kind: 'signup', domain: 'evil.example' }],
    ['DELETE', `/api/connections/${A.conn}`],
  ];
  for (const [m, p, body] of probes) {
    const r = await B.client.req(m, p, body);
    assert.ok([404, 409].includes(r.status), `${m} ${p} -> ${r.status}`);
  }
  // State unchanged for the victim.
  assert.equal((await A.client.get(`/api/accounts/${acc.id}`)).body.account.status, acc.status);
  assert.equal((await A.client.get('/api/connections')).body.items[0].status, 'active');
  assert.equal((await B.client.get('/api/accounts')).body.items.length, 0);
  assert.equal((await B.client.get('/api/dashboard')).body.accounts.confirmed, 0);
});

test('authorization: client-supplied user ids, scores and plans are ignored or rejected', async () => {
  const r1 = await B.client.post('/api/accounts', { serviceName: 'X', userId: crypto.randomUUID() });
  assert.equal(r1.status, 400);
  const acc = (await B.client.post('/api/accounts', { serviceName: 'Mine' })).body.account;
  const r2 = await B.client.patch(`/api/accounts/${acc.id}`, { risk_score: 0 });
  assert.equal(r2.status, 400);
  const r3 = await B.client.patch('/api/recommendations/00000000-0000-0000-0000-000000000000', { status: 'verified' });
  assert.equal(r3.status, 400);
  assert.equal((await B.client.get('/api/accounts/not-a-uuid')).status, 400);
});

test('breach provider failures are "unavailable", never a clean result; consent is required and provider-bound', async () => {
  const breach = await import('../src/services/breach.js');
  // Simulate a real (non-synthetic) Gmail connection for provider routing.
  const { encrypt } = await import('../src/crypto.js');
  const id = crypto.randomUUID();
  await t.db.query(
    `INSERT INTO email_connections (id, user_id, provider, email_hash, email_enc, email_masked, scope_mode, status, token_enc) VALUES ($1,$2,'gmail',$3,$4::jsonb,'r***l@gmail.com','metadata','active',$5::jsonb)`,
    [id, B.user.id, crypto.randomBytes(16).toString('hex'), JSON.stringify(encrypt('real@gmail.com', `connection:${id}:email`)), JSON.stringify(encrypt('tok', `connection:${id}:refresh_token`))]
  );
  const noConsent = await B.client.post(`/api/connections/${id}/breach-check`, {});
  assert.equal(noConsent.status, 403);
  assert.equal(noConsent.body.error.code, 'CONSENT_REQUIRED');
  assert.equal((await B.client.post('/api/breaches/consent', { granted: true })).status, 200);

  const cases = [
    [async () => { throw new Error('boom'); }, 'PROVIDER_ERROR'],
    [async () => ({ breaches: 'not-an-array' }), 'MALFORMED_RESPONSE'],
    [async () => null, 'MALFORMED_RESPONSE'],
  ];
  for (const [impl, code] of cases) {
    breach.setBreachProvider('xposedornot', { name: 'xposedornot', checkEmail: impl, normalize: breach.normalizeXon });
    const r = await B.client.post(`/api/connections/${id}/breach-check`, { force: true });
    assert.equal(r.status, 200);
    assert.equal(r.body.status, 'unavailable');
    assert.equal(r.body.errorCode, code);
  }
  const rows = await t.db.query("SELECT status FROM breach_checks WHERE connection_id = $1", [id]);
  assert.ok(rows.length === 3 && rows.every((x) => x.status === 'unavailable'));
  const accounts = await t.db.query('SELECT exposure_status FROM discovered_accounts WHERE connection_id = $1', [id]);
  assert.ok(accounts.every((a) => a.exposure_status === 'unknown'), 'a failed check never marks accounts as having no evidence');

  // Consent is bound to provider + policy version.
  await t.db.query("UPDATE consents SET provider = 'hibp' WHERE user_id = $1", [B.user.id]);
  assert.equal((await B.client.post(`/api/connections/${id}/breach-check`, { force: true })).status, 403);
  await B.client.post('/api/breaches/consent', { granted: false });
  const ov = (await B.client.get('/api/breaches')).body;
  assert.equal(ov.consent.current, false);
  assert.ok(ov.limitations.some((l) => /not that the address was never breached/.test(l)));
});

test('real provider parsing (stubbed fetch): not-found shapes are "no evidence", anything unexpected fails closed', async () => {
  const { builtInProviders } = await import('../src/services/breach.js');
  const xon = builtInProviders.xposedornot;
  const realFetch = globalThis.fetch;
  const respond = (status, body, headers = {}) => async (url, opts) => {
    assert.ok(String(url).startsWith('https://api.xposedornot.com/v1/breach-analytics?email='));
    assert.equal(opts.redirect, 'error');
    return new Response(typeof body === 'string' ? body : JSON.stringify(body), { status, headers });
  };
  const run = async (f) => {
    globalThis.fetch = f;
    try {
      return { ok: await xon.checkEmail('someone@example.com') };
    } catch (e) {
      return { err: e.code };
    } finally {
      globalThis.fetch = realFetch;
    }
  };
  assert.deepEqual(await run(respond(404, '')), { ok: { breaches: [] } });
  assert.deepEqual(await run(respond(200, { ExposedBreaches: null })), { ok: { breaches: [] } });
  assert.deepEqual(await run(respond(200, { Error: 'Not found' })), { ok: { breaches: [] } });
  assert.equal((await run(respond(200, { ExposedBreaches: { breaches_details: [{ breach: 'Adobe', xposed_data: 'Passwords' }] } }))).ok.breaches.length, 1);
  assert.deepEqual(await run(respond(200, { ExposedBreaches: { something: 'else' } })), { err: 'MALFORMED_RESPONSE' });
  assert.deepEqual(await run(respond(200, '<html>maintenance</html>')), { err: 'MALFORMED_RESPONSE' });
  assert.deepEqual(await run(respond(429, '')), { err: 'RATE_LIMITED' });
  assert.deepEqual(await run(respond(503, '')), { err: 'PROVIDER_ERROR' });
  assert.deepEqual(await run(async () => { throw new TypeError('fetch failed'); }), { err: 'NETWORK_ERROR' });
  assert.deepEqual(await run(async () => { throw Object.assign(new Error('aborted'), { name: 'AbortError' }); }), { err: 'TIMEOUT' });
});

test('notifications: in-app alerts always created; email respects preferences, de-duplication and daily cap', async () => {
  const n = await import('../src/services/notifications.js');
  const C = await registerAndLogin(t, 'notify@example.com');
  await C.client.patch('/api/notifications/preferences', { security_alerts_email: true });
  sent.length = 0;
  const a1 = await n.createAlert(C.user.id, { kind: 'breach', severity: 'high', title: 'T1', body: 'B', dedupKey: 'k1' });
  const a1dup = await n.createAlert(C.user.id, { kind: 'breach', severity: 'high', title: 'T1', body: 'B', dedupKey: 'k1' });
  assert.ok(a1);
  assert.equal(a1dup, null, 'unchanged finding is not re-alerted');
  const escalated = await n.createAlert(C.user.id, { kind: 'breach', severity: 'critical', title: 'T1', body: 'B', dedupKey: 'k1' });
  assert.ok(escalated, 'a material change (severity) creates a new alert');
  assert.equal(sent.length, 2);
  await n.createAlert(C.user.id, { kind: 'breach', severity: 'high', title: 'T3', body: 'B', dedupKey: 'k3' });
  assert.equal(sent.length, 2, 'daily cap (2 in this test) prevents an inbox flood');
  const low = await n.createAlert(C.user.id, { kind: 'scan', severity: 'low', title: 'T4', body: 'B', dedupKey: 'k4' });
  assert.ok(low);
  assert.equal(sent.length, 2, 'low severity never emails');
  await C.client.patch('/api/notifications/preferences', { security_alerts_email: false });
  await t.db.query('DELETE FROM notification_deliveries WHERE user_id = $1', [C.user.id]);
  await n.createAlert(C.user.id, { kind: 'breach', severity: 'critical', title: 'T5', body: 'B', dedupKey: 'k5' });
  assert.equal(sent.length, 2, 'email off â†’ no email');
  const inApp = (await C.client.get('/api/alerts')).body.items;
  assert.equal(inApp.length, 5, 'in-app alerts continue when email is off');
  const deliveries = (await C.client.get('/api/notifications/deliveries')).body.items;
  assert.ok(deliveries.some((d) => d.reason === 'preference_off'));
  assert.ok(!JSON.stringify(deliveries).includes('T5'), 'delivery log holds no content');
  assert.ok(sent.every((m) => /List-Unsubscribe/.test(JSON.stringify(m.headers)) && /never ask for your passwords/.test(m.text)));
});

test('notifications: delivery failures are recorded safely; unsubscribe links work without login and are tamper-proof', async () => {
  const n = await import('../src/services/notifications.js');
  const F = await registerAndLogin(t, 'fail@example.com');
  await F.client.patch('/api/notifications/preferences', { security_alerts_email: true });
  const out = await n.sendEmail(F.user.id, { category: 'security_alerts', dedupKey: 'x', subject: 's', text: 't' });
  assert.equal(out.status, 'failed');
  const row = await t.db.queryOne('SELECT status, reason FROM notification_deliveries WHERE user_id = $1', [F.user.id]);
  assert.deepEqual(row, { status: 'failed', reason: 'ECONNREFUSED' });
  const token = n.unsubscribeToken(F.user.id, 'security_alerts');
  const anon = t.client();
  assert.equal((await anon.post('/api/notifications/unsubscribe', { u: F.user.id, c: 'security_alerts', t: token.replace(/^./, token[0] === 'a' ? 'b' : 'a') })).status, 400);
  assert.equal((await anon.post('/api/notifications/unsubscribe', { u: F.user.id, c: 'security_alerts', t: token })).status, 200);
  assert.equal((await F.client.get('/api/notifications/preferences')).body.preferences.security_alerts_email, false);
});

test('a routine scan does not send email', async () => {
  sent.length = 0;
  await A.client.post(`/api/connections/${A.conn}/scan`, {});
  const { drainJobs } = await import('../src/services/worker.js');
  await drainJobs();
  assert.equal(sent.filter((m) => /scan/i.test(m.subject)).length, 0);
});

test('privacy export contains the userâ€™s data but no secrets', async () => {
  const res = await A.client.req('GET', '/api/privacy/export', undefined, { raw: true });
  assert.match(res.headers.get('content-disposition'), /attachment/);
  const text = await res.text();
  const data = JSON.parse(text);
  assert.ok(data.accounts.length > 5);
  assert.ok(data.breachFindings.length > 0);
  for (const forbidden of ['password_hash', 'token_enc', 'email_enc', 'token_hash', 'csrf_hash', 'source_ref_hash']) assert.ok(!text.includes(forbidden), forbidden);
});

test('account deletion requires the password and removes the userâ€™s data (audit trail pseudonymised)', async () => {
  const D = await registerAndLogin(t, 'delete-me@example.com');
  await connectSyntheticAndScan(D.client);
  assert.equal((await D.client.del('/api/account', { password: 'wrong password entirely', confirm: 'DELETE' })).status, 400);
  assert.equal((await D.client.del('/api/account', { password: STRONG_PASSWORD })).status, 400);
  const r = await D.client.del('/api/account', { password: STRONG_PASSWORD, confirm: 'DELETE' });
  assert.equal(r.status, 200);
  assert.equal(r.body.deleted, true);
  for (const table of ['users', 'email_connections', 'discovered_accounts', 'account_evidence', 'recommendations', 'dasi_snapshots', 'sessions', 'alerts']) {
    const col = table === 'users' ? 'id' : 'user_id';
    const row = await t.db.queryOne(`SELECT count(*)::int AS n FROM ${table} WHERE ${col} = $1`, [D.user.id]);
    assert.equal(row.n, 0, table);
  }
  const audit = await t.db.queryOne("SELECT user_id FROM audit_events WHERE event = 'account_deleted' ORDER BY id DESC LIMIT 1");
  assert.equal(audit.user_id, null);
  assert.equal((await D.client.get('/api/auth/me')).status, 401);
  assert.equal((await t.client().post('/api/auth/login', { email: 'delete-me@example.com', password: STRONG_PASSWORD })).status, 401);
});

test('logs never contain tokens, passwords, cookies or full email addresses', async () => {
  const all = logLines.join('\n');
  assert.ok(logLines.length > 20);
  for (const bad of [STRONG_PASSWORD, 'victim@example.com', 'attacker@example.com', 'fx_session=', 'real@gmail.com']) assert.ok(!all.includes(bad), bad);
  const sessions = await t.db.query('SELECT token_hash FROM sessions');
  for (const s of sessions) assert.ok(!all.includes(s.token_hash));
});

test('migrations run from a clean database and are idempotent', async () => {
  const db = await import('../src/db.js');
  assert.deepEqual(await db.migrate(), []);
  assert.deepEqual(await db.pendingMigrations(), []);
  const ready = await t.client().get('/api/ready');
  assert.deepEqual(ready.body, { ready: true });
});
