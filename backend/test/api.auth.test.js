// Integration tests: registration, login, sessions, CSRF, password reset.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestApp, STRONG_PASSWORD, registerAndLogin } from './helpers.js';

let t;
const sent = [];
before(async () => {
  t = await startTestApp({ SMTP_HOST: 'smtp.test', SMTP_FROM: 'FootprintX <no-reply@footprintx.test>' });
  const { setMailTransport } = await import('../src/services/notifications.js');
  setMailTransport({ sendMail: async (m) => { sent.push(m); return { accepted: [m.to], rejected: [] }; } });
});
after(() => t.close());

test('register creates a session with HttpOnly cookie and CSRF cookie', async () => {
  const c = t.client();
  const res = await c.req('POST', '/api/auth/register', { email: 'Alice@Example.com', password: STRONG_PASSWORD }, { raw: true });
  assert.equal(res.status, 201);
  const cookies = res.headers.getSetCookie();
  const session = cookies.find((x) => x.startsWith('fx_session='));
  assert.match(session, /HttpOnly/);
  assert.match(session, /SameSite=Lax/);
  assert.ok(cookies.find((x) => x.startsWith('fx_csrf=') && !/HttpOnly/.test(x)));
  const body = await res.json();
  assert.equal(body.user.email, 'alice@example.com');
  assert.ok(!('password_hash' in body.user));
});

test('weak passwords and duplicate emails are rejected without leaking details', async () => {
  const c = t.client();
  const weak = await c.post('/api/auth/register', { email: 'weak@example.com', password: 'short' });
  assert.equal(weak.status, 400);
  assert.equal(weak.body.error.code, 'WEAK_PASSWORD');
  await t.client().post('/api/auth/register', { email: 'dupe@example.com', password: STRONG_PASSWORD });
  const dupe = await c.post('/api/auth/register', { email: 'DUPE@example.com', password: STRONG_PASSWORD });
  assert.equal(dupe.status, 409);
  assert.equal(dupe.body.error.code, 'REGISTRATION_FAILED');
  assert.doesNotMatch(dupe.body.error.message, /exists|taken/i);
});

test('login: valid credentials succeed; wrong password and unknown email get the same error', async () => {
  await t.client().post('/api/auth/register', { email: 'bob@example.com', password: STRONG_PASSWORD });
  const ok = await t.client().post('/api/auth/login', { email: 'bob@example.com', password: STRONG_PASSWORD });
  assert.equal(ok.status, 200);
  const wrong = await t.client().post('/api/auth/login', { email: 'bob@example.com', password: 'not the password at all' });
  const unknown = await t.client().post('/api/auth/login', { email: 'nobody@example.com', password: 'not the password at all' });
  assert.equal(wrong.status, 401);
  assert.equal(unknown.status, 401);
  assert.deepEqual(wrong.body, unknown.body);
});

test('protected endpoints require authentication', async () => {
  const anon = t.client();
  for (const p of ['/api/auth/me', '/api/dashboard', '/api/accounts', '/api/recommendations', '/api/alerts', '/api/connections', '/api/dasi', '/api/activity', '/api/privacy/export', '/api/billing']) {
    const r = await anon.get(p);
    assert.equal(r.status, 401, p);
    assert.equal(r.body.error.code, 'UNAUTHENTICATED');
  }
});

test('state-changing requests require the CSRF token and JSON', async () => {
  const { client } = await registerAndLogin(t);
  client.csrf = false;
  const noCsrf = await client.patch('/api/notifications/preferences', { periodic_summary_email: true });
  assert.equal(noCsrf.status, 403);
  assert.equal(noCsrf.body.error.code, 'CSRF_FAILED');
  client.csrf = true;
  const form = await client.req('PATCH', '/api/notifications/preferences', 'periodic_summary_email=true', { headers: { 'content-type': 'application/x-www-form-urlencoded' } });
  assert.equal(form.status, 415);
  const ok = await client.patch('/api/notifications/preferences', { periodic_summary_email: true });
  assert.equal(ok.status, 200);
});

test('cross-origin state-changing requests are refused', async () => {
  const { client } = await registerAndLogin(t);
  const r = await client.patch('/api/notifications/preferences', { periodic_summary_email: true }, { headers: { origin: 'https://evil.example' } });
  assert.equal(r.status, 403);
  assert.equal(r.body.error.code, 'ORIGIN_NOT_ALLOWED');
});

test('logout revokes the session server-side', async () => {
  const { client } = await registerAndLogin(t);
  const stolen = new Map(client.cookies);
  assert.equal((await client.post('/api/auth/logout', {})).status, 204);
  const replay = t.client();
  replay.cookies = stolen;
  assert.equal((await replay.get('/api/auth/me')).status, 401);
});

test('changing the password signs out other sessions', async () => {
  const { client, email } = await registerAndLogin(t);
  const other = t.client();
  await other.post('/api/auth/login', { email, password: STRONG_PASSWORD });
  const r = await client.post('/api/auth/password/change', { currentPassword: STRONG_PASSWORD, newPassword: 'another long passphrase 99' });
  assert.equal(r.status, 200);
  assert.equal((await other.get('/api/auth/me')).status, 401);
  assert.equal((await client.get('/api/auth/me')).status, 200);
  const sessions = await client.get('/api/auth/sessions');
  assert.equal(sessions.body.items.length, 1);
  assert.equal(sessions.body.items[0].current, true);
});

test('password reset: same response for unknown email; token is single-use and resets sessions', async () => {
  const { client, email } = await registerAndLogin(t);
  sent.length = 0;
  const unknown = await t.client().post('/api/auth/password/reset-request', { email: 'ghost@example.com' });
  const known = await t.client().post('/api/auth/password/reset-request', { email });
  assert.equal(unknown.status, 202);
  assert.deepEqual(unknown.body, known.body);
  assert.equal(sent.length, 1);
  const token = decodeURIComponent(sent[0].text.match(/token=([^\s]+)/)[1]);
  const reset = await t.client().post('/api/auth/password/reset', { token, newPassword: 'brand new long passphrase 7' });
  assert.equal(reset.status, 200);
  const again = await t.client().post('/api/auth/password/reset', { token, newPassword: 'brand new long passphrase 8' });
  assert.equal(again.status, 400);
  assert.equal((await client.get('/api/auth/me')).status, 401, 'existing sessions revoked');
  assert.equal((await t.client().post('/api/auth/login', { email, password: 'brand new long passphrase 7' })).status, 200);
});

test('account lockout after repeated failures', async () => {
  const { email } = await registerAndLogin(t);
  for (let i = 0; i < 10; i += 1) await t.client().post('/api/auth/login', { email, password: `wrong password number ${i}` });
  const locked = await t.client().post('/api/auth/login', { email, password: STRONG_PASSWORD });
  assert.equal(locked.status, 429);
  assert.equal(locked.body.error.code, 'ACCOUNT_LOCKED');
});

test('extension tokens cannot be used as web sessions and web cookies cannot call extension endpoints', async () => {
  const { client } = await registerAndLogin(t);
  const code = (await client.post('/api/extension/link-codes', {})).body.code;
  const linked = await t.client({ origin: null }).post('/api/extension/link', { code, label: 'Test' });
  assert.equal(linked.status, 201);
  const ext = t.client({ bearer: linked.body.token, origin: null });
  assert.equal((await ext.get('/api/accounts')).status, 403, 'extension sessions cannot use web endpoints');
  assert.equal((await ext.get('/api/extension/status')).status, 200);
  assert.equal((await client.get('/api/extension/status')).status, 403);
});

test('security headers and no-store caching on API responses', async () => {
  const res = await t.client().req('GET', '/api/health', undefined, { raw: true });
  assert.equal(res.headers.get('cache-control'), 'no-store');
  assert.match(res.headers.get('content-security-policy'), /frame-ancestors 'none'/);
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(res.headers.get('x-powered-by'), null);
});

test('oversized and malformed bodies are rejected safely', async () => {
  const big = await t.client().post('/api/auth/login', { email: 'a@b.co', password: 'x'.repeat(70 * 1024) });
  assert.equal(big.status, 413);
  const bad = await t.client().req('POST', '/api/auth/login', '{not json', {});
  assert.equal(bad.status, 400);
  assert.equal(bad.body.error.code, 'INVALID_JSON');
});
