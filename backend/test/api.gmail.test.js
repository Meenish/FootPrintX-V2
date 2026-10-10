// Integration: Gmail OAuth flow and scan lifecycle with a simulated Gmail
// provider (no network). Live Google testing requires real credentials and
// is documented as blocked in docs/AUDIT.md.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestApp, registerAndLogin, drain } from './helpers.js';

let t;
let svc;
before(async () => {
  t = await startTestApp({ GOOGLE_CLIENT_ID: 'test-client-id.apps.googleusercontent.com', GOOGLE_CLIENT_SECRET: 'test-secret-value' });
  svc = {
    conn: await import('../src/services/connections.js'),
    scanner: await import('../src/services/scanner.js'),
    gmail: await import('../src/services/gmail.js'),
  };
});
after(() => t.close());

const revoked = [];
async function connectFakeGmail(client, email = 'person@gmail.com', exchangeImpl) {
  svc.conn.setOAuthProvider({
    exchangeCode: exchangeImpl || (async ({ verifier }) => {
      assert.ok(verifier && verifier.length >= 43, 'PKCE verifier is passed to the token exchange');
      return { email, refreshToken: `1//refresh-${email}`, grantedScopes: 'https://www.googleapis.com/auth/gmail.metadata' };
    }),
    revokeRefreshToken: async (tok) => {
      revoked.push(tok);
      return 'revoked';
    },
  });
  const start = await client.post('/api/connections/google/start', {});
  assert.equal(start.status, 200);
  const url = new URL(start.body.url);
  assert.equal(url.searchParams.get('scope'), 'https://www.googleapis.com/auth/gmail.metadata');
  assert.equal(url.searchParams.get('code_challenge_method'), 'S256');
  assert.equal(url.searchParams.get('access_type'), 'offline');
  const state = url.searchParams.get('state');
  const cb = await client.get(`/api/connections/google/callback?state=${encodeURIComponent(state)}&code=fake-code`);
  return { cb, state };
}

const messagesFor = (n, offset = 0) =>
  Array.from({ length: n }, (_, i) => ({ id: `m${i + offset}`, from: `Svc${i + offset} <no-reply@svc${i + offset}.example>`, subject: `Welcome to Svc${i + offset}`, authResults: 'dmarc=pass', internalDate: Date.now() - i * 864e5 }));

test('OAuth: least-privilege consent URL, single-use state, encrypted token, onboarding scan queued', async () => {
  const { client } = await registerAndLogin(t);
  svc.scanner.setScanProvider('gmail', async function* () {
    yield { source: 'recent_messages', messages: messagesFor(3), outcome: { source: 'recent_messages', status: 'ok', listed: 3, fetched: 3, failed: 0 } };
  });
  const { cb, state } = await connectFakeGmail(client);
  assert.equal(cb.status, 303);
  const loc = new URL(cb.headers.get('location'));
  assert.equal(loc.origin, 'http://app.test');
  assert.equal(loc.searchParams.get('oauth'), 'connected');
  const replay = await client.get(`/api/connections/google/callback?state=${encodeURIComponent(state)}&code=fake-code`);
  assert.equal(new URL(replay.headers.get('location')).searchParams.get('reason'), 'OAUTH_STATE_INVALID');

  const row = await t.db.queryOne('SELECT token_enc, email_enc, email_masked FROM email_connections');
  assert.ok(!JSON.stringify(row).includes('refresh-person'), 'refresh token is encrypted at rest');
  assert.ok(!JSON.stringify(row).includes('person@gmail.com'), 'email is encrypted at rest');
  assert.equal(row.email_masked, 'p***n@gmail.com');
  const conns = (await client.get('/api/connections')).body;
  assert.ok(!JSON.stringify(conns).includes('token_enc') && !JSON.stringify(conns).includes('refresh-person'), 'API never returns tokens');
  assert.equal(conns.items[0].latestScan.status, 'queued');
  await drain();
  const accounts = (await client.get('/api/accounts')).body.items;
  assert.equal(accounts.length, 4, '3 services + the Google account behind the mailbox');
  assert.ok(accounts.every((a) => !a.is_synthetic));
});

test('OAuth: a callback started by another user is rejected; denied consent connects nothing', async () => {
  const a = await registerAndLogin(t);
  const b = await registerAndLogin(t);
  svc.conn.setOAuthProvider({ exchangeCode: async () => ({ email: 'x@gmail.com', refreshToken: 'r', grantedScopes: '' }) });
  const start = await a.client.post('/api/connections/google/start', {});
  const state = new URL(start.body.url).searchParams.get('state');
  const cb = await b.client.get(`/api/connections/google/callback?state=${encodeURIComponent(state)}&code=c`);
  assert.equal(new URL(cb.headers.get('location')).searchParams.get('reason'), 'OAUTH_USER_MISMATCH');
  const denied = await a.client.get('/api/connections/google/callback?error=access_denied');
  assert.equal(new URL(denied.headers.get('location')).searchParams.get('oauth'), 'denied');
  assert.equal((await a.client.get('/api/connections')).body.items.length, 0);
});

test('OAuth: missing scope grant is reported and nothing is connected', async () => {
  const { client } = await registerAndLogin(t);
  const { cb } = await connectFakeGmail(client, 'scope@gmail.com', async () => {
    throw new svc.gmail.ProviderError('SCOPE_MISSING', 'not granted');
  });
  assert.equal(new URL(cb.headers.get('location')).searchParams.get('reason'), 'SCOPE_MISSING');
  assert.equal((await client.get('/api/connections')).body.items.length, 0);
});

test('Google not configured: clear setup error instead of a fake connection', async () => {
  const { loadConfig, setConfig, getConfig } = await import('../src/config.js');
  const saved = getConfig();
  setConfig({ ...saved, google: { ...saved.google, configured: false } });
  const { client } = await registerAndLogin(t);
  const r = await client.post('/api/connections/google/start', {});
  setConfig(saved);
  assert.equal(r.status, 503);
  assert.equal(r.body.error.code, 'GOOGLE_NOT_CONFIGURED');
  assert.ok(loadConfig);
});

test('scan: transient failures are retried; partial results are preserved with failing sources listed', async () => {
  const { client } = await registerAndLogin(t);
  let calls = 0;
  svc.scanner.setScanProvider('gmail', async function* () {
    calls += 1;
    if (calls === 1) throw new svc.gmail.ProviderError('RATE_LIMITED', 'slow down', { transient: true });
    yield { source: 'window_a', messages: messagesFor(2), outcome: { source: 'window_a', status: 'ok', listed: 2, fetched: 2, failed: 0 } };
    yield { source: 'window_b', messages: [], outcome: { source: 'window_b', status: 'failed', error: 'PROVIDER_UNAVAILABLE', listed: 0, fetched: 0, failed: 0 } };
  });
  await connectFakeGmail(client, 'retry@gmail.com');
  await drain();
  let job = (await client.get('/api/scans')).body.items[0];
  assert.equal(job.status, 'queued', 'transient error re-queued, not reported as success');
  assert.equal(job.error_code, 'RATE_LIMITED');
  await t.db.query('UPDATE scan_jobs SET next_attempt_at = now()');
  await drain();
  job = (await client.get('/api/scans')).body.items[0];
  assert.equal(job.status, 'partial');
  assert.equal(job.attempts, 2);
  assert.deepEqual(job.source_results.map((s) => [s.source, s.status]), [['window_a', 'ok'], ['window_b', 'failed']]);
  assert.equal((await client.get('/api/accounts')).body.items.length, 3);
});

test('scan: revoked authorization fails safely, keeps partial data and asks the user to reconnect', async () => {
  const { client } = await registerAndLogin(t);
  svc.scanner.setScanProvider('gmail', async function* () {
    yield { source: 'recent_messages', messages: messagesFor(2, 100), outcome: { source: 'recent_messages', status: 'ok', listed: 50, fetched: 2, failed: 0, inProgress: true } };
    throw new svc.gmail.ProviderError('AUTH_REVOKED', 'revoked', { status: 401 });
  });
  await connectFakeGmail(client, 'revoked@gmail.com');
  await drain();
  const job = (await client.get('/api/scans')).body.items[0];
  assert.equal(job.status, 'partial');
  assert.equal(job.error_code, 'AUTH_REVOKED');
  assert.match(job.error_message, /Reconnect/);
  const conn = (await client.get('/api/connections')).body.items[0];
  assert.equal(conn.status, 'reauth_required');
  assert.equal((await client.post(`/api/connections/${conn.id}/scan`, {})).status, 409);
  const alerts = (await client.get('/api/alerts')).body.items;
  assert.ok(alerts.some((a) => a.kind === 'scan' && /Reconnect/.test(a.title)));
});

test('scan: cancellation stops work and keeps what was found', async () => {
  const { client } = await registerAndLogin(t);
  svc.scanner.setScanProvider('gmail', async function* ({ connection }) {
    yield { source: 's', messages: messagesFor(2, 200), outcome: { source: 's', status: 'ok', listed: 10, fetched: 2, failed: 0, inProgress: true } };
    await t.db.query('UPDATE scan_jobs SET cancel_requested = true WHERE connection_id = $1', [connection.id]);
    yield { source: 's', messages: messagesFor(2, 300), outcome: { source: 's', status: 'ok', listed: 10, fetched: 4, failed: 0, inProgress: true } };
    yield { source: 's', messages: messagesFor(2, 400), outcome: { source: 's', status: 'ok', listed: 10, fetched: 6, failed: 0 } };
  });
  await connectFakeGmail(client, 'cancel@gmail.com');
  await drain();
  const job = (await client.get('/api/scans')).body.items[0];
  assert.equal(job.status, 'cancelled');
  assert.ok((await client.get('/api/accounts')).body.items.length >= 3);
  assert.ok((await client.get('/api/accounts')).body.items.length < 7);
});

test('scan: cancelling a queued job never runs it', async () => {
  const { client } = await registerAndLogin(t);
  // eslint-disable-next-line require-yield
  svc.scanner.setScanProvider('gmail', async function* () {
    throw new Error('must not run');
  });
  await connectFakeGmail(client, 'queued@gmail.com');
  const job = (await client.get('/api/scans')).body.items[0];
  const c = await client.post(`/api/scans/${job.id}/cancel`, {});
  assert.equal(c.body.status, 'cancelled');
  await drain();
  assert.equal((await client.get(`/api/scans/${job.id}`)).body.status, 'cancelled');
});

test('disconnect revokes the Google token, deletes it and stops scheduled monitoring', async () => {
  const { client } = await registerAndLogin(t);
  svc.scanner.setScanProvider('gmail', async function* () {
    yield { source: 's', messages: messagesFor(1, 500), outcome: { source: 's', status: 'ok', listed: 1, fetched: 1, failed: 0 } };
  });
  await connectFakeGmail(client, 'bye@gmail.com');
  await drain();
  const conn = (await client.get('/api/connections')).body.items[0];
  revoked.length = 0;
  const r = await client.post(`/api/connections/${conn.id}/disconnect`, {});
  assert.equal(r.body.revokeResult, 'revoked');
  assert.deepEqual(revoked, ['1//refresh-bye@gmail.com']);
  const row = await t.db.queryOne('SELECT token_enc, status, token_revoked_at FROM email_connections WHERE id = $1', [conn.id]);
  assert.equal(row.token_enc, null);
  assert.equal(row.status, 'disconnected');
  assert.ok(row.token_revoked_at);
  await t.db.query("UPDATE email_connections SET last_scan_at = now() - interval '3 days'");
  await svc.scanner.enqueueDueMonitoringScans();
  const queued = await t.db.query("SELECT id FROM scan_jobs WHERE connection_id = $1 AND status = 'queued'", [conn.id]);
  assert.equal(queued.length, 0);
});

test('scheduled monitoring enqueues due Gmail scans only, without duplicates', async () => {
  await t.db.query("UPDATE scan_jobs SET status = 'cancelled' WHERE status IN ('queued','running')");
  await t.db.query("UPDATE email_connections SET status = 'active', token_enc = '{}'::jsonb WHERE token_enc IS NULL AND status = 'disconnected'");
  await t.db.query("UPDATE email_connections SET last_scan_at = now() - interval '2 days'");
  const n1 = await svc.scanner.enqueueDueMonitoringScans();
  const n2 = await svc.scanner.enqueueDueMonitoringScans();
  assert.ok(n1 >= 1);
  assert.equal(n2, 0);
});

test('Gmail error classification', () => {
  const c = svc.gmail.classifyGoogleError;
  assert.equal(c({ response: { status: 401 } }).code, 'AUTH_REVOKED');
  assert.equal(c({ response: { data: { error: 'invalid_grant' } } }).code, 'AUTH_REVOKED');
  assert.equal(c({ response: { status: 429 } }).transient, true);
  assert.equal(c({ response: { status: 503 } }).transient, true);
  assert.equal(c({ code: 'ETIMEDOUT' }).transient, true);
  assert.equal(c({ response: { status: 403, data: { error: { message: 'Request had insufficient authentication scopes.' } } } }).code, 'SCOPE_MISSING');
  assert.equal(c({ response: { status: 400 } }).transient, false);
});
