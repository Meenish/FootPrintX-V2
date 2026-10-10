// Integration: threat dataset, reputation checks, extension linking/lookup/events,
// Premium entitlement enforcement. Threat data here is TEST-ONLY fixture data
// using reserved .example / .test names — never real malicious sites.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { startTestApp, registerAndLogin } from './helpers.js';
import { buildHashLookup } from '@footprintx/shared/domain';

let t;
let rep;
const FEED = [
  '# test-only fixture feed',
  'malicious.fx-test.example',
  'phish.weeblysite.com',
  'sites.google.com',
  'github.io',
  'google.com',
  'localhost',
  'not a domain!!',
  '0.0.0.0 hostsfile-style.fx-test.example',
].join('\n');

before(async () => {
  t = await startTestApp({ API_PUBLIC_URL: 'http://localhost:5000' });
  rep = await import('../src/services/reputation.js');
});
after(() => t.close());

async function linkExtension(client) {
  const code = (await client.post('/api/extension/link-codes', {})).body.code;
  const r = await t.client({ origin: null }).post('/api/extension/link', { code: code.toLowerCase().replace('-', ' '), label: 'Chromium test' });
  assert.equal(r.status, 201);
  return t.client({ bearer: r.body.token, origin: null });
}

test('before any dataset is loaded, checks are "unknown" — never green', async () => {
  const { client } = await registerAndLogin(t);
  const r = await client.post('/api/reputation/check', { domain: 'https://news.fx-test.example/path?secret=1' });
  assert.equal(r.status, 200);
  assert.equal(r.body.status, 'unknown');
  assert.equal(r.body.domain, 'news.fx-test.example');
  assert.ok(!JSON.stringify(r.body).includes('secret'));
});

test('feed ingestion validates entries and rejects dangerous listings', async () => {
  const out = await rep.syncFeed('test_fixture', { text: FEED, threatType: 'phishing' });
  assert.equal(out.accepted, 3);
  assert.deepEqual(out.rejected, { protected_shared_host: 1, public_suffix: 1, protected_platform_domain: 1, local_or_private: 1, invalid: 1 });
  const ds = await rep.datasetStatus();
  assert.equal(ds.usable, true);
  assert.equal(ds.indicatorCount, 3);
});

test('manual checks: exact and parent-domain matches are malicious; siblings, parents and lookalike-free sites are not', async () => {
  const { client } = await registerAndLogin(t);
  const check = async (d) => (await client.post('/api/reputation/check', { domain: d })).body;
  const exact = await check('malicious.fx-test.example');
  assert.equal(exact.status, 'malicious');
  assert.equal(exact.reasons[0].matchType, 'exact');
  const child = await check('login.malicious.fx-test.example');
  assert.equal(child.status, 'malicious');
  assert.equal(child.reasons[0].matchType, 'parent_domain');
  assert.equal((await check('fx-test.example')).status, 'no_known_threat', 'a listing never flags its parent');
  assert.equal((await check('notmalicious.fx-test.example')).status, 'no_known_threat', 'no substring matching');
  assert.equal((await check('other.weeblysite.com')).status, 'no_known_threat', 'other tenants of a platform are not flagged');
  assert.equal((await check('sites.google.com')).status, 'no_known_threat', 'protected shared hosts are never listed');
  const amber = await check('paypa1.com');
  assert.equal(amber.status, 'suspicious');
  assert.equal(amber.reasons[0].code, 'TYPOSQUAT');
  assert.equal((await client.post('/api/reputation/check', { domain: 'http://192.168.1.1' })).status, 400);
});

test('a stale dataset is reported as unknown rather than clean', async () => {
  const { client } = await registerAndLogin(t);
  await t.db.query("UPDATE threat_feed_runs SET finished_at = now() - interval '10 days'");
  const r = await client.post('/api/reputation/check', { domain: 'fine.fx-test.example' });
  assert.equal(r.body.status, 'unknown');
  assert.equal(r.body.reasons[0].code, 'DATASET_STALE');
  // Known-malicious entries are still reported even from an old dataset.
  assert.equal((await client.post('/api/reputation/check', { domain: 'malicious.fx-test.example' })).body.status, 'malicious');
  await t.db.query("UPDATE threat_feed_runs SET finished_at = now()");
});

test('a sharply shrunken feed does not silently deactivate protection', async () => {
  await rep.syncFeed('shrink_test', { text: Array.from({ length: 20 }, (_, i) => `h${i}.shrink.example`).join('\n') });
  const out = await rep.syncFeed('shrink_test', { text: 'h0.shrink.example' });
  assert.equal(out.deactivated, 0);
  const active = await t.db.queryOne("SELECT count(*)::int AS n FROM threat_indicators WHERE source = 'shrink_test' AND active");
  assert.equal(active.n, 20);
});

test('extension linking: one-time code, Bearer token, revocable', async () => {
  const { client } = await registerAndLogin(t);
  const code = (await client.post('/api/extension/link-codes', {})).body.code;
  assert.match(code, /^[A-Z2-9]{4}-[A-Z2-9]{4}$/);
  const anon = t.client({ origin: null });
  const linked = await anon.post('/api/extension/link', { code, label: 'Test browser' });
  assert.equal(linked.status, 201);
  assert.equal((await anon.post('/api/extension/link', { code })).status, 400, 'code is single-use');
  const ext = t.client({ bearer: linked.body.token, origin: null });
  const status = await ext.get('/api/extension/status');
  assert.equal(status.body.linked, true);
  assert.equal(status.body.entitlement.plan, 'free');
  assert.equal(status.body.account.emailMasked.includes('***'), true);
  const devices = (await client.get('/api/extension/devices')).body.items;
  assert.equal(devices.length, 1);
  assert.equal((await client.del(`/api/extension/devices/${devices[0].id}`)).status, 204);
  assert.equal((await ext.get('/api/extension/status')).status, 401, 'revoked from the web app');
});

test('Premium is enforced server-side: Free extension cannot use automatic lookups or event sync', async () => {
  const { client } = await registerAndLogin(t);
  const ext = await linkExtension(client);
  const entries = await buildHashLookup('malicious.fx-test.example');
  const free = await ext.post('/api/extension/lookup', { prefixes: entries.map((e) => e.prefix) });
  assert.equal(free.status, 402);
  assert.equal(free.body.error.code, 'PREMIUM_REQUIRED');
  assert.equal((await ext.put('/api/extension/settings', { syncEnabled: true })).status, 402);
  // Client-controlled "premium" flags are ignored / rejected.
  assert.equal((await ext.post('/api/extension/lookup', { prefixes: [entries[0].prefix], premium: true })).status, 400);
  assert.equal((await client.patch('/api/notifications/preferences', { plan: 'premium' })).status, 400);
  // Manual, user-initiated single checks remain available on Free.
  assert.equal((await ext.post('/api/reputation/check', { domain: 'malicious.fx-test.example' })).body.status, 'malicious');
});

test('Premium lookup returns only full hashes for matching prefixes; the server never receives hostnames', async () => {
  const { client } = await registerAndLogin(t);
  const ext = await linkExtension(client);
  const checkout = await client.post('/api/billing/dev-checkout', {});
  assert.equal(checkout.status, 200);
  assert.equal(checkout.body.paymentProcessed, false);
  assert.match(checkout.body.notice, /without any payment/);
  const entries = await buildHashLookup('login.malicious.fx-test.example');
  const r = await ext.post('/api/extension/lookup', { prefixes: entries.map((e) => e.prefix) });
  assert.equal(r.status, 200);
  const local = new Set(entries.map((e) => e.fullHash));
  const hits = r.body.matches.filter((m) => local.has(m.fullHash));
  assert.equal(hits.length, 1, 'parent-domain listing matched locally');
  assert.ok(!JSON.stringify(r.body).includes('fx-test.example'), 'response contains hashes, not hostnames');
  assert.equal(r.body.dataset.usable, true);
  const bad = await ext.post('/api/extension/lookup', { prefixes: ['zzzzzzzz'] });
  assert.equal(bad.status, 400);
  const tooMany = await ext.post('/api/extension/lookup', { prefixes: Array(11).fill('abcdef01') });
  assert.equal(tooMany.status, 400);
});

test('event sync: opt-in, validated, de-duplicated, owner-scoped', async () => {
  const a = await registerAndLogin(t);
  const b = await registerAndLogin(t);
  await a.client.post('/api/billing/dev-checkout', {});
  const ext = await linkExtension(a.client);
  const evt = (over = {}) => ({ clientEventId: crypto.randomUUID(), type: 'malicious_site_blocked', domain: 'malicious.fx-test.example', status: 'malicious', reasonCodes: ['THREAT_LIST_MATCH'], occurredAt: new Date().toISOString(), ...over });
  const notOptedIn = await ext.post('/api/extension/events', { events: [evt()] });
  assert.equal(notOptedIn.status, 403);
  assert.equal(notOptedIn.body.error.code, 'SYNC_NOT_ENABLED');
  assert.equal((await ext.put('/api/extension/settings', { syncEnabled: true })).body.syncEnabled, true);
  const e1 = evt();
  const r = await ext.post('/api/extension/events', { events: [e1, e1, evt({ domain: 'localhost' }), evt({ occurredAt: '2020-01-01T00:00:00.000Z' })] });
  assert.equal(r.status, 202);
  assert.equal(r.body.accepted, 1);
  assert.equal(r.body.duplicates, 1);
  assert.deepEqual(r.body.rejected.map((x) => x.reason).sort(), ['invalid_domain', 'invalid_timestamp']);
  assert.equal((await ext.post('/api/extension/events', { events: [evt({ type: 'page_visit' })] })).status, 400, 'unknown event types rejected');
  assert.equal((await ext.post('/api/extension/events', { events: [evt({ status: 'clean' })] })).status, 400, 'clean visits are never accepted');
  assert.equal((await ext.post('/api/extension/events', { events: [{ ...evt(), url: 'https://x.example/?q=1' }] })).status, 400, 'no full URLs');
  const mine = (await a.client.get('/api/extension/events')).body.items;
  assert.equal(mine.length, 1);
  assert.equal((await b.client.get('/api/extension/events')).body.items.length, 0);
  const alerts = (await a.client.get('/api/alerts')).body.items;
  assert.ok(alerts.some((x) => x.kind === 'extension'));
  const del = await a.client.del('/api/extension/events');
  assert.equal(del.body.deleted, 1);
});

test('expiry and cancellation downgrade without deleting data; expired is distinct from "never had Premium"', async () => {
  const { client } = await registerAndLogin(t);
  await client.post('/api/billing/dev-checkout', {});
  const ext = await linkExtension(client);
  const cancel = await client.post('/api/billing/cancel', {});
  assert.equal(cancel.body.entitlement.state, 'canceling');
  assert.equal(cancel.body.entitlement.plan, 'premium', 'cancellation takes effect at period end');
  await client.post('/api/billing/dev-expire', {});
  const st = await ext.get('/api/extension/status');
  assert.equal(st.body.entitlement.plan, 'free');
  assert.equal(st.body.entitlement.state, 'expired');
  const r = await ext.post('/api/extension/lookup', { prefixes: ['abcdef01'] });
  assert.equal(r.body.error.code, 'PREMIUM_EXPIRED');
  const { runMaintenance } = await import('../src/services/maintenance.js');
  await client.post('/api/billing/dev-checkout', {});
  await t.db.query("UPDATE subscriptions SET current_period_end = now() - interval '1 minute'");
  await runMaintenance();
  const sub = await t.db.queryOne('SELECT status FROM subscriptions LIMIT 1');
  assert.ok(['expired', 'canceled'].includes(sub.status));
});

test('billing disabled: no checkout and no fake subscription state', async () => {
  const { getConfig, setConfig } = await import('../src/config.js');
  const saved = getConfig();
  setConfig({ ...saved, billing: { ...saved.billing, mode: 'disabled' } });
  const { client } = await registerAndLogin(t);
  const plans = (await client.get('/api/billing')).body;
  const r = await client.post('/api/billing/dev-checkout', {});
  setConfig(saved);
  assert.equal(plans.catalog.checkoutAvailable, false);
  assert.equal(plans.catalog.premium.priceStatus, 'proposed');
  assert.equal(plans.catalog.premium.priceMinor, 14900);
  assert.equal(plans.catalog.currency, 'INR');
  assert.equal(r.status, 503);
  assert.equal(r.body.error.code, 'BILLING_NOT_CONFIGURED');
});

test('threat-intel updates alert users whose recently checked sites become listed', async () => {
  const { client } = await registerAndLogin(t);
  await client.post('/api/reputation/check', { domain: 'shop.later-bad.example' });
  await rep.syncFeed('update_feed', { text: 'unrelated.example' });
  await rep.syncFeed('update_feed', { text: 'unrelated.example\nlater-bad.example' });
  const alerts = (await client.get('/api/alerts')).body.items;
  const a = alerts.find((x) => x.kind === 'threat_intel');
  assert.ok(a, 'alert created');
  assert.match(a.title, /shop\.later-bad\.example/);
  await rep.syncFeed('update_feed', { text: 'unrelated.example\nlater-bad.example\nzzz.example' });
  const again = (await client.get('/api/alerts')).body.items.filter((x) => x.kind === 'threat_intel');
  assert.equal(again.length, 1, 'no duplicate alert for an unchanged finding');
});

test('false-positive reports are recorded for review, never auto-applied', async () => {
  const { client } = await registerAndLogin(t);
  const r = await client.post('/api/reputation/false-positive', { domain: 'malicious.fx-test.example', reportedStatus: 'malicious', note: 'This is my site' });
  assert.equal(r.status, 201);
  assert.equal((await client.post('/api/reputation/check', { domain: 'malicious.fx-test.example' })).body.status, 'malicious');
});

// ---- In-app extension delivery ------------------------------------------------------------

test('extension package: described and downloadable by any signed-in user, never anonymously', async () => {
  const { client } = await registerAndLogin(t);

  const anon = t.client({ origin: null });
  assert.equal((await anon.get('/api/extension/package')).status, 401, 'anonymous callers get nothing');
  assert.equal((await anon.get('/api/extension/package/chromium')).status, 401);

  const status = (await client.get('/api/extension/package')).body;
  assert.ok(status.version, 'reports the extension version');
  assert.match(status.apiBase, /^https?:\/\//, 'tells the user which server the build points at');
  for (const target of ['chromium', 'firefox']) {
    assert.ok(status.targets[target], `${target} is offered`);
    assert.equal(typeof status.targets[target].label, 'string');
  }

  // Free users may install the extension; only automatic lookups need Premium.
  const dl = await client.get('/api/extension/package/chromium', { raw: true });
  assert.equal(dl.status, 200, 'Free plan can download the extension');
  assert.match(dl.headers.get('content-type') || '', /zip/);
  assert.match(dl.headers.get('content-disposition') || '', /attachment; filename="footprintx-chromium-.*\.zip"/);
  assert.ok(Number(dl.headers.get('content-length')) > 1000, 'a real package, not an empty file');

  assert.equal((await client.get('/api/extension/package/netscape')).status, 400, 'unknown targets are rejected');
});

test('production refuses extension packages built for a different public origin', async () => {
  const { getConfig, setConfig } = await import('../src/config.js');
  const { getPackage, packageStatus } = await import('../src/services/extensionPackage.js');
  const original = getConfig();
  try {
    setConfig({ ...original, isProduction: true, apiPublicUrl: 'https://production.example', appUrl: 'https://production.example' });
    await assert.rejects(() => getPackage('chromium'), (err) => err.code === 'PACKAGE_ORIGIN_MISMATCH');
    assert.equal((await packageStatus()).targets.chromium.available, false);
  } finally { setConfig(original); }
});
