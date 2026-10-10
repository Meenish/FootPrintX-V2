// Extension logic tests (Node, no browser). Threat data is a TEST-ONLY
// fixture using reserved .example names; no real malicious sites are used.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { sha256Hex } from '@footprintx/shared/domain';
import { createApi, API_ERRORS } from '../src/lib/api.js';
import { createCache, createChecker, CACHE_TTL_MS } from '../src/lib/checker.js';
import { createAccount, ENTITLEMENT_FRESH_MS } from '../src/lib/account.js';
import { createEventLog } from '../src/lib/events.js';
import { toolbarFor } from '../src/lib/toolbar.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const memStore = () => {
  const m = new Map();
  return { get: async (k) => structuredClone(m.get(k)), set: async (k, v) => void m.set(k, structuredClone(v)), remove: async (k) => void m.delete(k), raw: m };
};

const LISTED = ['malicious.fx-test.example'];
async function fakeServer({ online = true, plan = 'premium', usable = true, version = 'v1', listed = LISTED } = {}) {
  const hashes = await Promise.all(listed.map(sha256Hex));
  const calls = [];
  const api = {
    calls,
    async lookup(prefixes) {
      calls.push(prefixes);
      if (!online) return { ok: false, status: 0, errorCode: API_ERRORS.OFFLINE };
      if (plan !== 'premium') return { ok: false, status: 402, errorCode: API_ERRORS.PREMIUM_REQUIRED };
      return { ok: true, data: { matches: hashes.filter((h) => prefixes.includes(h.slice(0, 8))).map((h) => ({ fullHash: h, source: 'test_fixture', sourceLabel: 'Test fixture', threatType: 'phishing' })), dataset: { usable, version, updatedAt: new Date().toISOString() } } };
    },
  };
  return api;
}
const premium = async () => ({ linked: true, plan: 'premium', state: 'active' });

test('checker: green only after a successful lookup; red for exact and parent-domain listings', async () => {
  const api = await fakeServer();
  const checker = createChecker({ api, cache: createCache(memStore()), getEntitlement: premium });
  const clean = await checker.evaluate('https://fine.fx-test.example/account?token=abc');
  assert.equal(clean.status, 'no_known_threat');
  const red = await checker.evaluate('https://malicious.fx-test.example/login');
  assert.equal(red.status, 'malicious');
  assert.equal(red.reasons[0].matchType, 'exact');
  const child = await checker.evaluate('https://a.b.malicious.fx-test.example/');
  assert.equal(child.status, 'malicious');
  assert.equal(child.reasons[0].matchType, 'parent_domain');
  assert.equal(child.reasons[0].matchedHost, 'malicious.fx-test.example');
});

test('checker: only 8-hex-char hash prefixes are sent — never hostnames, paths or queries', async () => {
  const api = await fakeServer();
  const checker = createChecker({ api, cache: createCache(memStore()), getEntitlement: premium });
  await checker.evaluate('https://user:pw@login.example.org/reset?email=me%40x.com#frag');
  const sent = JSON.stringify(api.calls);
  assert.ok(api.calls[0].every((p) => /^[0-9a-f]{8}$/.test(p)));
  for (const leak of ['example', 'login', 'reset', 'email', 'pw', 'frag']) assert.ok(!sent.includes(leak), leak);
});

test('checker: offline / errors are grey (unavailable), never green; cached threats still protect offline', async () => {
  const store = memStore();
  let now = Date.now();
  const cache = createCache(store, { now: () => now });
  const online = await fakeServer();
  const c1 = createChecker({ api: online, cache, getEntitlement: premium, now: () => now });
  assert.equal((await c1.evaluate('https://malicious.fx-test.example')).status, 'malicious');
  const offline = await fakeServer({ online: false });
  const c2 = createChecker({ api: offline, cache, getEntitlement: premium, now: () => now });
  const unknownSite = await c2.evaluate('https://never-seen.fx-test.example');
  assert.equal(unknownSite.status, 'unavailable');
  assert.equal(unknownSite.errorCode, 'OFFLINE');
  now += CACHE_TTL_MS.malicious + 60e3; // cache expired, still offline
  const stale = await c2.evaluate('https://malicious.fx-test.example');
  assert.equal(stale.status, 'malicious');
  assert.equal(stale.source, 'stale_cache');
  assert.ok(stale.reasons.some((r) => r.code === 'USING_CACHED_RESULT'));
});

test('checker: suspicious heuristics are amber even if the lookup failed; an unusable dataset is unknown', async () => {
  const offline = createChecker({ api: await fakeServer({ online: false }), cache: createCache(memStore()), getEntitlement: premium });
  const amber = await offline.evaluate('https://paypa1.com/');
  assert.equal(amber.status, 'suspicious');
  const noData = createChecker({ api: await fakeServer({ usable: false }), cache: createCache(memStore()), getEntitlement: premium });
  assert.equal((await noData.evaluate('https://fine.fx-test.example')).status, 'unknown');
});

test('checker: repeated navigation does not cause duplicate lookups (in-flight + cache de-dup)', async () => {
  const api = await fakeServer();
  const checker = createChecker({ api, cache: createCache(memStore()), getEntitlement: premium });
  await Promise.all(Array.from({ length: 10 }, () => checker.evaluate('https://fine.fx-test.example/page')));
  assert.equal(api.calls.length, 1);
  for (let i = 0; i < 5; i += 1) await checker.evaluate(`https://fine.fx-test.example/page${i}`);
  assert.equal(api.calls.length, 1, 'reloads/sub-pages of the same host hit the cache');
  await checker.evaluate('https://fine.fx-test.example/', { force: true });
  assert.equal(api.calls.length, 2);
});

test('checker: Free, unlinked, expired, paused, local and internal pages are not checked (and not shown as protected)', async () => {
  const api = await fakeServer();
  const cache = createCache(memStore());
  const mk = (ent, extra = {}) => createChecker({ api, cache, getEntitlement: async () => ent, apiHost: 'api.footprintx.example', ...extra });
  assert.equal((await mk({ linked: true, plan: 'free', state: 'none' }).evaluate('https://x.example')).reasons[0].code, 'PREMIUM_REQUIRED');
  assert.equal((await mk({ linked: true, plan: 'free', state: 'expired' }).evaluate('https://x.example')).reasons[0].code, 'PREMIUM_EXPIRED');
  assert.equal((await mk({ linked: false }).evaluate('https://x.example')).reasons[0].code, 'NOT_LINKED');
  assert.equal((await mk({ linked: true, plan: 'premium' }, { isPaused: async () => true }).evaluate('https://x.example')).reasons[0].code, 'PROTECTION_PAUSED');
  assert.equal((await mk({ linked: true, plan: 'premium' }).evaluate('http://localhost:3000')).reasons[0].code, 'LOCAL_PAGE');
  assert.equal((await mk({ linked: true, plan: 'premium' }).evaluate('chrome://settings')).reasons[0].code, 'UNSUPPORTED_PAGE');
  assert.equal((await mk({ linked: true, plan: 'premium' }).evaluate('https://api.footprintx.example/x')).reasons[0].code, 'FOOTPRINTX');
  assert.equal(api.calls.length, 0, 'no lookups were made for any of these');
  const ent = { linked: true, plan: 'premium' };
  const server402 = await fakeServer({ plan: 'free' });
  let authProblem = null;
  const c = createChecker({ api: server402, cache, getEntitlement: async () => ent, onAuthProblem: (e) => (authProblem = e) });
  const r = await c.evaluate('https://x.example');
  assert.equal(r.status, 'not_checked', 'a locally cached "premium" flag does not unlock protection; the server decides');
  assert.equal(authProblem, 'PREMIUM_REQUIRED');
});

test('checker: dataset updates re-check cached clean results and report escalations', async () => {
  const store = memStore();
  const cache = createCache(store);
  const v1 = createChecker({ api: await fakeServer({ listed: [] }), cache, getEntitlement: premium });
  assert.equal((await v1.evaluate('https://later.fx-test.example')).status, 'no_known_threat');
  assert.equal(await cache.markDatasetChanged('v2'), 1);
  const v2 = createChecker({ api: await fakeServer({ listed: ['later.fx-test.example'], version: 'v2' }), cache, getEntitlement: premium });
  const esc = await v2.recheckCached();
  assert.equal(esc.length, 1);
  assert.equal(esc[0].after.status, 'malicious');
  assert.equal((await cache.fresh('later.fx-test.example')).status, 'malicious');
});

test('cache: bounded size and expiry', async () => {
  let now = 0;
  const cache = createCache(memStore(), { now: () => now, max: 3 });
  for (const h of ['a', 'b', 'c', 'd']) {
    now += 1;
    await cache.put(h, { status: 'no_known_threat', checkedAt: now });
  }
  assert.equal((await cache.entries()).length, 3);
  assert.equal(await cache.get('a'), null);
  now += CACHE_TTL_MS.no_known_threat + 10;
  assert.equal(await cache.fresh('d'), null);
  await cache.purgeExpired();
  assert.equal((await cache.entries()).length, 0);
});

test('account: entitlement comes from the server; revoked tokens are forgotten; outages are "unverified"', async () => {
  const local = memStore();
  const session = memStore();
  let mode = 'ok';
  const api = {
    link: async () => ({ ok: true, data: { token: 'tok' } }),
    unlink: async () => ({ ok: true }),
    status: async () =>
      mode === 'ok'
        ? { ok: true, data: { entitlement: { plan: 'premium', state: 'active', features: {} }, session: { syncEnabled: false }, account: { emailMasked: 'a***@x.com' }, dataset: { version: 'v1', usable: true } } }
        : mode === 'down'
          ? { ok: false, errorCode: API_ERRORS.OFFLINE }
          : { ok: false, errorCode: API_ERRORS.UNAUTHENTICATED },
  };
  let now = 1000;
  const acct = createAccount({ api, local, session, now: () => now });
  assert.deepEqual(await acct.get(), { linked: false });
  await acct.link('ABCD-EFGH');
  assert.equal((await acct.get()).plan, 'premium');
  // Tampering with stored state cannot persist past the next verification.
  await session.set('fx_entitlement', { linked: true, plan: 'premium', verifiedAt: now - ENTITLEMENT_FRESH_MS - 1 });
  mode = 'down';
  const outage = await acct.get();
  assert.equal(outage.unverified, true);
  mode = 'revoked';
  const rev = await acct.get({ force: true });
  assert.equal(rev.linked, false);
  assert.equal(await local.get('fx_token'), null);
});

test('events: only warnings are logged; sync happens only when enabled; failures do not lose events', async () => {
  const local = memStore();
  const sent = [];
  let fail = false;
  const api = { sendEvents: async (evts) => (fail ? { ok: false, status: 0 } : (sent.push(...evts), { ok: true })) };
  const log = createEventLog({ local, api });
  await assert.rejects(() => log.record({ type: 'page_visit', hostname: 'x.example', status: 'no_known_threat' }, { sync: true }));
  await log.record({ type: 'malicious_site_blocked', hostname: 'malicious.fx-test.example', status: 'malicious', reasonCodes: ['THREAT_LIST_MATCH', 'bad code!'] }, { sync: false });
  assert.deepEqual(await log.flush({ syncEnabled: true }), { sent: 0, kept: 0 }, 'not queued when sync was off');
  fail = true;
  await log.record({ type: 'suspicious_site_warned', hostname: 'paypa1.com', status: 'suspicious' }, { sync: true });
  assert.equal((await log.flush({ syncEnabled: true })).kept, 1);
  fail = false;
  assert.equal((await log.flush({ syncEnabled: true })).sent, 1);
  assert.deepEqual(Object.keys(sent[0]).sort(), ['clientEventId', 'domain', 'occurredAt', 'reasonCodes', 'status', 'type']);
  assert.equal((await log.list())[1].reasonCodes.length, 1, 'invalid reason codes dropped');
});

test('toolbar: each state has a distinct icon, badge and accessible title', () => {
  const states = ['malicious', 'suspicious', 'no_known_threat', 'unavailable', 'pending'].map((status) => toolbarFor({ status, hostname: 'x.example' }));
  assert.deepEqual(states.map((s) => s.color), ['red', 'amber', 'green', 'grey', 'grey']);
  assert.deepEqual(states.map((s) => s.badge), ['!', '?', '✓', '', '…']);
  assert.ok(states.every((s) => s.title.startsWith('FootprintX — ') && s.title.includes('x.example')));
  assert.match(toolbarFor({ status: 'not_checked', reasons: [{ code: 'PREMIUM_REQUIRED' }] }).title, /Protection off \(Premium feature\)/);
  assert.match(toolbarFor({ status: 'unavailable', errorCode: 'OFFLINE' }).title, /offline/);
});

test('api client: error classification and no cookies', async () => {
  const seen = [];
  const api = createApi({
    baseUrl: 'https://api.example',
    getToken: async () => 'tok',
    fetchImpl: async (url, opts) => {
      seen.push(opts);
      if (url.endsWith('/lookup')) return new Response(JSON.stringify({ error: { code: 'PREMIUM_EXPIRED' } }), { status: 402 });
      if (url.endsWith('/status')) throw new TypeError('network');
      return new Response('nope', { status: 200 });
    },
  });
  assert.equal((await api.lookup(['abcdef01'])).errorCode, 'PREMIUM_EXPIRED');
  assert.equal((await api.status()).errorCode, 'OFFLINE');
  assert.equal((await api.setSync(true)).errorCode, 'BAD_RESPONSE');
  assert.ok(seen.every((o) => o.credentials === 'omit' && o.headers.authorization === 'Bearer tok'));
});

test('package: minimal permissions, no content scripts, no remote code, no unsafe DOM APIs', () => {
  execFileSync(process.execPath, [path.join(here, '../build.mjs')], { cwd: path.join(here, '..'), env: { ...process.env, FX_API_BASE: 'https://api.footprintx.example' }, stdio: 'pipe' });
  for (const target of ['chromium', 'firefox']) {
    const dir = path.join(here, '../dist', target);
    const m = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
    assert.equal(m.manifest_version, 3);
    assert.deepEqual(m.permissions.sort(), ['alarms', 'notifications', 'storage', 'webNavigation']);
    assert.deepEqual(m.host_permissions, ['https://api.footprintx.example/*']);
    assert.equal(m.content_scripts, undefined);
    assert.equal(m.web_accessible_resources, undefined);
    assert.match(m.content_security_policy.extension_pages, /script-src 'self'/);
    for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.js'))) {
      const src = fs.readFileSync(path.join(dir, f), 'utf8');
      assert.ok(!/\.innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML|document\.write|\beval\(|new Function\(/.test(src), `${target}/${f} unsafe DOM/eval`);
      assert.ok(!/import\(\s*['"]https?:|importScripts\(\s*['"]https?:/.test(src), `${target}/${f} remote code`);
      assert.ok(!/document\.cookie|chrome\.cookies|\.cookies\./.test(src), `${target}/${f} cookie access`);
    }
    for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.html'))) {
      const html = fs.readFileSync(path.join(dir, f), 'utf8');
      assert.ok(!/<script(?![^>]*\bsrc=)[^>]*>/.test(html), `${f} inline script`);
      assert.ok(!/src=["']https?:/.test(html), `${f} remote resource`);
    }
  }
  assert.ok(fs.readFileSync(path.join(here, '../dist/firefox/manifest.json'), 'utf8').includes('gecko'));
  // Restore the default local-development build.
  execFileSync(process.execPath, [path.join(here, '../build.mjs')], { cwd: path.join(here, '..'), stdio: 'pipe' });
});
