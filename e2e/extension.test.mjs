// End-to-end: the real extension loaded in Chromium, talking to a real API.
// Test hosts (*.fx-test.example, paypa1.com, example.org) are resolved to a
// local page server via --host-resolver-rules; no real sites are visited.
// The threat list is the TEST-ONLY fixture e2e/fixtures/threat-feed.txt.
/* global chrome -- evaluated inside the extension service worker */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright-core';
import { startStack, startSiteServer, apiClient, CHROMIUM } from './stack.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const API_PORT = 5072;
const SITE_PORT = 8099;
let stack;
let site;
let ctx;
let sw;
let page;
let extId;
let api;

const buildExt = (apiBase) => execFileSync(process.execPath, ['build.mjs', '--target=chromium'], { cwd: path.join(root, 'extension'), env: { ...process.env, FX_API_BASE: apiBase, FX_APP_URL: apiBase }, stdio: 'pipe' });

before(async () => {
  stack = await startStack({ port: API_PORT });
  site = await startSiteServer(SITE_PORT);
  buildExt(`http://localhost:${API_PORT}`);
  api = apiClient(stack.base);
  assert.equal((await api.call('POST', '/auth/register', { email: `ext-${Date.now()}@example.com`, password: 'correct horse battery staple 42' })).status, 201);
  const extDir = path.join(root, 'extension/dist/chromium');
  fs.mkdirSync(path.join(root, '.test-artifacts'), { recursive: true });
  ctx = await chromium.launchPersistentContext(fs.mkdtempSync(path.join(root, '.test-artifacts', 'fx-ext-')), {
    executablePath: CHROMIUM,
    headless: false,
    args: [
      '--headless=new',
      `--disable-extensions-except=${extDir}`,
      `--load-extension=${extDir}`,
      `--host-resolver-rules=MAP *.fx-test.example 127.0.0.1:${SITE_PORT}, MAP paypa1.com 127.0.0.1:${SITE_PORT}, MAP example.org 127.0.0.1:${SITE_PORT}`,
    ],
  });
  sw = ctx.serviceWorkers()[0] || (await ctx.waitForEvent('serviceworker'));
  extId = new URL(sw.url()).host;
  page = await ctx.newPage();
  // Wait until the server has loaded the test threat feed.
  for (let i = 0; i < 50; i += 1) {
    const ds = await api.call('GET', '/reputation/dataset');
    if (ds.body?.usable) break;
    await new Promise((r) => setTimeout(r, 200));
  }
});

after(async () => {
  await ctx?.close();
  site?.close();
  await stack?.stop();
  buildExt('http://localhost:5000'); // restore the default local-development build
});

/** Reads the extension's per-tab state for a hostname from session storage. */
async function stateFor(hostname, { status, timeout = 10000 } = {}) {
  const deadline = Date.now() + timeout;
  for (;;) {
    const found = await sw.evaluate(async (h) => {
      const all = await chrome.storage.session.get(null);
      for (const [k, v] of Object.entries(all)) {
        if (k.startsWith('tab:') && v.hostname === h) return { tabId: Number(k.slice(4)), ...v, title: await chrome.action.getTitle({ tabId: Number(k.slice(4)) }), badge: await chrome.action.getBadgeText({ tabId: Number(k.slice(4)) }) };
      }
      return null;
    }, hostname);
    // The verdict is stored before the toolbar is painted; wait for both.
    if (found && (!status || found.status === status) && !/Checking…/.test(found.title)) return found;
    if (Date.now() > deadline) return found;
    await new Promise((r) => setTimeout(r, 150));
  }
}

test('linking the extension with a one-time code (no password in the extension)', async () => {
  const code = (await api.call('POST', '/extension/link-codes', {})).body.code;
  await page.goto(`chrome-extension://${extId}/options.html`);
  await page.getByPlaceholder('ABCD-EFGH').fill(code);
  await page.getByRole('button', { name: 'Link', exact: true }).click();
  await page.getByText('Linked to').waitFor();
  await page.getByText(/part of FootprintX Premium/).waitFor();
  await page.getByRole('checkbox', { name: /Replace known-threat pages/ }).check();
  const devices = await api.call('GET', '/extension/devices');
  assert.equal(devices.body.items.length, 1);
});

test('Free plan: no automatic checks and no "protected" state', async () => {
  await page.goto('http://malicious.fx-test.example/');
  await page.getByText('Test page for malicious.fx-test.example').waitFor();
  const s = await stateFor('malicious.fx-test.example');
  assert.equal(s.status, 'not_checked');
  assert.equal(s.reasons[0].code, 'PREMIUM_REQUIRED');
  assert.match(s.title, /Protection off \(Premium feature\)/);
  assert.equal(s.badge, '');
});

test('Premium: known threat → red, page replaced by a warning', async () => {
  assert.equal((await api.call('POST', '/billing/dev-checkout', {})).status, 200);
  await sw.evaluate(() => chrome.storage.session.remove('fx_entitlement')); // pick up the new plan now
  await page.goto('http://phish-login.fx-test.example/login?user=me').catch(() => {});
  await page.waitForURL(new RegExp(`chrome-extension://${extId}/warning.html#`), { timeout: 15000 });
  await page.getByText('This site is listed as a known threat').waitFor();
  assert.equal(await page.locator('#domain').innerText(), 'phish-login.fx-test.example');
  assert.match(await page.locator('#reasons').innerText(), /Listed in Local threat file|Listed in local_file/);
  const s = await stateFor('phish-login.fx-test.example', { status: 'malicious' });
  assert.equal(s.badge, '!');
  assert.match(s.title, /Known threat detected/);
});

test('"Go back to safety" leaves the site; parent-domain listings also warn', async () => {
  await page.getByRole('button', { name: 'Go back to safety' }).click();
  await page.waitForURL((u) => !u.href.includes('warning.html'));
  await page.goto('http://deep.sub.malicious.fx-test.example/').catch(() => {});
  await page.waitForURL(/warning\.html/, { timeout: 15000 });
  assert.match(await page.locator('#reasons').innerText(), /parent domain malicious\.fx-test\.example/);
});

test('"Continue anyway" proceeds once and the toolbar stays red', async () => {
  await page.getByRole('button', { name: 'More options' }).click();
  await page.getByRole('button', { name: 'Continue to the site anyway' }).click();
  await page.getByText('Test page for deep.sub.malicious.fx-test.example').waitFor();
  const s = await stateFor('deep.sub.malicious.fx-test.example', { status: 'malicious' });
  assert.equal(s.badge, '!');
});

test('no known threat → green only after a completed lookup', async () => {
  await page.goto('http://fine.fx-test.example/');
  await page.getByText('Test page for fine.fx-test.example').waitFor();
  const s = await stateFor('fine.fx-test.example', { status: 'no_known_threat' });
  assert.equal(s.status, 'no_known_threat');
  assert.equal(s.badge, '✓');
  assert.match(s.title, /No known threat detected: fine\.fx-test\.example/);
});

test('account recognition is independent of the website verdict and login remains unknown', async () => {
  assert.equal((await api.call('POST', '/accounts', { domain: 'fine.fx-test.example', serviceName: 'Fixture account' })).status, 201);
  await page.goto('http://fine.fx-test.example/');
  const state = await stateFor('fine.fx-test.example', { status: 'no_known_threat' });
  const options = await ctx.newPage();
  await options.goto(`chrome-extension://${extId}/options.html`);
  const result = await options.evaluate((tabId) => chrome.runtime.sendMessage({ type: 'getPopupState', tabId }), state.tabId);
  assert.equal(result.tab.association.state, 'account_known');
  assert.equal(result.tab.association.login.state, 'unavailable');
  assert.equal(result.tab.status, 'no_known_threat');
  await options.close();
});

test('look-alike domain → amber with a notification, page not blocked', async () => {
  await page.goto('http://paypa1.com/');
  await page.getByText('Test page for paypa1.com').waitFor();
  const s = await stateFor('paypa1.com', { status: 'suspicious' });
  assert.equal(s.status, 'suspicious');
  assert.equal(s.badge, '?');
  assert.equal(s.reasons[0].code, 'TYPOSQUAT');
});

test('opt-in event sync sends only warnings to the dashboard', async () => {
  await page.goto(`chrome-extension://${extId}/options.html`);
  await page.getByRole('checkbox', { name: /Share security events/ }).check();
  await page.getByText('Security events will be shared.').waitFor();
  await page.goto('http://phish-login.fx-test.example/').catch(() => {});
  await page.waitForURL(/warning\.html/, { timeout: 15000 });
  let events = [];
  for (let i = 0; i < 40 && !events.length; i += 1) {
    events = (await api.call('GET', '/extension/events')).body.items;
    if (!events.length) await new Promise((r) => setTimeout(r, 250));
  }
  assert.equal(events.length, 1);
  assert.equal(events[0].domain, 'phish-login.fx-test.example');
  assert.equal(events[0].status, 'malicious');
  const domains = events.map((e) => e.domain);
  assert.ok(!domains.includes('fine.fx-test.example'), 'clean visits are never synced');
});

test('popup explains the current state in words', async () => {
  const popup = await ctx.newPage();
  await popup.goto(`chrome-extension://${extId}/popup.html`);
  await popup.locator('#plan').getByText('Premium', { exact: true }).waitFor();
  assert.equal(await popup.locator('#plan').innerText(), 'Premium');
  assert.match(await popup.getByText(/not a guarantee/).innerText(), /green result means no known threat/i);
  await popup.close();
});

test('server unreachable → grey "unavailable", while saved threats still warn', async () => {
  await stack.stop();
  await page.goto('http://never-seen.fx-test.example/');
  await page.getByText('Test page for never-seen.fx-test.example').waitFor();
  const s = await stateFor('never-seen.fx-test.example', { status: 'unavailable' });
  assert.equal(s.status, 'unavailable');
  assert.equal(s.badge, '');
  assert.match(s.title, /Check unavailable/);
  await page.goto('http://phish-login.fx-test.example/').catch(() => {});
  await page.waitForURL(/warning\.html/, { timeout: 15000 });
  stack = null;
});
