// End-to-end: the built web app against a real API process, in Chromium.
// Prerequisite: `npm run build -w frontend` (the API serves frontend/dist).
/* global document, getComputedStyle -- evaluated inside the browser page */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { chromium } from 'playwright-core';
import { startStack, CHROMIUM } from './stack.mjs';

let stack;
let browser;
let page;
const errors = [];
before(async () => {
  stack = await startStack({ port: 5071 });
  const downloadsPath = path.resolve('.test-artifacts/downloads');
  await fs.mkdir(downloadsPath, { recursive: true });
  browser = await chromium.launch({ executablePath: CHROMIUM, downloadsPath });
  page = await (await browser.newContext({ acceptDownloads: true, viewport: { width: 1280, height: 900 } })).newPage();
  page.on('pageerror', (e) => errors.push(String(e)));
});
after(async () => {
  await browser?.close();
  await stack?.stop();
});

test('register → onboarding with synthetic mailbox → scan progress → breach check → overview', async () => {
  await page.goto(stack.base + '/');
  await page.getByRole('link', { name: 'Create a free account' }).click();
  await page.getByLabel('Email').fill(`e2e-${Date.now()}@example.com`);
  await page.getByLabel('Password').fill('correct horse battery staple 42');
  await page.getByRole('button', { name: 'Create account' }).click();
  await page.waitForURL('**/onboarding');
  await page.getByRole('button', { name: 'Use the synthetic test mailbox' }).click();
  await page.getByText(/Found \d+ confirmed accounts?/).waitFor({ timeout: 30000 });
  assert.match(await page.locator('.scan-progress').innerText(), /21 of 21 messages read/);
  await page.getByRole('button', { name: 'Check now' }).click();
  await page.getByText(/appears in 4 breach listings/).waitFor();
  await page.getByRole('button', { name: 'Go to my overview' }).click();
  await page.waitForURL('**/dashboard');
  await page.getByText('Needs attention now').waitFor();
  assert.ok(await page.getByText('Synthetic development data').isVisible());
  const gauge = await page.locator('.gauge[role="img"]').getAttribute('aria-label');
  assert.match(gauge, /Digital Attack Surface Index \d+ out of 100/);
  await fs.mkdir('.test-artifacts', { recursive: true });
  await page.screenshot({ path: '.test-artifacts/dashboard.png', fullPage: true });
});

test('Excel button requests a report and initiates a named download', async () => {
  await page.goto(stack.base + '/accounts');
  const download = page.waitForEvent('download');
  const response = page.waitForResponse((r) => r.url().endsWith('/api/reports/security.xlsx'));
  await page.getByRole('button', { name: 'Download Excel report' }).click();
  const file = await download;
  assert.match(file.suggestedFilename(), /\.xlsx$/);
  const payload = await response;
  assert.equal(payload.status(), 200);
  assert.match(payload.headers()['content-type'], /spreadsheetml/);
  assert.ok(Number(payload.headers()['content-length']) > 1000);
  // Workbook parsing and ownership are covered in api.completion.test.js.
  // Saving the download to disk is a separate deployment acceptance check.
});

test('contact explains missing delivery configuration and mobile layout fits', async () => {
  await page.goto(stack.base + '/contact');
  await page.getByText('Contact delivery is not configured on this server.').waitFor();
  assert.equal(await page.getByRole('button', { name: 'Send message' }).isDisabled(), true);
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto(stack.base + '/dashboard');
  await page.getByText('Needs attention now').waitFor();
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth));
  await page.screenshot({ path: '.test-artifacts/dashboard-mobile.png', fullPage: true });
  await page.setViewportSize({ width: 1280, height: 900 });
});

test('accounts inventory, detail evidence and dismissing a false positive', async () => {
  await page.goto(stack.base + '/accounts');
  await page.getByRole('table').waitFor();
  assert.ok(await page.getByRole('link', { name: 'GitHub' }).isVisible());
  await page.getByPlaceholder('Search by name or website').fill('swig');
  await page.getByRole('link', { name: 'Swiggy' }).click();
  await page.getByRole('heading', { name: 'Evidence' }).waitFor();
  await page.getByRole('button', { name: 'This isn’t my account' }).click();
  await page.getByRole('button', { name: 'Dismiss account' }).click();
  await page.getByText('You dismissed this account.').waitFor();
});

test('remediation: report done → awaiting confirmation; history recorded', async () => {
  await page.goto(stack.base + '/recommendations');
  const card = page.locator('.rec-card', { hasText: 'Change your Adobe password' });
  await card.getByRole('button', { name: 'I’ve done this' }).click();
  await page.getByText(/checking your mailbox now|FootprintX will look for a confirmation email|confirmation email/i).first().waitFor();
  await page.getByRole('tab', { name: /Done/ }).click();
  await page.locator('.rec-card', { hasText: 'Change your Adobe password' }).getByText('Done — awaiting confirmation').waitFor();
  await page.getByRole('heading', { name: 'Remediation history' }).waitFor();
});

test('website check distinguishes known threats, look-alikes and clean results', async () => {
  await page.goto(stack.base + '/website-check');
  const check = async (d) => {
    await page.getByLabel('Website address').fill(d);
    await page.getByRole('button', { name: 'Check', exact: true }).click();
    await page.locator('.check-result').waitFor();
    await page.waitForFunction((dom) => document.querySelector('.check-result .domain')?.textContent === dom, d.replace(/^https?:\/\//, '').split('/')[0]);
    return page.locator('.check-result h2 .tag').innerText();
  };
  assert.equal(await check('login.malicious.fx-test.example'), 'Known threat');
  assert.equal(await check('paypa1.com'), 'Suspicious signs');
  assert.equal(await check('example.org'), 'No known threat found');
});

test('Premium test checkout is labelled as no payment; keyboard focus is visible', async () => {
  await page.goto(stack.base + '/premium');
  await page.getByRole('button', { name: 'Start Premium (test, no payment)' }).click();
  await page.getByText('This Premium access was granted by the development test checkout. No payment was taken.').waitFor();
  await page.keyboard.press('Tab');
  const outline = await page.evaluate(() => getComputedStyle(document.activeElement).outlineStyle);
  assert.notEqual(outline, 'none');
});

test('signing out protects pages; no uncaught client errors', async () => {
  await page.getByRole('button', { name: 'Sign out' }).click();
  await page.goto(stack.base + '/accounts');
  await page.waitForURL('**/login?next=%2Faccounts');
  assert.deepEqual(errors, []);
});
