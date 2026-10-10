// Rate limits are disabled in other test files for speed; enabled here.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startTestApp } from './helpers.js';

process.env.FX_TEST_RATE_LIMITS = 'true';
let t;
before(async () => {
  t = await startTestApp();
});
after(() => t.close());

test('login attempts are rate limited per client', async () => {
  const statuses = [];
  for (let i = 0; i < 12; i += 1) statuses.push((await t.client().post('/api/auth/login', { email: `x${i}@example.com`, password: 'whatever whatever' })).status);
  assert.deepEqual(statuses.slice(0, 10), Array(10).fill(401));
  assert.equal(statuses[10], 429);
  const r = await t.client().post('/api/auth/login', { email: 'y@example.com', password: 'whatever whatever' });
  assert.equal(r.body.error.code, 'RATE_LIMITED');
});

test('extension linking attempts are rate limited (code guessing)', async () => {
  const codes = [];
  for (let i = 0; i < 11; i += 1) codes.push((await t.client({ origin: null }).post('/api/extension/link', { code: 'AAAA-BBBB' })).status);
  assert.equal(codes.filter((s) => s === 400).length, 10);
  assert.equal(codes[10], 429);
});
