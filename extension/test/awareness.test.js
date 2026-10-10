import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createAwareness } from '../src/lib/awareness.js';

test('awareness suppresses Free and paused lookups and handles failures as unavailable', async () => {
  let plan = 'free', calls = 0, paused = false;
  const a = createAwareness({ api: { awareness: async () => { calls++; throw new Error('offline'); } }, entitlement: async () => ({ linked: true, plan }), paused: async () => paused });
  assert.equal((await a.evaluate('https://example.com')).state, 'unavailable');
  assert.equal(calls, 0);
  plan = 'premium'; paused = true;
  await a.evaluate('https://example.com'); assert.equal(calls, 0);
  paused = false;
  assert.equal((await a.evaluate('https://example.com')).state, 'unavailable');
  assert.equal(calls, 1);
});

test('awareness sends only hostname, deduplicates and expires cached associations', async () => {
  let now = 1, calls = 0;
  const a = createAwareness({ api: { awareness: async (host) => { assert.equal(host, 'example.com'); calls++; return { ok: true, data: { state: 'no_match', login: { state: 'unavailable' }, matches: [] } }; } }, entitlement: async () => ({ linked: true, plan: 'premium' }), paused: async () => false, now: () => now });
  await Promise.all([a.evaluate('https://example.com/path?secret=x'), a.evaluate('https://example.com/')]);
  assert.equal(calls, 1);
  await a.evaluate('example.com'); assert.equal(calls, 1);
  now += 61000; await a.evaluate('example.com'); assert.equal(calls, 2);
  a.clear(); await a.evaluate('example.com'); assert.equal(calls, 3);
});
