import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeHost, hostCandidates, indicatorMatches, buildHashLookup, sha256Hex, maskEmail, registrableDomain } from '../src/domain.js';
import { validateIndicatorHost, combineVerdict, REPUTATION_STATUS } from '../src/threat.js';
import { analyzeLookalike, editDistance } from '../src/lookalike.js';

test('normalizeHost strips scheme, path, query, credentials, port and trailing dot', () => {
  const n = normalizeHost('https://user:pw@Login.Example.COM.:8443/path?q=secret#frag');
  assert.equal(n.hostname, 'login.example.com');
  assert.equal(n.registrableDomain, 'example.com');
  assert.ok(!JSON.stringify(n).includes('secret'));
  assert.ok(!JSON.stringify(n).includes('pw'));
});

test('normalizeHost rejects non-http schemes and garbage', () => {
  assert.equal(normalizeHost('javascript:alert(1)'), null);
  assert.equal(normalizeHost('file:///etc/passwd'), null);
  assert.equal(normalizeHost('chrome://settings'), null);
  assert.equal(normalizeHost(''), null);
  assert.equal(normalizeHost('exa mple.com'), null);
  assert.equal(normalizeHost(42), null);
});

test('normalizeHost converts internationalized names to punycode and keeps a unicode form', () => {
  const n = normalizeHost('https://раypal.com/');
  assert.ok(n.hostname.startsWith('xn--'));
  assert.equal(n.unicodeHostname, 'раypal.com');
});

test('normalizeHost flags local and private hosts', () => {
  assert.equal(normalizeHost('localhost:3000').isLocal, true);
  assert.equal(normalizeHost('printer.local').isLocal, true);
  assert.equal(normalizeHost('192.168.1.10').isLocal, true);
  assert.equal(normalizeHost('8.8.8.8').isLocal, false);
  assert.equal(normalizeHost('example.com').isLocal, false);
});

test('registrable domain uses the public suffix list including private suffixes', () => {
  assert.equal(registrableDomain('a.b.example.co.uk'), 'example.co.uk');
  assert.equal(registrableDomain('alice.github.io'), 'alice.github.io');
  assert.equal(registrableDomain('github.io'), null);
  assert.equal(registrableDomain('mail.google.com'), 'google.com');
});

test('hostCandidates walks up to the registrable domain only', () => {
  assert.deepEqual(hostCandidates('a.b.evil.example.com'), ['a.b.evil.example.com', 'b.evil.example.com', 'evil.example.com', 'example.com']);
  assert.deepEqual(hostCandidates('alice.github.io'), ['alice.github.io']);
  assert.deepEqual(hostCandidates('github.io'), []);
  const deep = hostCandidates('1.2.3.4.5.6.7.example.com');
  assert.equal(deep.length, 5);
  assert.equal(deep.at(-1), 'example.com');
});

test('indicatorMatches is exact-or-subdomain, never parent, sibling or substring', () => {
  assert.ok(indicatorMatches('evil.example', 'evil.example'));
  assert.ok(indicatorMatches('login.evil.example', 'evil.example'));
  assert.ok(!indicatorMatches('evil.example', 'login.evil.example'));
  assert.ok(!indicatorMatches('notevil.example', 'evil.example'));
  assert.ok(!indicatorMatches('evil.example.com', 'evil.example'));
  assert.ok(!indicatorMatches('google.com', 'sites.google.com'));
});

test('buildHashLookup only exposes 8-hex-char prefixes and keeps full hashes local', async () => {
  const entries = await buildHashLookup('https://login.evil.example/path?token=abc');
  assert.deepEqual(entries.map((e) => e.candidate), ['login.evil.example', 'evil.example']);
  for (const e of entries) {
    assert.equal(e.prefix.length, 8);
    assert.equal(e.fullHash, await sha256Hex(e.candidate));
    assert.ok(e.fullHash.startsWith(e.prefix));
  }
});

test('validateIndicatorHost rejects public suffixes, protected platforms and shared hosts', () => {
  assert.deepEqual(validateIndicatorHost('github.io'), { rejected: 'public_suffix' });
  assert.deepEqual(validateIndicatorHost('sites.google.com'), { rejected: 'protected_shared_host' });
  assert.deepEqual(validateIndicatorHost('google.com'), { rejected: 'protected_platform_domain' });
  assert.deepEqual(validateIndicatorHost('www.weebly.com'), { rejected: 'protected_shared_host' });
  assert.deepEqual(validateIndicatorHost('localhost'), { rejected: 'local_or_private' });
  assert.equal(validateIndicatorHost('phish123.weeblysite.com').hostname, 'phish123.weeblysite.com');
  assert.equal(validateIndicatorHost('Evil.Example.').hostname, 'evil.example');
});

test('combineVerdict never turns a failed lookup into green', () => {
  assert.equal(combineVerdict({ lookup: { ok: false, errorCode: 'TIMEOUT' }, heuristics: { suspicious: false, reasons: [] } }).status, REPUTATION_STATUS.UNAVAILABLE);
  assert.equal(combineVerdict({ lookup: null, heuristics: null }).status, REPUTATION_STATUS.UNAVAILABLE);
  assert.equal(combineVerdict({ lookup: { ok: true, matches: [], datasetUsable: false }, heuristics: { suspicious: false } }).status, REPUTATION_STATUS.UNKNOWN);
  assert.equal(combineVerdict({ lookup: { ok: true, matches: [], datasetUsable: true }, heuristics: { suspicious: false } }).status, REPUTATION_STATUS.NO_KNOWN_THREAT);
  assert.equal(combineVerdict({ lookup: { ok: true, matches: [], datasetUsable: true }, heuristics: { suspicious: true, reasons: [{ code: 'TYPOSQUAT' }] } }).status, REPUTATION_STATUS.SUSPICIOUS);
  assert.equal(combineVerdict({ lookup: { ok: true, matches: [{ source: 'x' }], datasetUsable: true }, heuristics: { suspicious: true, reasons: [] } }).status, REPUTATION_STATUS.MALICIOUS);
});

test('lookalike heuristics flag homographs, embedded brands and typosquats', () => {
  const homograph = analyzeLookalike('https://раypal.com/'); // Cyrillic "ра"
  assert.ok(homograph.suspicious);
  assert.ok(homograph.reasons.some((r) => r.code === 'HOMOGRAPH' && r.brand === 'paypal.com'));
  assert.ok(analyzeLookalike('paypal.com.account-verify.example').reasons.some((r) => r.code === 'BRAND_IN_SUBDOMAIN'));
  assert.ok(analyzeLookalike('paypa1.com').reasons.some((r) => r.code === 'TYPOSQUAT'));
  assert.ok(analyzeLookalike('gooogle.com').reasons.some((r) => r.code === 'TYPOSQUAT'));
});

test('lookalike heuristics do not flag brands, brand subdomains, other brand TLDs or ordinary sites', () => {
  for (const host of ['paypal.com', 'www.paypal.com', 'accounts.google.com', 'google.de', 'amazon.co.uk', 'finance.yahoo.com', 'stripes.com', 'example.org', 'news.ycombinator.com', 'wikipedia.org', 'gitlab.com', 'my-new-startup.io']) {
    assert.equal(analyzeLookalike(host).suspicious, false, host);
  }
});

test('editDistance handles transpositions', () => {
  assert.equal(editDistance('google', 'goolge', 2), 1);
  assert.equal(editDistance('paypal', 'paypal', 2), 0);
});

test('maskEmail hides most of the local part', () => {
  assert.equal(maskEmail('alice@example.com'), 'a***e@example.com');
  assert.equal(maskEmail('al@example.com'), 'a***@example.com');
});
