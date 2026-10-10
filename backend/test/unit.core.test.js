// Unit tests: configuration, cryptography, logging redaction.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { loadConfig, setConfig } from '../src/config.js';
import { testEnv } from './helpers.js';

const hex = () => crypto.randomBytes(32).toString('hex');

test('config: refuses to start without encryption keys and index key', () => {
  assert.throws(() => loadConfig({ NODE_ENV: 'development' }), /ENCRYPTION_KEYS is required[\s\S]*INDEX_KEY is required/);
});

test('config: rejects trivially guessable or malformed keys', () => {
  assert.throws(() => loadConfig(testEnv({ ENCRYPTION_KEYS: `k1:${'a'.repeat(64)}` })), /trivially guessable/);
  assert.throws(() => loadConfig(testEnv({ ENCRYPTION_KEYS: 'k1:abc' })), /64 hex characters/);
  const k = hex();
  assert.throws(() => loadConfig(testEnv({ ENCRYPTION_KEYS: `k1:${k}`, INDEX_KEY: k })), /INDEX_KEY must differ/);
});

test('config: production rejects PGlite, synthetic data, development billing and http URLs', () => {
  const err = (() => {
    try {
      loadConfig(testEnv({ NODE_ENV: 'production', DEV_SYNTHETIC_DATA: 'true', BILLING_MODE: 'development', DATABASE_URL: 'pglite:memory' }));
    } catch (e) {
      return e.message;
    }
    return '';
  })();
  assert.match(err, /PostgreSQL DATABASE_URL/);
  assert.match(err, /DEV_SYNTHETIC_DATA must be false/);
  assert.match(err, /BILLING_MODE=development/);
  assert.match(err, /APP_URL must use https/);
});

test('config: a valid production configuration loads and enables secure cookies', () => {
  const cfg = loadConfig(
    testEnv({ NODE_ENV: 'production', DEV_SYNTHETIC_DATA: 'false', BILLING_MODE: 'disabled', DATABASE_URL: 'postgres://u:p@db/fx', APP_URL: 'https://app.example', API_PUBLIC_URL: 'https://api.example' })
  );
  assert.equal(cfg.cookieSecure, true);
  assert.equal(cfg.google.configured, false);
  assert.equal(cfg.billing.priceStatus, 'proposed');
});

test('config: hibp provider requires an API key; partial Google config is rejected', () => {
  assert.throws(() => loadConfig(testEnv({ BREACH_PROVIDER: 'hibp' })), /HIBP_API_KEY/);
  assert.throws(() => loadConfig(testEnv({ GOOGLE_CLIENT_ID: 'x' })), /both GOOGLE_CLIENT_ID/);
});

test('crypto: AES-256-GCM round trip, AAD binding and tamper detection', async () => {
  setConfig(loadConfig(testEnv()));
  const { encrypt, decrypt, resetDerivedKeys } = await import('../src/crypto.js');
  resetDerivedKeys();
  const rec = encrypt('refresh-token-value', 'connection:1:refresh_token');
  assert.ok(!JSON.stringify(rec).includes('refresh-token-value'));
  assert.equal(decrypt(rec, 'connection:1:refresh_token'), 'refresh-token-value');
  // Same ciphertext moved to another row/field must not decrypt.
  assert.throws(() => decrypt(rec, 'connection:2:refresh_token'));
  const tampered = { ...rec, ct: Buffer.from(Buffer.from(rec.ct, 'base64').map((b, i) => (i === 0 ? b ^ 1 : b))).toString('base64') };
  assert.throws(() => decrypt(tampered, 'connection:1:refresh_token'));
  // Fresh nonce per encryption.
  assert.notEqual(encrypt('x', 'a').iv, encrypt('x', 'a').iv);
  assert.throws(() => encrypt('x'), /AAD/);
});

test('crypto: key rotation keeps old records readable and encrypts with the new primary', async () => {
  const { encrypt, decrypt, needsReencryption } = await import('../src/crypto.js');
  const old = hex();
  setConfig(loadConfig(testEnv({ ENCRYPTION_KEYS: `k1:${old}` })));
  const rec = encrypt('secret', 'ctx');
  setConfig(loadConfig(testEnv({ ENCRYPTION_KEYS: `k2:${hex()},k1:${old}` })));
  assert.equal(decrypt(rec, 'ctx'), 'secret');
  assert.equal(needsReencryption(rec), true);
  assert.equal(encrypt('secret', 'ctx').kid, 'k2');
  setConfig(loadConfig(testEnv({ ENCRYPTION_KEYS: `k3:${hex()}` })));
  assert.throws(() => decrypt(rec, 'ctx'), /not configured/);
});

test('crypto: keyed hashes are deterministic, purpose-separated and not plain SHA-256', async () => {
  setConfig(loadConfig(testEnv()));
  const { keyedHash, resetDerivedKeys, sha256, canonicalEmail, humanCode, generatePkce } = await import('../src/crypto.js');
  resetDerivedKeys();
  assert.equal(keyedHash('email', 'a@b.c'), keyedHash('email', 'a@b.c'));
  assert.notEqual(keyedHash('email', 'a@b.c'), keyedHash('ip', 'a@b.c'));
  assert.notEqual(keyedHash('email', 'a@b.c'), sha256('a@b.c'));
  assert.equal(canonicalEmail('J.Doe+news@GoogleMail.com'), 'jdoe@gmail.com');
  assert.equal(canonicalEmail('j.doe@example.com'), 'j.doe@example.com');
  assert.match(humanCode(), /^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/);
  const p = generatePkce();
  assert.equal(p.challenge, crypto.createHash('sha256').update(p.verifier).digest('base64url'));
});

test('logger: redacts tokens, secrets, cookies, emails and bearer headers', async () => {
  setConfig(loadConfig(testEnv({ LOG_LEVEL: 'debug' })));
  const { log, setLogSink, redact } = await import('../src/logger.js');
  const lines = [];
  setLogSink((l) => lines.push(l));
  log.info('user alice@example.com sent Bearer abc.def.ghi', {
    password: 'hunter2hunter2',
    refreshToken: '1//0gLONGREFRESHTOKENVALUE123456789',
    headers: { authorization: 'Bearer xyz', cookie: 'fx_session=abc' },
    nested: { token_enc: { ct: 'zzz' }, note: 'ya29.a0AfH6SMBexampleaccesstoken' },
    errorCode: 'RATE_LIMITED',
  });
  const out = lines.join('\n');
  for (const secret of ['hunter2hunter2', 'LONGREFRESHTOKEN', 'abc.def.ghi', 'fx_session=abc', 'ya29.a0AfH6', 'zzz', 'alice@example.com']) assert.ok(!out.includes(secret), secret);
  assert.ok(out.includes('RATE_LIMITED'));
  assert.equal(redact(new Error('token for bob@example.com')).message, 'token for b***@example.com');
});
