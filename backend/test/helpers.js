// Test harness: boots the real Express app against a fresh database.
//   default:                  in-memory PGlite (real PostgreSQL engine, WASM)
//   FX_TEST_DATABASE=postgres: TEST_DATABASE_URL (schema is dropped and re-created)
// Every test file runs in its own process, so each gets a clean database.
import crypto from 'node:crypto';
import { loadConfig, setConfig } from '../src/config.js';
import { resetDerivedKeys } from '../src/crypto.js';
import { setLogSink } from '../src/logger.js';

export const logLines = [];

export function testEnv(overrides = {}) {
  const hex = () => crypto.randomBytes(32).toString('hex');
  return {
    NODE_ENV: 'test',
    APP_URL: 'http://app.test',
    API_PUBLIC_URL: 'http://api.test',
    DATABASE_URL: 'pglite:memory',
    ENCRYPTION_KEYS: `k1:${hex()}`,
    INDEX_KEY: hex(),
    DEV_SYNTHETIC_DATA: 'true',
    BILLING_MODE: 'development',
    BREACH_PROVIDER: 'xposedornot',
    LOG_LEVEL: 'debug',
    MONITOR_INTERVAL_HOURS: '24',
    ...overrides,
  };
}

export async function startTestApp(overrides = {}) {
  const env = testEnv(overrides);
  if (process.env.FX_TEST_DATABASE === 'postgres') {
    if (!process.env.TEST_DATABASE_URL) throw new Error('Set TEST_DATABASE_URL for FX_TEST_DATABASE=postgres');
    env.DATABASE_URL = process.env.TEST_DATABASE_URL;
  }
  const cfg = loadConfig(env);
  setConfig(cfg);
  resetDerivedKeys();
  logLines.length = 0;
  setLogSink((line) => logLines.push(line));
  const db = await import('../src/db.js');
  await db.initDb(cfg.databaseUrl);
  if (process.env.FX_TEST_DATABASE === 'postgres') {
    await db.query('DROP SCHEMA public CASCADE');
    await db.query('CREATE SCHEMA public');
  }
  await db.migrate();
  const { createApp } = await import('../src/app.js');
  const app = createApp();
  const server = await new Promise((resolve) => {
    const s = app.listen(0, '127.0.0.1', () => resolve(s));
  });
  const baseUrl = `http://127.0.0.1:${server.address().port}`;
  return {
    cfg,
    db,
    baseUrl,
    client: (opts) => new TestClient(baseUrl, { origin: cfg.appOrigin, ...opts }),
    async close() {
      await new Promise((r) => server.close(r));
      await db.closeDb();
    },
  };
}

/** Minimal browser-like client: cookie jar + CSRF header + Origin. */
export class TestClient {
  constructor(baseUrl, { origin, bearer } = {}) {
    this.baseUrl = baseUrl;
    this.origin = origin;
    this.bearer = bearer || null;
    this.cookies = new Map();
    this.csrf = true;
  }

  csrfToken() {
    return this.cookies.get('fx_csrf') || this.cookies.get('__Host-fx_csrf');
  }

  async req(method, path, body, { headers = {}, raw = false } = {}) {
    const h = { ...headers };
    if (this.origin && !('origin' in h)) h.origin = this.origin;
    if (body !== undefined) h['content-type'] = h['content-type'] || 'application/json';
    if (this.cookies.size) h.cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; ');
    if (this.csrf && this.csrfToken() && !['GET', 'HEAD'].includes(method)) h['x-csrf-token'] = this.csrfToken();
    if (this.bearer) h.authorization = `Bearer ${this.bearer}`;
    const res = await fetch(this.baseUrl + path, { method, headers: h, body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body), redirect: 'manual' });
    for (const c of res.headers.getSetCookie()) {
      const [pair, ...attrs] = c.split(';');
      const [k, v] = pair.split('=');
      if (attrs.some((a) => /expires=thu, 01 jan 1970/i.test(a.trim())) || v === '') this.cookies.delete(k.trim());
      else this.cookies.set(k.trim(), v);
    }
    if (raw) return res;
    const text = await res.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = text;
    }
    return { status: res.status, body: json, headers: res.headers };
  }

  get(p, o) {
    return this.req('GET', p, undefined, o);
  }
  post(p, b = {}, o) {
    return this.req('POST', p, b, o);
  }
  patch(p, b = {}, o) {
    return this.req('PATCH', p, b, o);
  }
  put(p, b = {}, o) {
    return this.req('PUT', p, b, o);
  }
  del(p, b, o) {
    return this.req('DELETE', p, b, o);
  }
}

export const STRONG_PASSWORD = 'correct horse battery staple 42';

export async function registerAndLogin(t, email = `user-${crypto.randomBytes(4).toString('hex')}@example.com`) {
  const c = t.client();
  const r = await c.post('/api/auth/register', { email, password: STRONG_PASSWORD });
  if (r.status !== 201) throw new Error(`register failed: ${r.status} ${JSON.stringify(r.body)}`);
  return { client: c, user: r.body.user, email };
}

/** Connects the synthetic mailbox and runs its scan to completion. */
export async function connectSyntheticAndScan(client) {
  const r = await client.post('/api/connections/synthetic', {});
  if (r.status !== 201) throw new Error(`synthetic connect failed: ${r.status} ${JSON.stringify(r.body)}`);
  const { drainJobs } = await import('../src/services/worker.js');
  await drainJobs();
  return r.body;
}

export async function drain() {
  const { drainJobs } = await import('../src/services/worker.js');
  return drainJobs();
}
