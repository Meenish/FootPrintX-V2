// Starts a real FootprintX API process (PGlite, synthetic data, test-only
// threat feed) for end-to-end tests, and a tiny site server for test pages.
import { chromium } from 'playwright-core';
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const CHROMIUM = process.env.FX_CHROMIUM || chromium.executablePath();

export async function startStack({ port, extra = {} }) {
  const env = {
    ...process.env,
    NODE_ENV: 'development',
    PORT: String(port),
    APP_URL: `http://localhost:${port}`,
    API_PUBLIC_URL: `http://localhost:${port}`,
    SERVE_FRONTEND: 'true',
    DATABASE_URL: 'pglite:memory',
    ENCRYPTION_KEYS: `k1:${crypto.randomBytes(32).toString('hex')}`,
    INDEX_KEY: crypto.randomBytes(32).toString('hex'),
    DEV_SYNTHETIC_DATA: 'true',
    BILLING_MODE: 'development',
    BREACH_PROVIDER: 'none',
    THREAT_FEED_FILE: path.join(root, 'e2e/fixtures/threat-feed.txt'),
    LOG_LEVEL: 'warn',
    ...extra,
  };
  const proc = spawn(process.execPath, ['src/server.js'], { cwd: path.join(root, 'backend'), env, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  proc.stdout.on('data', (d) => (output += d));
  proc.stderr.on('data', (d) => (output += d));
  const base = `http://localhost:${port}`;
  for (let i = 0; i < 450; i += 1) {
    try {
      const r = await fetch(`${base}/api/ready`, { signal: AbortSignal.timeout(1000) });
      if (r.ok) break;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 200));
    if (i === 449) { proc.kill(); throw new Error(`API did not start:\n${output}`); }
  }
  return { base, proc, output: () => output, stop: () => proc.exitCode !== null || proc.signalCode !== null ? Promise.resolve() : new Promise((r) => { proc.once('exit', r); proc.kill('SIGTERM'); }) };
}

/** Minimal cookie-aware API client for setting up test users. */
export function apiClient(base) {
  const jar = new Map();
  return {
    async call(method, p, body) {
      const headers = { origin: base, 'content-type': 'application/json' };
      if (jar.size) headers.cookie = [...jar].map(([k, v]) => `${k}=${v}`).join('; ');
      if (jar.get('fx_csrf')) headers['x-csrf-token'] = jar.get('fx_csrf');
      const res = await fetch(base + '/api' + p, { method, headers, body: body ? JSON.stringify(body) : undefined });
      for (const c of res.headers.getSetCookie()) {
        const [pair] = c.split(';');
        const i = pair.indexOf('=');
        jar.set(pair.slice(0, i), pair.slice(i + 1));
      }
      const text = await res.text();
      return { status: res.status, body: text ? JSON.parse(text) : null };
    },
  };
}

/** Serves a harmless page for any host (DNS for test hosts is mapped to 127.0.0.1). */
export function startSiteServer(port) {
  const server = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end(`<!doctype html><title>Test page ${req.headers.host}</title><h1>Test page for ${req.headers.host}</h1>`);
  });
  return new Promise((resolve) => server.listen(port, '127.0.0.1', () => resolve(server)));
}
