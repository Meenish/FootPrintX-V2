import '../backend/src/env.js';
import fs from 'node:fs';
import path from 'node:path';
import { getConfig } from '../backend/src/config.js';
import { initDb, closeDb, ping, pendingMigrations } from '../backend/src/db.js';
import { datasetStatus } from '../backend/src/services/reputation.js';
const cfg = getConfig();
const checks = [];
const check = (name, ok, action) => checks.push({ name, status: ok ? 'PASS' : 'BLOCKED', ...(ok ? {} : { action }) });
check('Production configuration', cfg.isProduction, 'Set NODE_ENV=production with HTTPS origins and PostgreSQL.');
check('Single origin web and API', cfg.appOrigin === new URL(cfg.apiPublicUrl).origin, 'Use one public HTTPS origin for this deployment.');
check('Frontend build', fs.existsSync('frontend/dist/index.html'), 'Run npm run build:production.');
for (const target of ['chromium','firefox']) {
  const version = JSON.parse(fs.readFileSync('extension/package.json')).version;
  const dir = path.join('extension/dist',target);
  let match = false;
  try { const m = JSON.parse(fs.readFileSync(path.join(dir,'build-info.json'))); match = m.apiBase === cfg.apiPublicUrl && m.appUrl === cfg.appUrl; } catch { /* missing build */ }
  check(`${target} package and origin`, fs.existsSync(`extension/dist/footprintx-${target}-${version}.zip`) && match, 'Rebuild extension for the configured public URLs.');
}
check('Gmail OAuth configured', cfg.google.configured, 'Set Google client credentials and register the exact callback. Live verification remains required.');
check('SMTP and contact configured', cfg.smtp.configured && !!cfg.smtp.contactTo, 'Set SMTP_HOST, SMTP_FROM, CONTACT_TO and provider authentication. Verify delivery.');
check('Breach provider selected', cfg.breach.provider !== 'none', 'Select xposedornot or hibp, check provider terms and configure credentials as needed.');
check('Purchases disabled', cfg.billing.mode === 'disabled', 'Keep BILLING_MODE=disabled for this release.');
try {
  await initDb(); await ping();
  check('Database migrations', (await pendingMigrations()).length === 0, 'Back up database, then run npm run migrate.');
  check('Fresh threat dataset', (await datasetStatus()).usable, 'Configure THREAT_FEEDS and run npm run threat:sync -w backend.');
} catch {
  check('Database available', false, 'Verify DATABASE_URL, connectivity and migrations.');
} finally { await closeDb(); }
console.log(JSON.stringify({ checks, note: 'Configuration checks do not prove OAuth approval, external delivery, browser-store publication or successful deployment.' }, null, 2));
process.exitCode = checks.some((c) => c.status === 'BLOCKED') ? 1 : 0;
