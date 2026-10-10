// API entry point: validate configuration, migrate, start HTTP + background work.
import './env.js';
import { loadConfig, setConfig } from './config.js';
import { log } from './logger.js';

let cfg;
try {
  cfg = loadConfig();
  setConfig(cfg);
} catch (err) {
  console.error(err.message);
  process.exit(1);
}

const { initDb, migrate, closeDb } = await import('./db.js');
const { createApp } = await import('./app.js');
const { startWorker, startScheduler, stopWorker, stopScheduler } = await import('./services/worker.js');

try {
  await initDb();
  const ran = await migrate();
  if (ran.length) log.info('migrations applied', { ran });
} catch (err) {
  log.error('database startup failed', { err });
  process.exit(1);
}

const app = createApp();
const server = app.listen(cfg.port, cfg.host, () => {
  log.info('FootprintX API listening', { port: cfg.port, env: cfg.env, database: cfg.usesPglite ? 'pglite' : 'postgres', google: cfg.google.configured, synthetic: cfg.syntheticData, billing: cfg.billing.mode });
  if (!cfg.google.configured) log.warn('Google OAuth is not configured: Gmail connection is unavailable (see docs/PROVIDERS.md).');
  if (!cfg.smtp.configured) log.warn('SMTP is not configured: optional email notifications are recorded as skipped.');
});
if (cfg.runWorker) startWorker();
if (cfg.runScheduler) startScheduler();

async function shutdown(signal) {
  log.info('shutting down', { signal });
  stopWorker();
  stopScheduler();
  server.close(async () => {
    await closeDb().catch(() => {});
    process.exit(0);
  });
  setTimeout(() => process.exit(1), 10000).unref();
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
