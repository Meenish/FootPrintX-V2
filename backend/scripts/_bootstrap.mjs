// Shared bootstrap for CLI scripts: load .env, validate config, open the DB.
import '../src/env.js';
import { loadConfig, setConfig } from '../src/config.js';

export async function bootstrap({ migrate: runMigrations = true } = {}) {
  let cfg;
  try {
    cfg = loadConfig();
    setConfig(cfg);
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
  const db = await import('../src/db.js');
  await db.initDb();
  if (runMigrations) await db.migrate();
  return { cfg, db };
}
