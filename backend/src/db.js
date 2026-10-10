// Database access. PostgreSQL (via `pg`) in every real deployment; PGlite (the
// real PostgreSQL engine compiled to WebAssembly) for zero-setup local
// development and fast tests. Both run the same SQL and the same migrations.
//
// All queries are parameterized ($1, $2, ...). No SQL is ever built from user
// input by string concatenation.
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { getConfig } from './config.js';
import { log } from './logger.js';

const MIGRATIONS_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../migrations');

let impl = null;

async function createPglite(url) {
  const { PGlite } = await import('@electric-sql/pglite');
  const target = url.slice('pglite:'.length);
  let instance;
  if (!target || target === 'memory') instance = new PGlite();
  else {
    const dir = path.resolve(target);
    await fs.mkdir(dir, { recursive: true });
    instance = new PGlite(dir);
  }
  await instance.waitReady;
  const wrap = (runner) => ({
    query: async (text, params = []) => (await runner.query(text, params)).rows,
    exec: (sql) => runner.exec(sql),
  });
  return {
    kind: 'pglite',
    ...wrap(instance),
    transaction: (fn) => instance.transaction((tx) => fn(wrap(tx))),
    close: () => instance.close(),
  };
}

function createPg(url) {
  const pool = new pg.Pool({
    connectionString: url,
    max: Number(process.env.PG_POOL_MAX || 10),
    connectionTimeoutMillis: 5000,
    idleTimeoutMillis: 30000,
    statement_timeout: 30000,
  });
  pool.on('error', (err) => log.error('postgres pool error', { err }));
  const wrapClient = (c) => ({
    query: async (text, params = []) => (await c.query(text, params)).rows,
    exec: (sql) => c.query(sql),
  });
  return {
    kind: 'postgres',
    ...wrapClient(pool),
    transaction: async (fn) => {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const result = await fn(wrapClient(client));
        await client.query('COMMIT');
        return result;
      } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        throw err;
      } finally {
        client.release();
      }
    },
    close: () => pool.end(),
  };
}

export async function initDb(url = getConfig().databaseUrl) {
  if (impl) return impl;
  impl = url.startsWith('pglite:') ? await createPglite(url) : createPg(url);
  return impl;
}

export async function closeDb() {
  if (impl) {
    const current = impl;
    impl = null;
    await current.close();
  }
}

function db() {
  if (!impl) throw new Error('Database not initialised: call initDb() first.');
  return impl;
}

export const dbKind = () => db().kind;

/** Run a parameterized query and return all rows. `client` may be a transaction handle. */
export function query(text, params = [], client) {
  return (client || db()).query(text, params);
}

/** Run a query and return the first row or null. */
export async function queryOne(text, params = [], client) {
  const rows = await query(text, params, client);
  return rows[0] || null;
}

/** Run `fn(tx)` inside a transaction; use tx for every query inside it. */
export function transaction(fn) {
  return db().transaction(fn);
}

export async function ping() {
  await query('SELECT 1');
  return true;
}

export async function listMigrationFiles() {
  return (await fs.readdir(MIGRATIONS_DIR)).filter((f) => /^\d{3}_.+\.sql$/.test(f)).sort();
}

/** Applies pending migrations in order, each in its own transaction. */
export async function migrate() {
  const d = db();
  await d.exec('CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())');
  const applied = new Set((await d.query('SELECT version FROM schema_migrations')).map((r) => r.version));
  const files = await listMigrationFiles();
  const ran = [];
  for (const file of files) {
    const version = file.slice(0, 3);
    if (applied.has(version)) continue;
    const sql = await fs.readFile(path.join(MIGRATIONS_DIR, file), 'utf8');
    await d.transaction(async (tx) => {
      if (d.kind === 'postgres') await tx.query('SELECT pg_advisory_xact_lock(727274)');
      const again = await tx.query('SELECT 1 FROM schema_migrations WHERE version = $1', [version]);
      if (again.length) return;
      await tx.exec(sql);
      await tx.query('INSERT INTO schema_migrations (version) VALUES ($1)', [version]);
    });
    ran.push(file);
  }
  return ran;
}

/** Pending migration versions (used by the readiness probe). */
export async function pendingMigrations() {
  const files = await listMigrationFiles();
  let applied = [];
  try {
    applied = (await query('SELECT version FROM schema_migrations')).map((r) => r.version);
  } catch {
    return files;
  }
  return files.filter((f) => !applied.includes(f.slice(0, 3)));
}
