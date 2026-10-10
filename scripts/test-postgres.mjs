import { spawnSync } from 'node:child_process';
if (!process.env.TEST_DATABASE_URL) throw new Error('Set TEST_DATABASE_URL to a disposable PostgreSQL database. The tests reset its public schema.');
const r = spawnSync(process.execPath, ['--test','--test-concurrency=1', ...['api.auth','api.completion','api.flow','api.gmail','api.protection','api.ratelimit','api.security','unit.core','unit.scoring'].map((s) => `backend/test/${s}.test.js`)], { stdio: 'inherit', env: { ...process.env, FX_TEST_DATABASE: 'postgres' } });
process.exitCode = r.status ?? 1;
