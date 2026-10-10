import { spawnSync } from 'node:child_process';
import '../backend/src/env.js';
import { getConfig } from '../backend/src/config.js';
const cfg = getConfig();
if (!cfg.isProduction) throw new Error('Set NODE_ENV=production and configure backend/.env or environment variables before building for production.');
for (const [script, args] of [['node_modules/vite/bin/vite.js', ['build', 'frontend']], ['extension/build.mjs', ['--zip','--minify']]]) {
  const r = spawnSync(process.execPath, [script,...args], { stdio: 'inherit', env: { ...process.env, FX_API_BASE: cfg.apiPublicUrl, FX_APP_URL: cfg.appUrl } });
  if (r.status !== 0) process.exit(r.status || 1);
}
