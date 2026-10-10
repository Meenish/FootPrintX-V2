// Packaging and delivery of the browser extension for in-app download.
//
// The extension must be built with the URL of the server that will serve it,
// because the build inlines FX_API_BASE. A zip produced on someone else's
// machine would point at their server, so the package is produced from this
// server's own configuration.
//
// Resolution order for a target:
//   1. A zip already present in extension/dist (produced by `npm run build`).
//      Used as-is in production, where spawning a build is not appropriate.
//   2. Outside production, build one on demand and cache it under
//      extension/dist. Rebuilt when the extension sources are newer.
//
// The download requires an authenticated web session but NOT Premium: a Free
// user is allowed to install the extension and see its status and upgrade path
// (the extension itself refuses active protection without server-side
// entitlement). See docs/PLANS.md.
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { getConfig } from '../config.js';
import { HttpError } from '../http.js';
import { log } from '../logger.js';

const execFileAsync = promisify(execFile);
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
const extDir = path.join(repoRoot, 'extension');
const distDir = path.join(extDir, 'dist');

export const TARGETS = Object.freeze({
  chromium: { label: 'Chrome, Edge, Brave and other Chromium browsers', storeReady: false },
  firefox: { label: 'Firefox', storeReady: false },
});

const BUILD_TIMEOUT_MS = 120e3;
let version = null;
/** Build locks, so concurrent downloads produce one build per target. */
const inFlight = new Map();

function extensionVersion() {
  if (version) return version;
  try {
    version = JSON.parse(fs.readFileSync(path.join(extDir, 'package.json'), 'utf8')).version || '0.0.0';
  } catch {
    version = '0.0.0';
  }
  return version;
}

const zipPathFor = (target) => path.join(distDir, `footprintx-${target}-${extensionVersion()}.zip`);

/** Newest mtime across the extension and shared sources, so a stale zip is rebuilt. */
async function sourcesChangedAt() {
  let newest = 0;
  const walk = async (dir) => {
    let entries;
    try {
      entries = await fsp.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (e.name === 'dist' || e.name === 'node_modules') continue;
      const p = path.join(dir, e.name);
      if (e.isDirectory()) await walk(p);
      else {
        const st = await fsp.stat(p).catch(() => null);
        if (st && st.mtimeMs > newest) newest = st.mtimeMs;
      }
    }
  };
  await walk(extDir);
  await walk(path.join(repoRoot, 'shared', 'src'));
  return newest;
}

async function buildPackage(target) {
  const cfg = getConfig();
  await execFileAsync(
    process.execPath,
    ['build.mjs', `--target=${target}`, '--zip'],
    {
      cwd: extDir,
      timeout: BUILD_TIMEOUT_MS,
      env: { ...process.env, FX_API_BASE: cfg.apiPublicUrl, FX_APP_URL: cfg.appUrl },
    }
  );
  const zipPath = zipPathFor(target);
  if (!fs.existsSync(zipPath)) throw new Error('build produced no package');
  return zipPath;
}

/**
 * Returns `{ path, filename, size, builtAt }` for the target's package.
 * Throws HttpError 503 when no package exists and none can be produced here.
 */
export async function getPackage(target) {
  if (!TARGETS[target]) throw new HttpError(400, 'UNKNOWN_TARGET', 'That browser is not a supported build target.');
  const zipPath = zipPathFor(target);
  const cfg = getConfig();

  const stat = await fsp.stat(zipPath).catch(() => null);
  if (stat) {
    if (cfg.isProduction) {
      let info;
      try { info = JSON.parse(await fsp.readFile(path.join(distDir, target, 'build-info.json'), 'utf8')); } catch { /* fail closed */ }
      if (info?.apiBase !== cfg.apiPublicUrl || info?.appUrl !== cfg.appUrl) throw new HttpError(503, 'PACKAGE_ORIGIN_MISMATCH', 'Rebuild the browser extension for this deployment before downloading it.');
      return describe(zipPath, stat);
    }
    let info;
    try { info = JSON.parse(await fsp.readFile(path.join(distDir, target, 'build-info.json'), 'utf8')); } catch { /* rebuild */ }
    const originMatches = info?.apiBase === cfg.apiPublicUrl && info?.appUrl === cfg.appUrl;
    const changed = await sourcesChangedAt();
    if (originMatches && stat.mtimeMs >= changed) return describe(zipPath, stat);
  }

  if (cfg.isProduction) {
    throw new HttpError(
      503,
      'PACKAGE_NOT_BUILT',
      'The extension package has not been built on this server. Run `npm run build -w extension -- --zip` during deployment.'
    );
  }

  if (!inFlight.has(target)) {
    inFlight.set(
      target,
      buildPackage(target).finally(() => inFlight.delete(target))
    );
  }
  try {
    await inFlight.get(target);
  } catch (err) {
    log.error('extension package build failed', { target, err });
    throw new HttpError(503, 'PACKAGE_BUILD_FAILED', 'The extension package could not be built on this server. See the server log, or build it manually with `npm run build -w extension -- --zip`.');
  }
  const built = await fsp.stat(zipPath);
  return describe(zipPath, built);
}

function describe(zipPath, stat) {
  return { path: zipPath, filename: path.basename(zipPath), size: stat.size, builtAt: stat.mtime.toISOString() };
}

/** Availability summary for the Settings screen; never throws. */
export async function packageStatus() {
  const cfg = getConfig();
  const out = { version: extensionVersion(), apiBase: cfg.apiPublicUrl, targets: {} };
  for (const [target, meta] of Object.entries(TARGETS)) {
    const stat = await fsp.stat(zipPathFor(target)).catch(() => null);
    let valid = Boolean(stat);
    if (cfg.isProduction && valid) {
      try {
        const info = JSON.parse(await fsp.readFile(path.join(distDir, target, 'build-info.json'), 'utf8'));
        valid = info.apiBase === cfg.apiPublicUrl && info.appUrl === cfg.appUrl;
      } catch { valid = false; }
    }
    out.targets[target] = {
      label: meta.label,
      // Outside production a package can always be produced on demand.
      available: valid || !cfg.isProduction,
      prebuilt: Boolean(stat),
      size: stat ? stat.size : null,
      builtAt: stat ? stat.mtime.toISOString() : null,
    };
  }
  return out;
}
