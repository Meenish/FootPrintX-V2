// Builds the FootprintX browser extension.
//
//   node build.mjs                      → dist/chromium and dist/firefox
//   node build.mjs --target=chromium    → one target
//   node build.mjs --zip                → also writes dist/footprintx-<target>-<version>.zip
//
// Environment:
//   FX_API_BASE   FootprintX API origin the extension talks to (default http://localhost:5000)
//   FX_APP_URL    FootprintX web app URL for links (default http://localhost:5173)
//   FX_GECKO_ID   Firefox add-on id (default footprintx@footprintx.example)
//
// No remote code: everything (including the shared domain logic and the
// Public Suffix List data) is bundled into the package at build time.
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import * as esbuild from 'esbuild';

const here = path.dirname(fileURLToPath(import.meta.url));
const args = Object.fromEntries(process.argv.slice(2).map((a) => a.replace(/^--/, '').split('=')).map(([k, v]) => [k, v ?? true]));
const targets = args.target && args.target !== 'all' ? [args.target] : ['chromium', 'firefox'];
const pkg = JSON.parse(fs.readFileSync(path.join(here, 'package.json'), 'utf8'));
const VERSION = pkg.version;
const API_BASE = (process.env.FX_API_BASE || 'http://localhost:5000').replace(/\/$/, '');
const APP_URL = (process.env.FX_APP_URL || 'http://localhost:5173').replace(/\/$/, '');
const apiOrigin = new URL(API_BASE).origin;
if (!/^https:\/\//.test(API_BASE) && !/^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(apiOrigin)) {
  console.error('FX_API_BASE must be https:// (http is only allowed for localhost development).');
  process.exit(1);
}

// ---------- icons (generated; no binary assets in the repo) ----------
const COLORS = { green: [6, 118, 71], red: [180, 35, 24], amber: [181, 71, 8], grey: [71, 84, 103] };
const GLYPH_INK = [255, 255, 255];
const crcTable = Array.from({ length: 256 }, (_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
const crc32 = (buf) => {
  let c = 0xffffffff;
  for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};
function png(size, rgba) {
  const chunk = (type, data) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const td = Buffer.concat([Buffer.from(type), data]);
    const crc = Buffer.alloc(4);
    crc.writeUInt32BE(crc32(td));
    return Buffer.concat([len, td, crc]);
  };
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  const raw = Buffer.alloc((size * 4 + 1) * size);
  for (let y = 0; y < size; y++) rgba.copy(raw, y * (size * 4 + 1) + 1, y * size * 4, (y + 1) * size * 4);
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', ihdr), chunk('IDAT', zlib.deflateSync(raw)), chunk('IEND', Buffer.alloc(0))]);
}
const segDist = (px, py, [ax, ay], [bx, by]) => {
  const dx = bx - ax;
  const dy = by - ay;
  const t = Math.max(0, Math.min(1, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy || 1)));
  return Math.hypot(px - (ax + t * dx), py - (ay + t * dy));
};
const GLYPHS = {
  green: { lines: [[[0.27, 0.52], [0.43, 0.68]], [[0.43, 0.68], [0.74, 0.35]]], dots: [] },
  red: { lines: [[[0.5, 0.24], [0.5, 0.56]]], dots: [[0.5, 0.74]] },
  amber: {
    // Question mark: an arc (polyline) over the top, then a short stem.
    lines: (() => {
      const pts = [];
      for (let i = 0; i <= 12; i++) {
        const a = Math.PI * (1.05 - (1.55 * i) / 12);
        pts.push([0.5 + 0.13 * Math.cos(a), 0.36 - 0.12 * Math.sin(a)]);
      }
      pts.push([0.5, 0.5], [0.5, 0.56]);
      return pts.slice(1).map((p, i) => [pts[i], p]);
    })(),
    dots: [[0.5, 0.74]],
  },
  grey: { lines: [[[0.3, 0.5], [0.7, 0.5]]], dots: [] },
};
function icon(color, size) {
  const [r, g, b] = COLORS[color];
  const glyph = GLYPHS[color];
  const stroke = 0.075;
  const out = Buffer.alloc(size * size * 4);
  const ss = 4;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let bg = 0;
      let ink = 0;
      for (let sy = 0; sy < ss; sy++) {
        for (let sx = 0; sx < ss; sx++) {
          const u = (x + (sx + 0.5) / ss) / size;
          const v = (y + (sy + 0.5) / ss) / size;
          // Shield: rounded top rectangle that tapers to a point at the bottom.
          const half = v < 0.55 ? 0.42 : 0.42 * Math.max(0, (0.97 - v) / 0.42);
          const top = 0.05;
          const inShield = v > top && v < 0.97 && Math.abs(u - 0.5) < half - (v < top + 0.08 ? (0.08 - (v - top)) * 0.6 : 0);
          if (!inShield) continue;
          bg += 1;
          const d = Math.min(...glyph.lines.map((l) => segDist(u, v, l[0], l[1])), ...glyph.dots.map(([cx, cy]) => Math.hypot(u - cx, v - cy) - 0.02));
          if (d < stroke / 2 + (size <= 16 ? 0.02 : 0)) ink += 1;
        }
      }
      const n = ss * ss;
      const a = bg / n;
      const k = bg ? ink / bg : 0;
      const i = (y * size + x) * 4;
      out[i] = Math.round(r * (1 - k) + GLYPH_INK[0] * k);
      out[i + 1] = Math.round(g * (1 - k) + GLYPH_INK[1] * k);
      out[i + 2] = Math.round(b * (1 - k) + GLYPH_INK[2] * k);
      out[i + 3] = Math.round(a * 255);
    }
  }
  return png(size, out);
}

// ---------- minimal zip writer (deflate) ----------
function zip(files) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const [name, data] of files) {
    const nameBuf = Buffer.from(name);
    const deflated = zlib.deflateRawSync(data);
    const crc = crc32(data);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(8, 8);
    local.writeUInt32LE(0, 10);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(deflated.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(nameBuf.length, 26);
    locals.push(local, nameBuf, deflated);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(8, 10);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(deflated.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBuf.length, 28);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, nameBuf);
    offset += 30 + nameBuf.length + deflated.length;
  }
  const cd = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(files.length, 8);
  end.writeUInt16LE(files.length, 10);
  end.writeUInt32LE(cd.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, end]);
}

// ---------- manifest ----------
function manifest(target) {
  const icons = { 16: 'icons/grey-16.png', 32: 'icons/grey-32.png', 48: 'icons/grey-48.png', 128: 'icons/grey-128.png' };
  const m = {
    manifest_version: 3,
    name: 'FootprintX',
    short_name: 'FootprintX',
    description: 'FootprintX website threat warnings. Checks the domains you open using privacy-preserving hash-prefix lookups.',
    version: VERSION,
    icons,
    action: { default_popup: 'popup.html', default_title: 'FootprintX', default_icon: icons },
    options_ui: { page: 'options.html', open_in_tab: true },
    // storage: settings/cache; alarms: periodic refresh; webNavigation: hostnames of top-level
    // navigations; notifications: suspicious-site and threat-update notices.
    permissions: ['storage', 'alarms', 'webNavigation', 'notifications'],
    // Only the FootprintX API. No access to the content of websites you visit.
    host_permissions: [`${apiOrigin}/*`],
    content_security_policy: { extension_pages: "script-src 'self'; object-src 'none'; base-uri 'none'" },
  };
  if (target === 'chromium') {
    m.background = { service_worker: 'background.js' };
    m.minimum_chrome_version = '116';
  } else {
    m.background = { scripts: ['background.js'] };
    m.browser_specific_settings = { gecko: { id: process.env.FX_GECKO_ID || 'footprintx@footprintx.example', strict_min_version: '121.0' } };
  }
  return m;
}

// ---------- build ----------
for (const target of targets) {
  const out = path.join(here, 'dist', target);
  fs.rmSync(out, { recursive: true, force: true });
  fs.mkdirSync(path.join(out, 'icons'), { recursive: true });
  await esbuild.build({
    entryPoints: {
      background: path.join(here, 'src/background.js'),
      popup: path.join(here, 'src/pages/popup.js'),
      options: path.join(here, 'src/pages/options.js'),
      warning: path.join(here, 'src/pages/warning.js'),
    },
    outdir: out,
    bundle: true,
    format: 'iife',
    target: target === 'firefox' ? ['firefox121'] : ['chrome116'],
    minify: !!args.minify,
    legalComments: 'none',
    define: { __FX_API_BASE__: JSON.stringify(API_BASE), __FX_APP_URL__: JSON.stringify(APP_URL) },
    logLevel: 'warning',
  });
  for (const f of fs.readdirSync(path.join(here, 'static'))) fs.copyFileSync(path.join(here, 'static', f), path.join(out, f));
  for (const color of Object.keys(COLORS)) for (const size of [16, 32, 48, 128]) fs.writeFileSync(path.join(out, 'icons', `${color}-${size}.png`), icon(color, size));
  fs.writeFileSync(path.join(out, 'build-info.json'), JSON.stringify({ apiBase: API_BASE, appUrl: APP_URL, version: VERSION }));
  fs.writeFileSync(path.join(out, 'manifest.json'), JSON.stringify(manifest(target), null, 2));
  console.log(`Built ${target} extension → ${path.relative(process.cwd(), out)} (API ${API_BASE})`);
  if (args.zip) {
    const files = [];
    const walk = (dir) => {
      for (const f of fs.readdirSync(dir)) {
        const p = path.join(dir, f);
        if (fs.statSync(p).isDirectory()) walk(p);
        else files.push([path.relative(out, p).split(path.sep).join('/'), fs.readFileSync(p)]);
      }
    };
    walk(out);
    const zipPath = path.join(here, 'dist', `footprintx-${target}-${VERSION}.zip`);
    fs.writeFileSync(zipPath, zip(files));
    console.log(`Packaged ${path.relative(process.cwd(), zipPath)}`);
  }
}
