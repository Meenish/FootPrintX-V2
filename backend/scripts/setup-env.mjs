// Creates backend/.env from .env.example with freshly generated secrets.
// Never overwrites an existing .env.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const target = path.join(root, 'backend/.env');
if (fs.existsSync(target)) {
  console.log('backend/.env already exists; not overwriting. Delete it first to regenerate.');
  process.exit(0);
}
const hex = () => crypto.randomBytes(32).toString('hex');
let text = fs.readFileSync(path.join(root, '.env.example'), 'utf8');
text = text
  .replace(/^ENCRYPTION_KEYS=.*$/m, `ENCRYPTION_KEYS=k1:${hex()}`)
  .replace(/^INDEX_KEY=.*$/m, `INDEX_KEY=${hex()}`)
  .replace(/^DEV_SYNTHETIC_DATA=.*$/m, 'DEV_SYNTHETIC_DATA=true')
  .replace(/^BILLING_MODE=.*$/m, 'BILLING_MODE=disabled')
  // Without a threat dataset every website check and every extension lookup can
  // only answer "unknown", so the Premium experience looks broken on a fresh
  // install. Turn the public feed on by default; it syncs on first startup.
  .replace(/^THREAT_FEEDS=.*$/m, 'THREAT_FEEDS=phishing_database');
fs.writeFileSync(target, text, { mode: 0o600 });
console.log('Created backend/.env with new random ENCRYPTION_KEYS and INDEX_KEY (local development settings).');
console.log('Synthetic development data is ON; purchases remain disabled. Never enable synthetic data in production.');
console.log('Threat feed "phishing_database" is enabled; it downloads on first startup (needs internet).');
