// Application-level cryptography.
//
//  * encrypt()/decrypt(): AES-256-GCM (authenticated encryption) with a fresh
//    96-bit random nonce per message and *additional authenticated data*
//    (AAD) binding each ciphertext to its purpose and row (e.g.
//    "connection:<id>:refresh_token"). A ciphertext copied into another row or
//    field fails authentication instead of decrypting.
//  * Key ring: ENCRYPTION_KEYS="k2:<hex>,k1:<hex>". New data is encrypted
//    with the first key; the key id is stored with each record so older
//    records stay readable during rotation (see docs/THREAT_MODEL.md).
//  * keyedHash(): HMAC-SHA-256 under purpose-specific subkeys derived from
//    INDEX_KEY with HKDF. Used for blind indexes (email uniqueness),
//    de-duplication references and IP pseudonymization. Never reversible.
//  * Session/reset/link tokens are random 256-bit values; only their SHA-256
//    hash is stored.
import crypto from 'node:crypto';
import { getConfig } from './config.js';

const VERSION = 1;

function ring() {
  const keys = getConfig().keyRing;
  if (!keys.length) throw new Error('No encryption keys configured.');
  return keys;
}

export function encrypt(plaintext, aad) {
  if (typeof aad !== 'string' || !aad) throw new Error('encrypt() requires an AAD context string.');
  const { id, key } = ring()[0];
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ct = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  return { v: VERSION, kid: id, iv: iv.toString('base64'), ct: ct.toString('base64'), tag: cipher.getAuthTag().toString('base64') };
}

export function decrypt(record, aad) {
  if (!record || record.v !== VERSION) throw new Error('Unsupported ciphertext record.');
  const entry = ring().find((k) => k.id === record.kid);
  if (!entry) throw new Error(`Encryption key "${record.kid}" is not configured.`);
  const decipher = crypto.createDecipheriv('aes-256-gcm', entry.key, Buffer.from(record.iv, 'base64'));
  decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(Buffer.from(record.tag, 'base64'));
  return Buffer.concat([decipher.update(Buffer.from(record.ct, 'base64')), decipher.final()]).toString('utf8');
}

/** True if the record was encrypted with a key other than the current primary. */
export const needsReencryption = (record) => record?.kid !== ring()[0].id;

const subkeys = new Map();
function subkey(purpose) {
  if (!subkeys.has(purpose)) {
    const k = crypto.hkdfSync('sha256', getConfig().indexKey, Buffer.alloc(0), Buffer.from(`footprintx:${purpose}`), 32);
    subkeys.set(purpose, Buffer.from(k));
  }
  return subkeys.get(purpose);
}
/** Test hook: config changes invalidate derived subkeys. */
export const resetDerivedKeys = () => subkeys.clear();

export function keyedHash(purpose, value) {
  return crypto.createHmac('sha256', subkey(purpose)).update(String(value)).digest('hex');
}

export const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');
export const sha256 = (value) => crypto.createHash('sha256').update(String(value)).digest('hex');

export function timingSafeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
}

/** Human-enterable one-time code (no ambiguous characters), e.g. "K7QF-M2XA". */
export function humanCode() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = crypto.randomBytes(8);
  const chars = [...bytes].map((b) => alphabet[b % alphabet.length]);
  return `${chars.slice(0, 4).join('')}-${chars.slice(4).join('')}`;
}

/** PKCE (RFC 7636) S256 verifier/challenge pair. */
export function generatePkce() {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge, method: 'S256' };
}

/** Gmail-aware canonical form used for de-duplicating mailbox connections. */
export function canonicalEmail(email) {
  const e = String(email).trim().toLowerCase();
  const [local, domain] = e.split('@');
  if (!domain) return e;
  if (domain === 'gmail.com' || domain === 'googlemail.com') return `${local.split('+')[0].replace(/\./g, '')}@gmail.com`;
  return `${local.split('+')[0]}@${domain}`;
}
