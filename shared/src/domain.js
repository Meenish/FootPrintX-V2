// Domain normalization and matching shared by the backend and the browser
// extension. Everything here is pure (no network, no storage) so the same
// semantics apply on both sides and are unit-tested once.
//
// Matching rules (documented in docs/EXTENSION.md and docs/THREAT_MODEL.md):
//   * Hostnames are compared in their ASCII (punycode) form, lower-case, with
//     any trailing dot removed. Internationalized names are converted by the
//     WHATWG URL parser, which applies IDNA/UTS-46 processing.
//   * An indicator for host I matches host H only if H === I or H is a
//     subdomain of I (H ends with "." + I). A listing never matches a parent
//     domain or a sibling: "login.evil.example" does NOT flag "evil.example",
//     and "sites.google.com" never flags "google.com".
//   * We never match on substrings ("paypal" inside "notpaypal.com" is not a
//     match) and never across the registrable-domain boundary.
import { parse } from 'tldts';
import { toUnicode } from 'punycode/punycode.es6.js';

const MAX_HOST_LENGTH = 253;
const LABEL_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

// Hostnames that identify the user's own machine or private network. These
// are never sent anywhere and never reported as "checked".
const LOCAL_SUFFIXES = ['localhost', 'local', 'internal', 'lan', 'home.arpa', 'intranet', 'corp'];

function isPrivateIpv4(host) {
  const m = host.match(IPV4_RE);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  return (
    a === 10 ||
    a === 127 ||
    a === 0 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 100 && b >= 64 && b <= 127)
  );
}

/**
 * Normalize a hostname or URL into the canonical form used everywhere in
 * FootprintX. Returns null for anything that is not an http(s) host we can
 * reason about. Paths, query strings, fragments, credentials and ports are
 * discarded and never returned.
 */
export function normalizeHost(input) {
  if (typeof input !== 'string') return null;
  const raw = input.trim();
  if (!raw || raw.length > 2048) return null;

  let url;
  try {
    url = raw.includes('://') ? new URL(raw) : new URL(`http://${raw}`);
  } catch {
    return null;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;

  let hostname = url.hostname.toLowerCase().replace(/\.$/, '');
  if (!hostname) return null;

  const isIpv6 = hostname.startsWith('[');
  const isIpv4 = IPV4_RE.test(hostname);
  if (isIpv6 || isIpv4) {
    const isPrivate = isIpv6 ? /^\[(::1|f[cd]|fe80)/i.test(hostname) : isPrivateIpv4(hostname);
    return { hostname, unicodeHostname: hostname, isIp: true, isLocal: isPrivate, registrableDomain: hostname, publicSuffix: null };
  }

  if (hostname.length > MAX_HOST_LENGTH) return null;
  const labels = hostname.split('.');
  if (labels.some((l) => !LABEL_RE.test(l))) return null;

  const isLocal = labels.length === 1 || LOCAL_SUFFIXES.some((s) => hostname === s || hostname.endsWith(`.${s}`));
  const info = parse(hostname, { allowPrivateDomains: true });
  let unicodeHostname = hostname;
  try {
    unicodeHostname = toUnicode(hostname);
  } catch {
    /* keep ASCII form */
  }
  return {
    hostname,
    unicodeHostname,
    isIp: false,
    isLocal,
    // null when the host *is* a public suffix (e.g. "github.io", "co.uk").
    registrableDomain: info.domain || null,
    publicSuffix: info.publicSuffix || null,
  };
}

/**
 * Registrable domain ("eTLD+1") for a hostname, using the Public Suffix List
 * including private suffixes (so "alice.github.io" is its own registrable
 * domain and does not collapse into "github.io").
 */
export function registrableDomain(host) {
  const n = normalizeHost(host);
  return n ? n.registrableDomain : null;
}

/**
 * The hostnames whose listing would apply to `hostname`: the host itself and
 * each parent up to (and including) its registrable domain. Never includes a
 * bare public suffix. At most `max` entries, most specific first.
 */
export function hostCandidates(hostname, max = 5) {
  const n = normalizeHost(hostname);
  if (!n) return [];
  if (n.isIp) return [n.hostname];
  if (!n.registrableDomain) return [];
  const out = [];
  let current = n.hostname;
  while (current && out.length < max) {
    out.push(current);
    if (current === n.registrableDomain) break;
    current = current.slice(current.indexOf('.') + 1);
  }
  // Always include the registrable domain even if the host is very deep.
  if (!out.includes(n.registrableDomain)) out[out.length - 1] = n.registrableDomain;
  return out;
}

/** True when an indicator listed for `indicatorHost` applies to `hostname`. */
export function indicatorMatches(hostname, indicatorHost) {
  if (!hostname || !indicatorHost) return false;
  return hostname === indicatorHost || hostname.endsWith(`.${indicatorHost}`);
}

/** Lower-case hex SHA-256 using WebCrypto (available in Node 20+ and browsers). */
export async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(text);
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** Length of the hash prefix (hex chars) exchanged with the reputation API: 32 bits. */
export const HASH_PREFIX_HEX_LENGTH = 8;

export const hashPrefixOf = (fullHashHex) => fullHashHex.slice(0, HASH_PREFIX_HEX_LENGTH);

/**
 * Builds the privacy-preserving lookup for a hostname: the full hashes stay
 * local; only the short prefixes are sent to the server.
 */
export async function buildHashLookup(hostname) {
  const candidates = hostCandidates(hostname);
  const entries = [];
  for (const candidate of candidates) {
    const fullHash = await sha256Hex(candidate);
    entries.push({ candidate, fullHash, prefix: hashPrefixOf(fullHash) });
  }
  return entries;
}

/** Masks an email address for display: "alice@example.com" -> "a***e@example.com". */
export function maskEmail(email) {
  if (typeof email !== 'string' || !email.includes('@')) return '***';
  const [local, domain] = email.split('@');
  const masked = local.length <= 2 ? `${local[0] || ''}***` : `${local[0]}***${local[local.length - 1]}`;
  return `${masked}@${domain}`;
}
