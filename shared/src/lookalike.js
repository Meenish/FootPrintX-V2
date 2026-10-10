// Conservative lookalike heuristics. These produce *suspicious* (amber)
// signals only — never a "malicious" verdict — and only for imitations of a
// short list of high-value brands. Being unfamiliar, new, or unpopular is
// never treated as suspicious.
//
// Implemented checks:
//   HOMOGRAPH            internationalized name whose ASCII "skeleton" equals a brand
//   MIXED_SCRIPT         one label mixes Latin with Cyrillic or Greek letters
//   BRAND_IN_SUBDOMAIN   e.g. "paypal.com.account-verify.example"
//   TYPOSQUAT            registrable label one edit away from a brand label (>= 6 chars)
// See docs/EXTENSION.md ("Detection quality") for the evaluation method.
import { normalizeHost } from './domain.js';

// Brand registrable domains. Brand labels are derived from these.
export const BRAND_DOMAINS = Object.freeze([
  'google.com', 'gmail.com', 'youtube.com', 'microsoft.com', 'outlook.com', 'office.com', 'live.com', 'apple.com', 'icloud.com',
  'amazon.com', 'amazon.in', 'paypal.com', 'facebook.com', 'instagram.com', 'whatsapp.com', 'twitter.com', 'linkedin.com',
  'github.com', 'gitlab.com', 'netflix.com', 'dropbox.com', 'adobe.com', 'spotify.com', 'yahoo.com', 'docusign.com',
  'coinbase.com', 'binance.com', 'kraken.com', 'metamask.io', 'steamcommunity.com', 'steampowered.com', 'roblox.com', 'discord.com',
  'chase.com', 'wellsfargo.com', 'bankofamerica.com', 'citibank.com', 'hsbc.com', 'barclays.co.uk', 'hdfcbank.com', 'icicibank.com',
  'onlinesbi.sbi', 'axisbank.com', 'kotak.com', 'paytm.com', 'phonepe.com', 'flipkart.com', 'myntra.com', 'irctc.co.in', 'incometax.gov.in',
  'americanexpress.com', 'mastercard.com', 'visa.com', 'stripe.com', 'shopify.com', 'ebay.com', 'walmart.com', 'zoom.us', 'slack.com',
]);

// Distinct brand labels with their canonical domains, e.g. "paypal" -> ["paypal.com"].
const BRAND_LABELS = (() => {
  const map = new Map();
  for (const d of BRAND_DOMAINS) {
    const label = d.split('.')[0];
    map.set(label, [...(map.get(label) || []), d]);
  }
  return map;
})();

// Characters that render (near-)identically to Latin letters. Covers the
// common Cyrillic/Greek homoglyphs plus digit substitutions used in skeletons.
const CONFUSABLES = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ԁ': 'd', 'ɡ': 'g', 'ӏ': 'l', 'һ': 'h',
  'ѕ': 's', 'ԛ': 'q', 'ԝ': 'w', 'к': 'k', 'м': 'm', 'н': 'h', 'т': 't', 'в': 'b', 'ь': 'b', 'ո': 'n', 'ս': 'u',
  'α': 'a', 'ο': 'o', 'ρ': 'p', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w',
  'ı': 'i', 'ł': 'l', 'ø': 'o', 'à': 'a', 'á': 'a', 'â': 'a', 'ä': 'a', 'å': 'a', 'ç': 'c', 'è': 'e', 'é': 'e', 'ê': 'e', 'ë': 'e',
  'ì': 'i', 'í': 'i', 'î': 'i', 'ï': 'i', 'ñ': 'n', 'ò': 'o', 'ó': 'o', 'ô': 'o', 'ö': 'o', 'õ': 'o', 'ù': 'u', 'ú': 'u', 'û': 'u', 'ü': 'u', 'ý': 'y',
};

const CYRILLIC = /\p{Script=Cyrillic}/u;
const GREEK = /\p{Script=Greek}/u;
const LATIN = /\p{Script=Latin}/u;

export function skeleton(label) {
  return [...label.toLowerCase()].map((ch) => CONFUSABLES[ch] ?? ch).join('');
}

// Optimal string alignment distance (Damerau-Levenshtein with adjacent
// transpositions), with an early exit once the distance exceeds `max`.
export function editDistance(a, b, max = 2) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    let rowMin = Infinity;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      rowMin = Math.min(rowMin, d[i][j]);
    }
    if (rowMin > max) return max + 1;
  }
  return d[a.length][b.length];
}

const isBrandOrBrandSubdomain = (host) => BRAND_DOMAINS.some((d) => host === d || host.endsWith(`.${d}`));

// Well-known legitimate domains that sit one edit away from a brand label.
// Extend this list (with evidence) when the evaluation finds a false positive.
export const TYPOSQUAT_ALLOWLIST = Object.freeze(new Set([]));

// Ordinary words that happen to be one edit from a brand label ("finance" vs
// "binance", "stripes" vs "stripe"). Labels here are never typosquat-flagged.
export const TYPOSQUAT_LABEL_ALLOWLIST = Object.freeze(new Set(['finance', 'stripes', 'offices', 'officer', 'gitlab', 'github']));

// Brand labels that are themselves common words; typosquat matching against
// them would mostly flag unrelated sites, so they are excluded from check 3.
const TYPOSQUAT_EXCLUDED_BRANDS = new Set(['office', 'stripe', 'kraken', 'outlook']);

/**
 * Analyzes a hostname for lookalike signals. Returns
 * { suspicious: boolean, reasons: [{ code, brand, message }] }.
 */
export function analyzeLookalike(input) {
  const n = normalizeHost(input);
  const result = { suspicious: false, reasons: [] };
  if (!n || n.isIp || n.isLocal || !n.registrableDomain) return result;
  const host = n.hostname;
  if (isBrandOrBrandSubdomain(host)) return result;

  const reg = n.registrableDomain;
  const regLabelAscii = reg.slice(0, reg.length - (n.publicSuffix ? n.publicSuffix.length + 1 : 0)).split('.').pop();
  const unicodeReg = n.unicodeHostname.split('.').slice(-reg.split('.').length).join('.');
  const regLabelUnicode = unicodeReg.split('.')[0];

  // 1. Homograph / mixed script (only meaningful for internationalized names).
  if (regLabelAscii.startsWith('xn--')) {
    const sk = skeleton(regLabelUnicode);
    if (BRAND_LABELS.has(sk)) {
      result.reasons.push({
        code: 'HOMOGRAPH',
        brand: BRAND_LABELS.get(sk)[0],
        message: `The address uses look-alike characters that make it read as "${BRAND_LABELS.get(sk)[0]}".`,
      });
    }
    const mixed = LATIN.test(regLabelUnicode) && (CYRILLIC.test(regLabelUnicode) || GREEK.test(regLabelUnicode));
    if (mixed) {
      result.reasons.push({ code: 'MIXED_SCRIPT', message: 'The site name mixes characters from different alphabets, a common disguise technique.' });
    }
  }

  // 2. A full brand domain embedded in the subdomain part.
  const sub = host.slice(0, Math.max(0, host.length - reg.length - 1));
  if (sub) {
    const embedded = BRAND_DOMAINS.find((d) => `.${sub}.`.includes(`.${d}.`) || sub.endsWith(d) || sub.includes(`${d}-`));
    if (embedded) {
      result.reasons.push({
        code: 'BRAND_IN_SUBDOMAIN',
        brand: embedded,
        message: `The address starts with "${embedded}" but the site actually belongs to "${reg}".`,
      });
    }
  }

  // 3. Typosquatting: one edit away from a brand label of 6+ characters,
  //    compared on the ASCII skeleton. Different TLDs of the brand itself
  //    (e.g. google.de) are NOT flagged: they are frequently legitimate.
  if (!TYPOSQUAT_ALLOWLIST.has(reg) && !TYPOSQUAT_LABEL_ALLOWLIST.has(regLabelAscii) && !BRAND_LABELS.has(regLabelAscii)) {
    const candidate = skeleton(regLabelUnicode).replace(/0/g, 'o').replace(/1/g, 'l');
    for (const [label, domains] of BRAND_LABELS) {
      if (label.length < 6 || TYPOSQUAT_EXCLUDED_BRANDS.has(label)) continue;
      if (regLabelAscii === label) break; // same label, different TLD: not flagged
      const raw = regLabelAscii.replace(/^xn--.*/, '');
      const dist = Math.min(editDistance(candidate, label, 1), raw ? editDistance(raw, label, 1) : 2);
      if (dist === 1 || (candidate === label && raw !== label)) {
        result.reasons.push({
          code: 'TYPOSQUAT',
          brand: domains[0],
          message: `The name "${reg}" is one character away from "${domains[0]}".`,
        });
        break;
      }
    }
  }

  // De-duplicate (a homograph is usually also a distance-0 skeleton match).
  const seen = new Set();
  result.reasons = result.reasons.filter((r) => (seen.has(r.code + r.brand) ? false : seen.add(r.code + r.brand)));
  if (result.reasons.some((r) => r.code === 'HOMOGRAPH')) result.reasons = result.reasons.filter((r) => r.code !== 'TYPOSQUAT');
  result.suspicious = result.reasons.length > 0;
  return result;
}
