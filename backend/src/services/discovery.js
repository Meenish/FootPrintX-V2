// Account discovery from email *metadata*. Pure functions: no network.
//
// Input per message: { id, from, subject, snippet?, internalDate, authResults? }
//   - subject/snippet are classified in memory and then discarded; they are
//     never stored, logged or returned.
//   - the Gmail message id is stored only as an HMAC (refHash) for de-dup.
//
// Evidence strength:
//   strong: signup / verification / password reset / password changed /
//           security alert / login notice / MFA change / account closed
//   weak:   billing, generic "your account" mail
//   ignored: newsletters/marketing and anything unmatched
// A confirmed account needs at least one strong item from a sender that did
// not fail authentication. Weak-only senders become "possible" associations
// (shown separately, excluded from DASI). Newsletters never create records.
import { normalizeHost } from '@footprintx/shared/domain';
import { canonicalServiceDomain, categoryFor, officialServiceName } from './catalog.js';

const DAY = 864e5;

// Consumer mailbox domains: mail *from* these is usually person-to-person, so
// it is never treated as evidence of a service account. (Mail from the
// providers' own service domains, e.g. accounts.google.com, still counts.)
export const MAILBOX_PROVIDERS = new Set(['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'yahoo.com', 'icloud.com', 'me.com', 'proton.me', 'protonmail.com', 'aol.com']);

// Bulk-mail infrastructure: the sending domain says nothing about the brand.
export const SENDING_PLATFORMS = new Set([
  'amazonses.com', 'sendgrid.net', 'sendgrid.com', 'mailchimp.com', 'mandrillapp.com', 'mcsv.net', 'rsgsv.net', 'mailgun.org', 'mailgun.com', 'sparkpostmail.com',
  'postmarkapp.com', 'mktomail.com', 'klaviyomail.com', 'customeriomail.com', 'exacttarget.com', 'cmail19.com', 'cmail20.com', 'sendinblue.com', 'brevo.com', 'hubspotemail.net',
]);

const NOISE_WORDS = /\b(team|support|security|no-?reply|do-?not-?reply|notifications?|accounts?|alerts?|news(letter)?|hello|info|mail|updates?|billing|help|service|customer care)\b/gi;

// Order matters: the first matching rule wins.
export const RULES = [
  { kind: 'security_alert', strength: 'strong', re: /(unusual (sign|log)[- ]?in|unusual activity|suspicious (activity|sign|log|attempt)|critical security alert|security alert|unrecogni[sz]ed (device|sign|log)|someone (else )?(tried|may have|has your|knows your)|sign[- ]?in attempt (was )?(blocked|prevented)|account (was |has been )?(locked|compromised|accessed by)|was this you\??)/i },
  { kind: 'password_changed', strength: 'strong', re: /(password (was |has been )?(successfully )?(changed|updated)|your password (was|has been) (reset|changed|updated)|password change (confirmation|successful))/i },
  { kind: 'mfa_disabled', strength: 'strong', re: /((2-?step|two[- ]step|two[- ]factor|2fa|multi[- ]factor)( verification| authentication)?( is| was| has been)? (now )?(turned off|disabled|removed|deactivated|off\b))/i },
  { kind: 'mfa_enabled', strength: 'strong', re: /((2-?step|two[- ]step|two[- ]factor|2fa|multi[- ]factor)( verification| authentication)?( is| was| has been)? (now )?(turned on|enabled|activated|set up|on\b))/i },
  { kind: 'account_closed', strength: 'strong', re: /(account (has been |was |is )?(deleted|closed|deactivated)|we('ve| have) (deleted|closed) your account)/i },
  { kind: 'password_reset', strength: 'strong', re: /((reset|recover) your password|password reset|forgot (your )?password|reset password request)/i },
  { kind: 'newsletter', strength: 'ignored', re: /(newsletter|weekly digest|daily digest|thanks for subscribing|you('re| are) subscribed|webinar|% off|sale ends|deal of the day)/i },
  { kind: 'signup', strength: 'strong', re: /(welcome to|verify your (email|account|e-mail)|confirm your (email|account|registration|e-mail)|account (has been |was )?(created|activated)|activate your account|thanks for (signing up|joining|registering|creating)|complete your (sign ?up|registration)|registration (confirmation|successful|complete)|finish (setting up|creating) your account)/i },
  { kind: 'login_notice', strength: 'strong', re: /(new (sign|log)[- ]?in|(signed|logged) in (from|on) (a )?new|new device)/i },
  { kind: 'billing', strength: 'weak', re: /(receipt|invoice|payment (received|confirmation|successful)|order confirmation|your order|subscription (renew|confirm|receipt|has been)|billing (statement|update))/i },
  { kind: 'generic_account', strength: 'weak', re: /(your account|account (update|information|settings)|profile (update|changes))/i },
];

export function parseSender(from = '') {
  const m = String(from).match(/^\s*"?([^"<]*?)"?\s*<([^>]+)>\s*$/);
  const email = (m ? m[2] : String(from)).trim().toLowerCase();
  const displayName = m ? m[1].trim().slice(0, 80) : '';
  const host = email.includes('@') ? email.split('@').pop().replace(/[>\s]/g, '') : '';
  return { email, host, displayName };
}

export function cleanDisplayName(raw = '') {
  return raw
    .replace(/\bvia\b.*$/i, '')
    .replace(NOISE_WORDS, ' ')
    .replace(/^\s*the\s+/i, '')
    .replace(/[^\p{L}\p{N}&.+' -]/gu, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 40);
}

const squash = (s) => s.toLowerCase().replace(/[^a-z0-9]/g, '');

export function serviceNameFor(domain, displayNames = []) {
  const official = officialServiceName(domain);
  if (official) return official;
  const label = domain.split('.')[0] || domain;
  const counts = new Map();
  for (const raw of displayNames) {
    const cleaned = cleanDisplayName(raw);
    if (cleaned && cleaned.length <= 30 && squash(cleaned).includes(squash(label))) counts.set(cleaned, (counts.get(cleaned) || 0) + 1);
  }
  if (counts.size) return [...counts.entries()].sort((a, b) => b[1] - a[1])[0][0];
  return label.replace(/[-_]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

/** { key, domain, displayName, viaPlatform } or null for non-service senders. */
export function identifyService(from) {
  const { host, displayName } = parseSender(from);
  if (!host) return null;
  const n = normalizeHost(host);
  if (!n || !n.registrableDomain || n.isIp || n.isLocal) return null;
  const domain = n.registrableDomain;
  if (MAILBOX_PROVIDERS.has(domain)) return null;
  if (SENDING_PLATFORMS.has(domain)) {
    const cleaned = cleanDisplayName(displayName);
    if (!cleaned || cleaned.length > 30) return null;
    return { key: `name:${squash(cleaned)}`, domain: null, displayName: cleaned, viaPlatform: true };
  }
  const canonical = canonicalServiceDomain(domain);
  return { key: canonical, domain: canonical, displayName, viaPlatform: false };
}

export function classifyMessage({ subject = '', snippet = '' }) {
  const text = `${subject} ${snippet}`.slice(0, 600);
  for (const rule of RULES) if (rule.re.test(text)) return { kind: rule.kind, strength: rule.strength };
  return null;
}

/** Sender authentication from Gmail's Authentication-Results header. */
export function parseAuthResults(header, senderDomain) {
  if (!header) return 'unknown';
  const h = String(header).toLowerCase();
  if (/\bdmarc=pass\b/.test(h)) return 'pass';
  if (/\bdmarc=fail\b/.test(h)) return 'fail';
  const dkim = h.match(/dkim=pass[^;]*header\.(?:i|d)=@?([a-z0-9.-]+)/);
  if (dkim && senderDomain && (dkim[1] === senderDomain || dkim[1].endsWith(`.${senderDomain}`))) return 'pass';
  if (/\bspf=fail\b/.test(h) && /\bdkim=(fail|none)\b/.test(h)) return 'fail';
  return 'unknown';
}

/**
 * Folds one message into the per-service accumulator. `refHash` must be a
 * keyed hash of the message id (computed by the caller).
 */
export function addMessage(found, msg, refHash) {
  const svc = identifyService(msg.from);
  if (!svc) return 'not_a_service';
  const cls = classifyMessage(msg);
  if (!cls || cls.strength === 'ignored') return cls ? 'ignored' : 'unclassified';
  const observedAt = Number(msg.internalDate) || null;
  if (!observedAt) return 'no_date';
  const senderHost = parseSender(msg.from).host;
  const auth = parseAuthResults(msg.authResults, normalizeHost(senderHost)?.registrableDomain);
  let f = found.get(svc.key);
  if (!f) {
    f = { key: svc.key, domain: svc.domain, viaPlatform: svc.viaPlatform, names: [], evidence: [], weakCount: 0 };
    found.set(svc.key, f);
  }
  if (svc.displayName && f.names.length < 20) f.names.push(svc.displayName);
  // A failed-authentication sender may be spoofed: keep as weak only.
  const strength = auth === 'fail' ? 'weak' : cls.strength;
  if (strength === 'weak') f.weakCount += 1;
  f.evidence.push({ kind: cls.kind, strength, observedAt, refHash, auth, senderDomain: normalizeHost(senderHost)?.hostname || null });
  return 'recorded';
}

const KIND_PRIORITY = ['signup', 'password_reset', 'password_changed', 'security_alert', 'login_notice', 'mfa_enabled', 'mfa_disabled', 'account_closed'];

/** Converts accumulated evidence into account candidates. */
export function finalize(found) {
  const out = [];
  for (const f of found.values()) {
    const strong = f.evidence.filter((e) => e.strength === 'strong');
    const weak = f.evidence.filter((e) => e.strength === 'weak');
    let status;
    let confidence;
    if (strong.length) {
      status = 'confirmed';
      const authenticated = strong.some((e) => e.auth === 'pass');
      confidence = authenticated && !f.viaPlatform ? 'high' : 'medium';
    } else if (weak.length >= 2) {
      status = 'possible';
      confidence = 'low';
    } else continue;

    const all = f.evidence.map((e) => e.observedAt);
    const latest = (kind) => Math.max(0, ...f.evidence.filter((e) => e.kind === kind && e.strength === 'strong').map((e) => e.observedAt)) || null;
    const mfaOn = latest('mfa_enabled');
    const mfaOff = latest('mfa_disabled');
    const name = f.domain ? serviceNameFor(f.domain, f.names) : cleanDisplayName(f.names[0] || f.key.replace(/^name:/, ''));
    // Keep a bounded, most-relevant set of evidence rows per account.
    const evidence = [...strong].sort((a, b) => KIND_PRIORITY.indexOf(a.kind) - KIND_PRIORITY.indexOf(b.kind) || b.observedAt - a.observedAt).slice(0, 25);
    if (status === 'possible') evidence.push(...weak.slice(0, 5));
    out.push({
      serviceKey: f.key,
      serviceName: name || f.key,
      serviceDomain: f.domain,
      category: categoryFor(f.domain),
      status,
      confidence,
      firstObservedAt: new Date(Math.min(...all)),
      lastObservedAt: new Date(Math.max(...all)),
      weakSignalCount: weak.length,
      mfa: mfaOn || mfaOff ? { status: (mfaOn || 0) >= (mfaOff || 0) ? 'enabled' : 'disabled', observedAt: new Date(Math.max(mfaOn || 0, mfaOff || 0)) } : null,
      closedAt: latest('account_closed') ? new Date(latest('account_closed')) : null,
      evidence,
    });
  }
  return out;
}

export const isRecent = (date, days, now = Date.now()) => !!date && now - new Date(date).getTime() <= days * DAY;
