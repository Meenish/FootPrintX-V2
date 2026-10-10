// Website-reputation vocabulary shared by backend, web app and extension.
// These statuses are deliberately distinct from account-discovery and breach
// statuses: visiting a website says nothing about having an account there.
import { normalizeHost } from './domain.js';

export const REPUTATION_STATUS = Object.freeze({
  NO_KNOWN_THREAT: 'no_known_threat', // a check completed and found no listing / heuristic signal
  SUSPICIOUS: 'suspicious', // weaker indicators only (e.g. lookalike of a major brand)
  MALICIOUS: 'malicious', // exact or parent-domain match in a threat dataset
  UNKNOWN: 'unknown', // insufficient evidence (e.g. no threat dataset loaded / dataset stale)
  UNAVAILABLE: 'unavailable', // check failed: offline, timeout, provider/server error
  PENDING: 'pending', // check in progress
  NOT_CHECKED: 'not_checked', // local/internal page, unsupported scheme, protection off
});

// Toolbar presentation. Color is never the only signal: every state also has
// a distinct badge glyph and a text label (used for the accessible title).
export const TOOLBAR = Object.freeze({
  [REPUTATION_STATUS.MALICIOUS]: { color: 'red', badge: '!', label: 'Known threat detected' },
  [REPUTATION_STATUS.SUSPICIOUS]: { color: 'amber', badge: '?', label: 'Suspicious indicators' },
  [REPUTATION_STATUS.NO_KNOWN_THREAT]: { color: 'green', badge: '✓', label: 'No known threat detected' },
  [REPUTATION_STATUS.UNKNOWN]: { color: 'grey', badge: '', label: 'Not enough information' },
  [REPUTATION_STATUS.UNAVAILABLE]: { color: 'grey', badge: '', label: 'Check unavailable' },
  [REPUTATION_STATUS.PENDING]: { color: 'grey', badge: '…', label: 'Checking…' },
  [REPUTATION_STATUS.NOT_CHECKED]: { color: 'grey', badge: '', label: 'Not checked' },
});

export const STATUS_EXPLANATION = Object.freeze({
  no_known_threat:
    'The available checks found no known threat for this site. This is not a guarantee that the site is safe.',
  suspicious:
    'This site shows warning signs (for example, it resembles a well-known brand). It is not on a known-threat list. Be careful before signing in or paying.',
  malicious: 'This site, or a domain it belongs to, is listed in a threat-intelligence dataset used by FootprintX.',
  unknown: 'FootprintX does not have enough information to assess this site (for example, the threat dataset is not loaded or is out of date).',
  unavailable: 'The check could not be completed (offline, timeout or service error). This is not a clean result.',
  pending: 'A check is in progress.',
  not_checked: 'This page was not checked.',
});

// Security events the extension may synchronise (only with opt-in). Routine
// clean visits are never synchronised.
export const EXTENSION_EVENT_TYPES = Object.freeze([
  'malicious_site_blocked', // red warning shown
  'suspicious_site_warned', // amber warning shown
  'cached_result_escalated', // a newer dataset changed a cached clean result to a threat
]);

// Major multi-tenant platforms and brands. A threat listing for one of these
// registrable domains (or one of the shared-content hosts below) would flag a
// huge amount of legitimate traffic, so such listings are rejected at
// ingestion. Listings for *other users'* subdomains of these platforms (e.g.
// "phish123.weeblysite.com") are still accepted because they only match that
// subdomain and its children.
export const PROTECTED_PLATFORM_DOMAINS = Object.freeze(new Set([
  'google.com', 'googleusercontent.com', 'gstatic.com', 'youtube.com', 'gmail.com', 'goo.gl', 'forms.gle', 'g.page',
  'microsoft.com', 'live.com', 'office.com', 'office365.com', 'sharepoint.com', 'onedrive.com', 'outlook.com', 'azurewebsites.net', 'windows.net', 'msn.com', 'bing.com',
  'apple.com', 'icloud.com', 'amazon.com', 'amazon.in', 'amazonaws.com', 'cloudfront.net',
  'facebook.com', 'instagram.com', 'whatsapp.com', 'fb.com', 'x.com', 'twitter.com', 't.co', 'linkedin.com', 'lnkd.in',
  'github.com', 'githubusercontent.com', 'gitlab.com', 'bitbucket.org', 'atlassian.net',
  'dropbox.com', 'box.com', 'wetransfer.com', 'notion.so', 'notion.site', 'canva.com', 'figma.com', 'adobe.com',
  'wordpress.com', 'blogspot.com', 'medium.com', 'substack.com', 'wixsite.com', 'wix.com', 'weebly.com', 'weeblysite.com',
  'squarespace.com', 'webflow.io', '000webhostapp.com', 'firebaseapp.com', 'web.app', 'appspot.com', 'pages.dev', 'workers.dev',
  'vercel.app', 'netlify.app', 'herokuapp.com', 'glitch.me', 'r2.dev', 'duckdns.org', 'ngrok.io', 'ngrok-free.app',
  'cloudflare.com', 'akamaihd.net', 'yahoo.com', 'zoom.us', 'paypal.com', 'docusign.net', 'docusign.com', 'mailchimp.com', 'sendgrid.net',
  'telegram.org', 't.me', 'discord.com', 'discord.gg', 'reddit.com', 'wikipedia.org', 'ipfs.io', 'dweb.link', 'surveymonkey.com', 'typeform.com', 'jotform.com',
]));

// Shared-content hosts on protected platforms where content is path-based,
// so a host-level listing cannot be attributed to a single bad actor.
export const PROTECTED_HOSTS = Object.freeze(new Set([
  'sites.google.com', 'docs.google.com', 'drive.google.com', 'forms.google.com', 'storage.googleapis.com', 'script.google.com',
  'onedrive.live.com', '1drv.ms', 'forms.office.com', 'www.dropbox.com', 'dl.dropboxusercontent.com', 'gist.github.com',
  'raw.githubusercontent.com', 'bit.ly', 'tinyurl.com', 'ipfs.io', 'www.canva.com', 'www.notion.so', 'www.wix.com', 'www.weebly.com',
]));

/**
 * Validates a hostname from a threat feed. Returns the normalized hostname, or
 * { rejected: reason } when the listing must not be used.
 */
export function validateIndicatorHost(raw) {
  const n = normalizeHost(String(raw || '').trim());
  if (!n) return { rejected: 'invalid' };
  if (n.isLocal) return { rejected: 'local_or_private' };
  if (n.isIp) return { hostname: n.hostname, isIp: true };
  if (!n.registrableDomain) return { rejected: 'public_suffix' };
  if (PROTECTED_HOSTS.has(n.hostname)) return { rejected: 'protected_shared_host' };
  const bare = n.hostname.replace(/^www\./, '');
  if (PROTECTED_PLATFORM_DOMAINS.has(bare)) return { rejected: 'protected_platform_domain' };
  return { hostname: n.hostname, isIp: false };
}

/**
 * Combines independent signals into one verdict. A malicious listing always
 * wins; a completed lookup with no listing plus suspicious heuristics is
 * amber; green is only possible when the lookup actually completed.
 */
export function combineVerdict({ lookup, heuristics }) {
  // lookup: { ok: boolean, matches: [...], datasetUsable: boolean }
  // heuristics: { suspicious: boolean, reasons: [...] }
  const reasons = [];
  if (lookup?.ok && lookup.matches?.length) {
    for (const m of lookup.matches) reasons.push({ code: 'THREAT_LIST_MATCH', ...m });
    return { status: REPUTATION_STATUS.MALICIOUS, reasons };
  }
  if (heuristics?.suspicious) {
    return { status: REPUTATION_STATUS.SUSPICIOUS, reasons: [...heuristics.reasons], lookupCompleted: !!lookup?.ok };
  }
  if (!lookup || !lookup.ok) return { status: REPUTATION_STATUS.UNAVAILABLE, reasons: [{ code: lookup?.errorCode || 'LOOKUP_FAILED' }] };
  if (!lookup.datasetUsable) return { status: REPUTATION_STATUS.UNKNOWN, reasons: [{ code: lookup.datasetReason || 'DATASET_NOT_READY' }] };
  return { status: REPUTATION_STATUS.NO_KNOWN_THREAT, reasons: [] };
}
