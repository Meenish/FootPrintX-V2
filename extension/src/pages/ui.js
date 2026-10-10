// Tiny DOM helpers for extension pages. Text is always set with textContent;
// no HTML strings are ever parsed (no innerHTML), so data from the network or
// from URLs cannot inject markup or script.
const ext = globalThis.browser ?? globalThis.chrome;

export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k.startsWith('on') && typeof v === 'function') node.addEventListener(k.slice(2), v);
    else if (v === true) node.setAttribute(k, '');
    else if (v !== false && v != null) node.setAttribute(k, String(v));
  }
  for (const c of children.flat()) if (c != null) node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return node;
}

export const send = (msg) => ext.runtime.sendMessage(msg);

export function ago(t) {
  const ms = Date.now() - new Date(t).getTime();
  if (!Number.isFinite(ms)) return '';
  const m = Math.round(ms / 60e3);
  if (m < 1) return 'just now';
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} h ago`;
  return `${Math.round(h / 24)} days ago`;
}

const CODE_TEXT = {
  THREAT_LIST_MATCH: (r) => `${r.matchType === 'parent_domain' ? `Its parent domain ${r.matchedHost} is` : 'Listed'} in ${r.sourceLabel || 'a threat dataset'}${r.threatType ? ` (${r.threatType})` : ''}${r.lastSeenAt ? `, last confirmed ${new Date(r.lastSeenAt).toLocaleDateString()}` : ''}.`,
  USING_CACHED_RESULT: () => 'FootprintX could not re-check right now, so this saved result is shown.',
  OFFLINE: () => 'You appear to be offline.',
  TIMEOUT: () => 'The check timed out.',
  LOOKUP_FAILED: () => 'The threat lookup failed.',
  SERVER_ERROR: () => 'FootprintX had a problem completing the check.',
  RATE_LIMITED: () => 'Too many checks right now; try again shortly.',
  DATASET_NOT_READY: () => 'The threat dataset is not loaded on the server yet.',
  DATASET_NOT_LOADED: () => 'The threat dataset is not loaded on the server yet.',
  DATASET_STALE: () => 'The threat dataset is out of date.',
  ENTITLEMENT_UNVERIFIED: () => 'Your subscription could not be confirmed.',
  CHECK_FAILED: () => 'The check could not be completed.',
};

export function reasonText(r) {
  if (r.message) return r.message;
  if (CODE_TEXT[r.code]) return CODE_TEXT[r.code](r);
  if (CODE_TEXT[r.errorCode]) return CODE_TEXT[r.errorCode](r);
  return r.code;
}
