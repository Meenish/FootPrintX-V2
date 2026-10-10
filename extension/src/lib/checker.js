// Core site-check logic, independent of browser APIs (unit-tested in Node).
//
// Privacy: the hostname never leaves the device. Only 32-bit SHA-256 prefixes
// of the hostname and its parent domains are sent; the full hashes returned
// by the server are compared locally. Paths, queries, page content, cookies
// and form data are never read.
import { normalizeHost, buildHashLookup } from '@footprintx/shared/domain';
import { analyzeLookalike } from '@footprintx/shared/lookalike';
import { combineVerdict, REPUTATION_STATUS as S } from '@footprintx/shared/threat';
import { API_ERRORS } from './api.js';

const MIN = 60e3;
export const CACHE_TTL_MS = Object.freeze({ [S.MALICIOUS]: 24 * 60 * MIN, [S.SUSPICIOUS]: 6 * 60 * MIN, [S.NO_KNOWN_THREAT]: 6 * 60 * MIN, [S.UNKNOWN]: 10 * MIN });
export const CACHE_MAX_ENTRIES = 300;
const STALE_MALICIOUS_MAX_MS = 7 * 24 * 60 * MIN;

export const NOT_CHECKED_REASONS = Object.freeze({
  UNSUPPORTED_PAGE: 'This kind of page is not checked.',
  LOCAL_PAGE: 'Local and private-network pages are not checked.',
  FOOTPRINTX: 'This is FootprintX itself.',
  NOT_LINKED: 'Link the extension to your FootprintX account to turn on protection.',
  PREMIUM_REQUIRED: 'Automatic site checks are part of FootprintX Premium.',
  PREMIUM_EXPIRED: 'Your Premium subscription has ended, so automatic checks are paused.',
  PROTECTION_PAUSED: 'You paused protection in the extension settings.',
});

/** LRU-ish cache persisted through a minimal async store ({ get, set }). */
export function createCache(store, { now = Date.now, max = CACHE_MAX_ENTRIES } = {}) {
  let mem = null;
  const load = async () => {
    if (!mem) mem = (await store.get('fx_cache')) || {};
    return mem;
  };
  const save = () => store.set('fx_cache', mem);
  return {
    async get(hostname) {
      const c = await load();
      return c[hostname] || null;
    },
    async fresh(hostname) {
      const e = (await load())[hostname];
      if (!e || e.needsRecheck) return null;
      const ttl = CACHE_TTL_MS[e.status];
      return ttl && now() - e.checkedAt < ttl ? e : null;
    },
    async put(hostname, entry) {
      const c = await load();
      c[hostname] = entry;
      const keys = Object.keys(c);
      if (keys.length > max) {
        keys.sort((a, b) => c[a].checkedAt - c[b].checkedAt).slice(0, keys.length - max).forEach((k) => delete c[k]);
      }
      await save();
    },
    async entries() {
      return Object.entries(await load());
    },
    async purgeExpired() {
      const c = await load();
      for (const [k, e] of Object.entries(c)) if (now() - e.checkedAt > Math.max(CACHE_TTL_MS[e.status] || 0, e.status === S.MALICIOUS ? STALE_MALICIOUS_MAX_MS : 0)) delete c[k];
      await save();
    },
    async markDatasetChanged(version) {
      const c = await load();
      let n = 0;
      for (const e of Object.values(c)) {
        if (e.datasetVersion !== version && (e.status === S.NO_KNOWN_THREAT || e.status === S.SUSPICIOUS)) {
          e.needsRecheck = true;
          n += 1;
        }
      }
      await save();
      return n;
    },
    async clear() {
      mem = {};
      await save();
    },
  };
}

/**
 * @param deps.api          createApi() instance
 * @param deps.cache        createCache() instance
 * @param deps.getEntitlement async () => { linked, plan, state, datasetVersion }
 * @param deps.isPaused     async () => boolean
 * @param deps.apiHost      hostname of the FootprintX API (never checked)
 */
export function createChecker({ api, cache, getEntitlement, isPaused = async () => false, apiHost = null, now = Date.now, onAuthProblem = () => {} }) {
  const inflight = new Map();

  function notChecked(hostname, reason, extra = {}) {
    return { status: S.NOT_CHECKED, hostname, reasons: [{ code: reason, message: NOT_CHECKED_REASONS[reason] }], checkedAt: now(), source: 'none', ...extra };
  }

  async function lookupLive(n) {
    const heuristics = analyzeLookalike(n.hostname);
    const entries = await buildHashLookup(n.hostname);
    const res = await api.lookup(entries.map((e) => e.prefix));
    if (!res.ok) {
      if (res.errorCode === API_ERRORS.UNAUTHENTICATED || res.errorCode === API_ERRORS.PREMIUM_REQUIRED || res.errorCode === API_ERRORS.PREMIUM_EXPIRED) {
        onAuthProblem(res.errorCode);
        return notChecked(n.hostname, res.errorCode === API_ERRORS.UNAUTHENTICATED ? 'NOT_LINKED' : res.errorCode);
      }
      const verdict = combineVerdict({ lookup: { ok: false, errorCode: res.errorCode }, heuristics });
      // A previously confirmed threat stays a threat while we are offline.
      const prior = await cache.get(n.hostname);
      if (prior && prior.status === S.MALICIOUS && now() - prior.checkedAt < STALE_MALICIOUS_MAX_MS) {
        return { ...prior, source: 'stale_cache', staleMinutes: Math.round((now() - prior.checkedAt) / MIN), reasons: [...prior.reasons, { code: 'USING_CACHED_RESULT', errorCode: res.errorCode }] };
      }
      return { status: verdict.status, hostname: n.hostname, displayHost: n.unicodeHostname, reasons: verdict.reasons, checkedAt: now(), source: 'live', errorCode: res.errorCode };
    }
    const byHash = new Map(entries.map((e) => [e.fullHash, e.candidate]));
    const matches = (res.data.matches || [])
      .filter((m) => byHash.has(m.fullHash))
      .map((m) => ({ matchedHost: byHash.get(m.fullHash), matchType: byHash.get(m.fullHash) === n.hostname ? 'exact' : 'parent_domain', source: m.source, sourceLabel: m.sourceLabel, threatType: m.threatType, firstSeenAt: m.firstSeenAt, lastSeenAt: m.lastSeenAt }));
    const ds = res.data.dataset || {};
    const verdict = combineVerdict({ lookup: { ok: true, matches, datasetUsable: !!ds.usable, datasetReason: ds.reason }, heuristics });
    const result = { status: verdict.status, hostname: n.hostname, displayHost: n.unicodeHostname, reasons: verdict.reasons, checkedAt: now(), source: 'live', datasetVersion: ds.version || null, datasetUpdatedAt: ds.updatedAt || null };
    if (CACHE_TTL_MS[result.status]) await cache.put(n.hostname, { ...result, source: 'cache' });
    return result;
  }

  /** Evaluates a URL (only its hostname is used). Never throws. */
  async function evaluate(url, { force = false } = {}) {
    const n = normalizeHost(url);
    if (!n) return notChecked(null, 'UNSUPPORTED_PAGE');
    if (n.isLocal) return notChecked(n.hostname, 'LOCAL_PAGE');
    if (apiHost && (n.hostname === apiHost || n.hostname.endsWith(`.${apiHost}`))) return notChecked(n.hostname, 'FOOTPRINTX');
    if (await isPaused()) return notChecked(n.hostname, 'PROTECTION_PAUSED');
    let ent;
    try {
      ent = await getEntitlement();
    } catch {
      ent = null;
    }
    if (!ent || !ent.linked) return notChecked(n.hostname, 'NOT_LINKED');
    if (ent.unverified && !ent.plan) return { status: S.UNAVAILABLE, hostname: n.hostname, reasons: [{ code: 'ENTITLEMENT_UNVERIFIED' }], checkedAt: now(), source: 'none' };
    if (ent.plan !== 'premium') return notChecked(n.hostname, ent.state === 'expired' || ent.state === 'canceled' ? 'PREMIUM_EXPIRED' : 'PREMIUM_REQUIRED');

    const cached = force ? null : await cache.fresh(n.hostname);
    if (cached) return { ...cached, source: 'cache' };
    if (inflight.has(n.hostname)) return inflight.get(n.hostname);
    const p = lookupLive(n)
      .catch(() => ({ status: S.UNAVAILABLE, hostname: n.hostname, reasons: [{ code: 'CHECK_FAILED' }], checkedAt: now(), source: 'live' }))
      .finally(() => inflight.delete(n.hostname));
    inflight.set(n.hostname, p);
    return p;
  }

  /**
   * Re-checks cached clean/suspicious results after the threat dataset
   * changes. Returns the entries whose status got worse.
   */
  async function recheckCached(limit = 50) {
    const escalations = [];
    const stale = (await cache.entries()).filter(([, e]) => e.needsRecheck).slice(0, limit);
    for (const [host, before] of stale) {
      const after = await lookupLive(normalizeHost(host));
      if (after.status === S.NOT_CHECKED || after.status === S.UNAVAILABLE) break;
      const rank = { [S.NO_KNOWN_THREAT]: 0, [S.UNKNOWN]: 0, [S.SUSPICIOUS]: 1, [S.MALICIOUS]: 2 };
      if ((rank[after.status] ?? 0) > (rank[before.status] ?? 0)) escalations.push({ hostname: host, before: before.status, after });
    }
    return escalations;
  }

  return { evaluate, recheckCached, inflightCount: () => inflight.size };
}
