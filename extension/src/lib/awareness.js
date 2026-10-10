import { normalizeHost } from '@footprintx/shared/domain';

export const unavailable = () => ({ state: 'unavailable', message: 'Account lookup unavailable.', login: { state: 'unavailable', message: 'Login status unavailable.' }, matches: [] });

// Short in-memory cache; never reuse another linked user's inventory.
export function createAwareness({ api, entitlement, paused, now = Date.now }) {
  let epoch = 0;
  const pending = new Map();
  const cache = new Map();
  return {
    clear() { epoch++; cache.clear(); pending.clear(); },
    async evaluate(url, { force = false } = {}) {
      const n = normalizeHost(url);
      if (!n || n.isLocal || n.isIp || await paused()) return unavailable();
      const ent = await entitlement().catch(() => null);
      if (!ent?.linked || ent.plan !== 'premium' || ent.unverified) return unavailable();
      const old = cache.get(n.hostname);
      if (!force && old && now() - old.at < 60000) return old.data;
      if (pending.has(n.hostname)) return pending.get(n.hostname);
      const generation = epoch;
      const p = api.awareness(n.hostname).then((res) => {
        if (generation !== epoch) return unavailable();
        const data = res.data;
        if (!res.ok || !['account_known','possible_association','no_match'].includes(data?.state) || data?.login?.state !== 'unavailable' || !Array.isArray(data.matches)) return unavailable();
        if (cache.size >= 100) cache.delete(cache.keys().next().value);
        cache.set(n.hostname, { at: now(), data });
        return data;
      }).catch(unavailable).finally(() => pending.delete(n.hostname));
      pending.set(n.hostname,p);
      return p;
    },
  };
}
