// Linked-account state and server-verified entitlement for the extension.
//
// Entitlement is never decided locally. The extension asks the server; the
// answer is cached for ENTITLEMENT_FRESH_MS to avoid a request per page.
// If the server can't be reached, a cached answer up to ENTITLEMENT_MAX_AGE_MS
// old is shown as "unverified"; Premium APIs are enforced server-side anyway,
// so editing local storage cannot unlock anything.
import { API_ERRORS } from './api.js';

export const ENTITLEMENT_FRESH_MS = 60 * 60e3;
export const ENTITLEMENT_MAX_AGE_MS = 24 * 60 * 60e3;

export function createAccount({ api, local, session, now = Date.now }) {
  let refreshing = null;

  async function token() {
    return (await local.get('fx_token')) || null;
  }

  async function refresh() {
    if (refreshing) return refreshing;
    refreshing = (async () => {
      if (!(await token())) {
        await session.set('fx_entitlement', null);
        return { linked: false };
      }
      const res = await api.status();
      if (res.ok) {
        const d = res.data;
        const ent = {
          linked: true,
          plan: d.entitlement.plan,
          state: d.entitlement.state,
          features: d.entitlement.features,
          currentPeriodEnd: d.entitlement.currentPeriodEnd,
          syncEnabled: !!d.session.syncEnabled,
          accountLabel: d.account.emailMasked,
          datasetVersion: d.dataset?.version || null,
          datasetUsable: !!d.dataset?.usable,
          datasetUpdatedAt: d.dataset?.updatedAt || null,
          verifiedAt: now(),
        };
        await session.set('fx_entitlement', ent);
        return ent;
      }
      if (res.errorCode === API_ERRORS.UNAUTHENTICATED) {
        // Token revoked or expired: forget it; the user must link again.
        await local.set('fx_token', null);
        await session.set('fx_entitlement', null);
        return { linked: false, revoked: true };
      }
      const cached = await session.get('fx_entitlement');
      if (cached && now() - cached.verifiedAt < ENTITLEMENT_MAX_AGE_MS) return { ...cached, unverified: true, lastError: res.errorCode };
      return { linked: true, plan: null, unverified: true, lastError: res.errorCode };
    })();
    try {
      return await refreshing;
    } finally {
      refreshing = null;
    }
  }

  async function get({ force = false } = {}) {
    if (!(await token())) return { linked: false };
    const cached = await session.get('fx_entitlement');
    if (!force && cached && now() - cached.verifiedAt < ENTITLEMENT_FRESH_MS) return cached;
    return refresh();
  }

  async function link(code, label) {
    const res = await api.link(code, label);
    if (!res.ok) return { ok: false, errorCode: res.errorCode, message: res.message || 'Linking failed.' };
    await local.set('fx_token', res.data.token);
    const ent = await refresh();
    return { ok: true, entitlement: ent };
  }

  async function unlink() {
    if (await token()) await api.unlink().catch(() => {});
    await local.set('fx_token', null);
    await session.set('fx_entitlement', null);
  }

  return { token, get, refresh, link, unlink, invalidate: () => session.set('fx_entitlement', null) };
}
