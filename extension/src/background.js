// FootprintX browser extension — background (service worker in Chromium,
// event page in Firefox). All listeners are registered synchronously at the
// top level so the browser can wake the worker for them.
//
// What this script reads: the URL of top-level navigations (to get the
// hostname). What it never reads: page content, form fields, passwords,
// cookies, or subresource requests. It has no content scripts.
import { createAwareness, unavailable } from './lib/awareness.js';
import { createApi } from './lib/api.js';
import { createAccount } from './lib/account.js';
import { createCache, createChecker } from './lib/checker.js';
import { createEventLog } from './lib/events.js';
import { toolbarFor } from './lib/toolbar.js';
import { REPUTATION_STATUS as S } from '@footprintx/shared/threat';
import { normalizeHost } from '@footprintx/shared/domain';

const API_BASE = __FX_API_BASE__;
const APP_URL = __FX_APP_URL__;
const ext = globalThis.browser ?? globalThis.chrome;
const EXT_ORIGIN = ext.runtime.getURL('');

const wrap = (area) => ({
  get: async (k) => (await area.get(k))[k],
  set: (k, v) => area.set({ [k]: v }),
  remove: (k) => area.remove(k),
});
const local = wrap(ext.storage.local);
const session = wrap(ext.storage.session || ext.storage.local);

const api = createApi({ baseUrl: API_BASE, getToken: () => local.get('fx_token') });
const account = createAccount({ api, local, session });
const cache = createCache(local);
const events = createEventLog({ local, api });
const settings = async () => ({ paused: false, notifySuspicious: true, blockKnownThreats: false, ...((await local.get('fx_settings')) || {}) });
const checker = createChecker({
  api,
  cache,
  getEntitlement: () => account.get(),
  isPaused: async () => (await settings()).paused,
  apiHost: normalizeHost(API_BASE)?.hostname,
  onAuthProblem: () => account.refresh(),
});

const awareness = createAwareness({ api, entitlement: () => account.get(), paused: async () => (await settings()).paused });

// ---- Toolbar ------------------------------------------------------------------------
// Paints are serialised per tab and always apply the *latest* desired state,
// so an older "checking…" paint can never overwrite a newer verdict.
const desiredPaint = new Map();
const paintChain = new Map();
function paintToolbar(tabId, state) {
  desiredPaint.set(tabId, state);
  const run = (paintChain.get(tabId) || Promise.resolve()).then(() => applyPaint(tabId));
  paintChain.set(tabId, run.catch(() => {}));
  return run.catch(() => {});
}
async function applyPaint(tabId) {
  const state = desiredPaint.get(tabId);
  if (!state) return;
  const t = toolbarFor(state);
  try {
    await ext.action.setIcon({ tabId, path: t.iconPaths });
    await ext.action.setBadgeText({ tabId, text: t.badge });
    if (t.badge) await ext.action.setBadgeBackgroundColor({ tabId, color: t.badgeColor });
    await ext.action.setTitle({ tabId, title: t.title });
  } catch {
    /* tab closed */
  }
}

// ---- Per-tab state (session storage survives worker restarts) ---------------------------
const tabKey = (id) => `tab:${id}`;
const navSeq = new Map();
const lastWarning = new Map(); // tabId -> { hostname, at }: suppresses the duplicate commit event of one navigation until the warning page loads

async function handleNavigation(tabId, url) {
  if (tabId < 0 || !url) return;
  if (url.startsWith(EXT_ORIGIN)) {
    // Browsers reset per-tab toolbar state on navigation; keep showing the
    // verdict while our own warning page is displayed in the tab.
    const s = await session.get(tabKey(tabId));
    if (s) await paintToolbar(tabId, s);
    return;
  }
  const seq = (navSeq.get(tabId) || 0) + 1;
  navSeq.set(tabId, seq);
  const n = normalizeHost(url);
  const prev = (await session.get(tabKey(tabId))) || {};
  if (n && !n.isLocal) await paintToolbar(tabId, { status: S.PENDING, hostname: n.hostname });
  const accountResult = awareness.evaluate(url);
  const result = await checker.evaluate(url);
  if (navSeq.get(tabId) !== seq) return; // user navigated again meanwhile
  const state = { ...result, lastSafeUrl: prev.lastSafeUrl || null };
  const bypassed = n && (await isBypassed(n.hostname));
  if (result.status === S.NO_KNOWN_THREAT && /^https?:/.test(url)) state.lastSafeUrl = new URL(url).origin;
  await session.set(tabKey(tabId), state);
  await paintToolbar(tabId, state);
  accountResult.then(async (association) => {
    if (navSeq.get(tabId) !== seq) return;
    const latest = await session.get(tabKey(tabId));
    if (navSeq.get(tabId) === seq && latest?.hostname === result.hostname) await session.set(tabKey(tabId), { ...latest, association });
  }).catch(() => {});
  const ent = await account.get();

  const recentWarn = lastWarning.get(tabId);
  const alreadyWarned = recentWarn && recentWarn.hostname === result.hostname && Date.now() - recentWarn.at < 10e3;
  if (result.status === S.MALICIOUS && !bypassed && !alreadyWarned) {
    lastWarning.set(tabId, { hostname: result.hostname, at: Date.now() });
    const id = crypto.randomUUID();
    const interstitial = (await settings()).blockKnownThreats;
    if (interstitial) await session.set(`warn:${id}`, { tabId, url: new URL(url).origin, result, createdAt: Date.now(), lastSafeUrl: prev.lastSafeUrl || null });
    await events.record({ type: 'malicious_site_blocked', hostname: result.hostname, status: 'malicious', reasonCodes: result.reasons.map((r) => r.code), datasetVersion: result.datasetVersion }, { sync: !!ent.syncEnabled });
    if (interstitial) await ext.tabs.update(tabId, { url: ext.runtime.getURL(`warning.html#${id}`) });
    else ext.notifications?.create(`mal:${tabId}:${Date.now()}`, { type: 'basic', iconUrl: ext.runtime.getURL('icons/red-128.png'), title: 'FootprintX: known threat detected', message: `${result.hostname}: avoid sensitive interactions and leave this site. Open FootprintX for details.` }).catch(() => {});
    events.flush({ syncEnabled: !!ent.syncEnabled }).catch(() => {});
  } else if (result.status === S.SUSPICIOUS && !bypassed) {
    const key = `notified:${result.hostname}`;
    if (!(await session.get(key))) {
      await session.set(key, Date.now());
      await events.record({ type: 'suspicious_site_warned', hostname: result.hostname, status: 'suspicious', reasonCodes: result.reasons.map((r) => r.code), datasetVersion: result.datasetVersion }, { sync: !!ent.syncEnabled });
      if ((await settings()).notifySuspicious && ext.notifications) {
        ext.notifications.create(`sus:${tabId}:${Date.now()}`, {
          type: 'basic',
          iconUrl: ext.runtime.getURL('icons/amber-128.png'),
          title: 'FootprintX: be careful on this site',
          message: `${result.displayHost || result.hostname}: ${result.reasons[0]?.message || 'Suspicious indicators found.'} Open the FootprintX toolbar button for details.`,
          priority: 1,
        });
      }
      events.flush({ syncEnabled: !!ent.syncEnabled }).catch(() => {});
    }
  }
}

async function isBypassed(hostname) {
  const until = await session.get(`bypass:${hostname}`);
  return !!until && until > Date.now();
}

ext.webNavigation.onBeforeNavigate.addListener((d) => {
  if (d.frameId === 0) handleNavigation(d.tabId, d.url).catch(() => {});
});
ext.webNavigation.onCommitted.addListener((d) => {
  if (d.frameId === 0) handleNavigation(d.tabId, d.url).catch(() => {});
});
ext.webNavigation.onHistoryStateUpdated.addListener((d) => {
  if (d.frameId === 0) handleNavigation(d.tabId, d.url).catch(() => {});
});
ext.tabs.onActivated.addListener(async ({ tabId }) => {
  const s = await session.get(tabKey(tabId));
  if (s) paintToolbar(tabId, s);
});
ext.tabs.onRemoved.addListener((tabId) => {
  navSeq.delete(tabId);
  desiredPaint.delete(tabId);
  paintChain.delete(tabId);
  session.remove(tabKey(tabId));
});

// ---- Periodic refresh: entitlement, dataset updates, event sync, cache hygiene ---------------
ext.alarms.create('fx-refresh', { periodInMinutes: 30 });
ext.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== 'fx-refresh') return;
  await periodicRefresh().catch(() => {});
});

async function periodicRefresh() {
  const ent = await account.refresh();
  if (ent.linked && ent.plan === 'premium' && ent.datasetVersion) {
    const seen = await local.get('fx_dataset_version');
    if (seen && seen !== ent.datasetVersion) {
      await cache.markDatasetChanged(ent.datasetVersion);
      for (const esc of await checker.recheckCached()) {
        await events.record({ type: 'cached_result_escalated', hostname: esc.hostname, status: esc.after.status, reasonCodes: esc.after.reasons.map((r) => r.code), datasetVersion: ent.datasetVersion }, { sync: !!ent.syncEnabled });
        ext.notifications?.create(`esc:${esc.hostname}`, {
          type: 'basic',
          iconUrl: ext.runtime.getURL(`icons/${esc.after.status === S.MALICIOUS ? 'red' : 'amber'}-128.png`),
          title: 'FootprintX: a site you visited is now flagged',
          message: `${esc.hostname} is now ${esc.after.status === S.MALICIOUS ? 'listed as a known threat' : 'showing suspicious indicators'}. If you entered a password there, change it on the real site.`,
        });
      }
    }
    await local.set('fx_dataset_version', ent.datasetVersion);
  }
  await events.flush({ syncEnabled: !!ent.syncEnabled });
  await cache.purgeExpired();
}

ext.runtime.onInstalled.addListener((details) => {
  if (details.reason === 'install') ext.runtime.openOptionsPage();
});

ext.notifications?.onClicked.addListener((id) => {
  const tabId = Number(id.split(':')[1]);
  if (Number.isInteger(tabId)) ext.tabs.update(tabId, { active: true }).catch(() => {});
});

// ---- Messages from the extension's own pages (popup, options, warning) ---------------------
const HANDLERS = {
  async getPopupState({ tabId }) {
    const [tab, ent, s, recent] = await Promise.all([session.get(tabKey(tabId)), account.get(), settings(), events.list()]);
    const association = tab?.hostname ? await awareness.evaluate(tab.hostname, { force: true }) : unavailable();
    return { tab: tab ? { ...tab, association } : null, entitlement: ent, settings: s, apiBase: API_BASE, appUrl: APP_URL, recentEvents: recent.slice(0, 5) };
  },
  async recheckTab({ tabId }) {
    // Uses the hostname recorded from navigation; the extension does not need the "tabs" permission.
    const prev = (await session.get(tabKey(tabId))) || {};
    if (!prev.hostname) return { ok: false };
    const result = await checker.evaluate(`https://${prev.hostname}/`, { force: true });
    await session.set(tabKey(tabId), { ...prev, ...result });
    await paintToolbar(tabId, result);
    return result;
  },
  async manualCheck({ tabId }) {
    // User-initiated single check (available on Free). Sends this one hostname, as disclosed in the popup.
    const prev = (await session.get(tabKey(tabId))) || {};
    const n = prev.hostname ? normalizeHost(prev.hostname) : null;
    if (!n || n.isLocal) return { ok: false, message: 'This page cannot be checked.' };
    const res = await api.manualCheck(n.hostname);
    if (!res.ok) return { ok: false, errorCode: res.errorCode, message: res.message || 'The check could not be completed. This is not a clean result.' };
    const state = { status: res.data.status, hostname: n.hostname, displayHost: res.data.displayDomain, reasons: res.data.reasons, checkedAt: Date.now(), source: 'manual', datasetUpdatedAt: res.data.dataset?.updatedAt || null };
    await session.set(tabKey(tabId), { ...state, lastSafeUrl: prev.lastSafeUrl || null });
    await paintToolbar(tabId, state);
    return { ok: true, result: state };
  },
  async getOptionsState() {
    const [ent, s, recent, cacheEntries] = await Promise.all([account.get({ force: true }), settings(), events.list(), cache.entries()]);
    return { entitlement: ent, settings: s, apiBase: API_BASE, appUrl: APP_URL, events: recent, cachedSites: cacheEntries.length };
  },
  async link({ code }) {
    if (typeof code !== 'string' || code.length > 20) return { ok: false, message: 'Enter the 8-character code from FootprintX.' };
    const label = `${navigator.userAgent.includes('Firefox') ? 'Firefox' : navigator.userAgent.includes('Edg/') ? 'Edge' : 'Chromium'} browser`;
    awareness.clear();
    await events.clear();
    await cache.clear();
    await ext.storage.session?.clear();
    return account.link(code, label);
  },
  async unlink() {
    awareness.clear();
    await account.unlink();
    await events.clear();
    await ext.storage.session?.clear();
    await cache.clear();
    return { ok: true };
  },
  async setSync({ enabled }) {
    const res = await api.setSync(!!enabled);
    await account.refresh();
    if (!enabled) await events.flush({ syncEnabled: false });
    return res.ok ? { ok: true } : { ok: false, errorCode: res.errorCode, message: res.message };
  },
  async setSettings({ paused, notifySuspicious, blockKnownThreats }) {
    const s = await settings();
    if (typeof blockKnownThreats === 'boolean') s.blockKnownThreats = blockKnownThreats;
    if (typeof paused === 'boolean') { s.paused = paused; awareness.clear(); }
    if (typeof notifySuspicious === 'boolean') s.notifySuspicious = notifySuspicious;
    await local.set('fx_settings', s);
    return { ok: true, settings: s };
  },
  async clearLocalData() {
    awareness.clear();
    await ext.storage.session?.clear();
    await cache.clear();
    await events.clear();
    return { ok: true };
  },
  async getWarning({ id }) {
    const w = (await session.get(`warn:${id}`)) || null;
    // The warning page is showing: later navigations to the site must warn again.
    if (w) lastWarning.delete(w.tabId);
    return w;
  },
  async warningAction({ id, action, note }) {
    const w = await session.get(`warn:${id}`);
    if (!w) return { ok: false };
    if (action === 'leave') {
      await ext.tabs.update(w.tabId, { url: w.lastSafeUrl || ext.runtime.getURL('left.html') });
      return { ok: true };
    }
    if (action === 'proceed') {
      await session.set(`bypass:${w.result.hostname}`, Date.now() + 60 * 60e3);
      await ext.tabs.update(w.tabId, { url: w.url });
      return { ok: true };
    }
    if (action === 'report') {
      const res = await api.reportFalsePositive(w.result.hostname, 'malicious', typeof note === 'string' ? note.slice(0, 500) : undefined);
      return { ok: res.ok, message: res.ok ? res.data.message : 'The report could not be sent. Are you linked and online?' };
    }
    return { ok: false };
  },
};

ext.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Only our own extension pages may talk to the background; web pages cannot.
  if (sender.id !== ext.runtime.id || !String(sender.url || '').startsWith(EXT_ORIGIN)) return false;
  const handler = msg && typeof msg.type === 'string' && Object.hasOwn(HANDLERS, msg.type) ? HANDLERS[msg.type] : null;
  if (!handler) return false;
  handler(msg)
    .then(sendResponse)
    .catch(() => sendResponse({ ok: false, message: 'Something went wrong.' }));
  return true;
});
