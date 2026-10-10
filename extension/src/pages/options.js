import { el, send, ago } from './ui.js';

const $ = (id) => document.getElementById(id);

const ext = globalThis.browser ?? globalThis.chrome;

async function checkHostPermission(apiBase) {
  // Firefox can treat host permissions as optional; ask explicitly if missing.
  const origins = [`${new URL(apiBase).origin}/*`];
  if (!ext.permissions?.contains) return;
  const granted = await ext.permissions.contains({ origins });
  $('perm-card').hidden = granted;
  $('grant').onclick = async () => {
    if (await ext.permissions.request({ origins })) render();
  };
}

async function render() {
  const st = await send({ type: 'getOptionsState' });
  await checkHostPermission(st.apiBase);
  const ent = st.entitlement || {};
  $('server').textContent = `Connected to ${st.apiBase}`;
  const account = $('account');
  if (!ent.linked) {
    account.replaceChildren(el('p', {}, ent.revoked ? 'This browser was unlinked from your FootprintX account. Link it again to continue.' : 'This browser is not linked to a FootprintX account.'));
    $('link-form').hidden = false;
    $('code-help').hidden = false;
  } else {
    $('link-form').hidden = true;
    $('code-help').hidden = true;
    account.replaceChildren(
      el('p', {}, 'Linked to ', el('b', {}, ent.accountLabel || 'your account'), ent.unverified ? ' (could not reach FootprintX just now)' : ''),
      el('div', { class: 'row' },
        el('button', { onclick: () => globalThis.open(`${st.appUrl}/settings?tab=extension`, '_blank') }, 'Manage in FootprintX'),
        el('button', { class: 'danger', onclick: async () => { await send({ type: 'unlink' }); render(); } }, 'Unlink this browser'))
    );
  }

  const prot = $('protection');
  if (!ent.linked) prot.replaceChildren(el('p', {}, 'Link your account to see protection status.'));
  else if (ent.plan === 'premium') {
    prot.replaceChildren(el('p', {}, el('span', { class: 'pill premium' }, 'Premium'), ' Automatic checks are on for sites you open', ent.currentPeriodEnd ? ` (subscription period ends ${new Date(ent.currentPeriodEnd).toLocaleDateString()})` : '', '.'));
    if (!ent.datasetUsable) prot.append(el('div', { class: 'notice' }, 'The server’s threat dataset is not loaded or is out of date, so results will show “not enough information” rather than green.'));
  } else if (ent.plan === 'free') {
    prot.replaceChildren(el('p', {}, ent.state === 'expired' || ent.state === 'canceled' ? 'Your Premium subscription has ended, so automatic checks are paused. Everything else in FootprintX keeps working.' : 'Automatic checks of the sites you visit are part of FootprintX Premium. On Free you can still check the current site on demand from the toolbar button.'),
      el('button', { class: 'primary', onclick: () => globalThis.open(`${st.appUrl}/premium`, '_blank') }, 'About Premium'));
  } else {
    prot.replaceChildren(el('div', { class: 'notice' }, 'FootprintX could not confirm your subscription (offline or server unavailable). Protection status is unknown until it can.'));
  }
  $('paused').checked = !!st.settings.paused;
  $('interstitial').checked = !!st.settings.blockKnownThreats;
  $('notify').checked = !!st.settings.notifySuspicious;
  $('sync').checked = !!ent.syncEnabled;
  $('sync').disabled = !(ent.linked && ent.plan === 'premium');
  const synced = (st.events || []).filter((e) => e.synced).length;
  $('local-data').textContent = `${st.cachedSites} locally saved site results (clean results expire after six hours; known threats may remain for seven days) and ${(st.events || []).length} warning events${synced ? ` (${synced} shared with your dashboard)` : ''}.${st.events?.[0] ? ` Last warning ${ago(st.events[0].occurredAt)}.` : ''}`;
}

$('link-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('link-msg').textContent = 'Linking…';
  const r = await send({ type: 'link', code: $('code').value.trim() });
  $('link-msg').textContent = r.ok ? 'Linked.' : r.message || 'Linking failed.';
  if (r.ok) $('code').value = '';
  render();
});
$('interstitial').addEventListener('change', (e) => send({ type: 'setSettings', blockKnownThreats: e.target.checked }));
$('paused').addEventListener('change', (e) => send({ type: 'setSettings', paused: e.target.checked }));
$('notify').addEventListener('change', (e) => send({ type: 'setSettings', notifySuspicious: e.target.checked }));
$('sync').addEventListener('change', async (e) => {
  const r = await send({ type: 'setSync', enabled: e.target.checked });
  $('sync-msg').textContent = r.ok ? (e.target.checked ? 'Security events will be shared.' : 'Sharing turned off.') : r.message || 'Could not change this setting.';
  render();
});
$('clear').addEventListener('click', async () => {
  await send({ type: 'clearLocalData' });
  render();
});
render();
