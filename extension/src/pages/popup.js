import { STATUS_EXPLANATION, TOOLBAR, REPUTATION_STATUS as S } from '@footprintx/shared/threat';
import { NOT_CHECKED_REASONS } from '../lib/checker.js';
import { el, send, reasonText, ago } from './ui.js';

const ext = globalThis.browser ?? globalThis.chrome;
const GLYPH = { red: '!', amber: '?', green: '✓', grey: '–' };

async function render() {
  const [tab] = await ext.tabs.query({ active: true, currentWindow: true });
  const st = await send({ type: 'getPopupState', tabId: tab.id });
  const ent = st.entitlement || {};
  const plan = document.getElementById('plan');
  plan.textContent = !ent.linked ? 'Not linked' : ent.plan === 'premium' ? 'Premium' : ent.plan === 'free' ? 'Free' : 'Unverified';
  plan.className = `pill ${ent.plan === 'premium' ? 'premium' : ''}`;

  const state = st.tab || { status: S.NOT_CHECKED, reasons: [] };
  const association = state.association;
  document.getElementById('association').textContent = association?.message || 'Account lookup unavailable.';
  document.getElementById('login-state').textContent = association?.login?.message || 'Login status unavailable.';
  document.getElementById('account-matches').replaceChildren(...(association?.matches || []).map((a) => el('li', {}, `${a.serviceName}: ${a.association}, ${a.confidence} confidence; source ${a.sourceStatus}; ${a.accountState}`)));
  const t = TOOLBAR[state.status] || TOOLBAR[S.NOT_CHECKED];
  document.getElementById('status').className = `status ${t.color}`;
  document.getElementById('glyph').textContent = GLYPH[t.color];
  let label = t.label;
  if (state.status === S.NOT_CHECKED && state.reasons?.[0]?.code === 'PREMIUM_REQUIRED') label = 'Active protection is off';
  document.getElementById('label').textContent = label;
  document.getElementById('domain').textContent = state.displayHost || state.hostname || '';
  const explanation = state.status === S.NOT_CHECKED ? NOT_CHECKED_REASONS[state.reasons?.[0]?.code] || STATUS_EXPLANATION.not_checked : STATUS_EXPLANATION[state.status];
  document.getElementById('explanation').textContent = explanation || '';
  const reasons = document.getElementById('reasons');
  reasons.replaceChildren(...(state.status === S.NOT_CHECKED ? [] : (state.reasons || []).map((r) => el('li', {}, reasonText(r)))));
  const meta = [];
  if (state.checkedAt && state.status !== S.NOT_CHECKED) meta.push(`Checked ${ago(state.checkedAt)}${state.source === 'cache' ? ' (saved result)' : state.source === 'manual' ? ' (one-off check)' : ''}`);
  if (state.datasetUpdatedAt) meta.push(`threat data updated ${ago(state.datasetUpdatedAt)}`);
  if (ent.unverified) meta.push('Could not reach FootprintX to confirm your plan');
  document.getElementById('meta').textContent = meta.join(' · ');

  const actions = document.getElementById('actions');
  const buttons = [];
  if (!ent.linked) {
    buttons.push(el('button', { class: 'primary', onclick: () => ext.runtime.openOptionsPage() }, 'Link your FootprintX account'));
  } else if (ent.plan !== 'premium') {
    buttons.push(el('button', { class: 'primary', onclick: () => ext.tabs.create({ url: `${st.appUrl}/premium` }) }, 'About Premium protection'));
    if (state.hostname) {
      buttons.push(
        el('button', {
          title: 'Sends this site’s domain name to FootprintX for a one-time check.',
          onclick: async (e) => {
            e.target.disabled = true;
            e.target.textContent = 'Checking…';
            const r = await send({ type: 'manualCheck', tabId: tab.id });
            if (!r.ok) document.getElementById('meta').textContent = r.message;
            render();
          },
        }, 'Check this site once')
      );
    }
  } else if (state.hostname) {
    buttons.push(el('button', { onclick: async (e) => { e.target.disabled = true; await send({ type: 'recheckTab', tabId: tab.id }); render(); } }, 'Re-check'));
  }
  buttons.push(el('button', { onclick: () => ext.tabs.create({ url: `${st.appUrl}/dashboard` }) }, 'Dashboard'));
  buttons.push(el('button', { onclick: () => ext.runtime.openOptionsPage() }, 'Settings'));
  actions.replaceChildren(...buttons);

  const recent = (st.recentEvents || []).filter((e) => e.status === 'malicious' || e.status === 'suspicious');
  document.getElementById('recent-card').hidden = !recent.length;
  document.getElementById('recent').replaceChildren(...recent.map((e) => el('li', {}, `${e.domain} — ${e.status === 'malicious' ? 'known threat' : 'suspicious'} · ${ago(e.occurredAt)}`)));
}

render().catch(() => {
  document.getElementById('label').textContent = 'Something went wrong';
});
