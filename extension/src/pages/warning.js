import { el, send, reasonText, ago } from './ui.js';

const $ = (id) => document.getElementById(id);
// The warning id comes from our own redirect; details are fetched from the
// background, never trusted from the URL itself.
const id = location.hash.slice(1);

async function init() {
  const w = /^[0-9a-f-]{36}$/.test(id) ? await send({ type: 'getWarning', id }) : null;
  if (!w) {
    $('title').textContent = 'This warning has expired';
    $('why').textContent = 'Open the site again to re-check it.';
    $('more').remove();
    $('details-toggle').remove();
    $('leave').remove();
    return;
  }
  const r = w.result;
  $('domain').textContent = r.displayHost || r.hostname;
  $('why').textContent = 'FootprintX stopped this page because its address matches a threat-intelligence listing:';
  $('reasons').replaceChildren(...r.reasons.map((x) => el('li', {}, reasonText(x))));
  $('meta').textContent = `Checked ${ago(r.checkedAt)}${r.datasetUpdatedAt ? ` · threat data updated ${ago(r.datasetUpdatedAt)}` : ''}${r.source === 'stale_cache' ? ' · saved result (could not re-check)' : ''}`;
  $('leave').addEventListener('click', () => send({ type: 'warningAction', id, action: 'leave' }));
  $('details-toggle').addEventListener('click', (e) => {
    const more = $('more');
    more.hidden = !more.hidden;
    e.target.setAttribute('aria-expanded', String(!more.hidden));
  });
  $('proceed').addEventListener('click', () => send({ type: 'warningAction', id, action: 'proceed' }));
  $('report').addEventListener('click', async (e) => {
    e.target.disabled = true;
    const res = await send({ type: 'warningAction', id, action: 'report' });
    $('report-msg').textContent = res.message || (res.ok ? 'Reported.' : 'Could not send the report.');
  });
  $('leave').focus();
}
init();
