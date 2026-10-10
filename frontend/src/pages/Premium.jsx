import { Shell, PageHeader, Loading, ErrorNote, Note, Tag, useToast } from '../components.jsx';
import { api } from '../lib/api.js';
import { useAction, useResource } from '../lib/hooks.js';
import { useAuth } from '../lib/auth.jsx';
import { formatDate } from '../lib/labels.js';

const ROWS = [
  ['Connect multiple mailboxes and rescan any time', true, true],
  ['Account inventory with evidence', true, true],
  ['Breach checks (with your consent)', true, true],
  ['Risk score, explanations and recommendations', true, true],
  ['Remediation tracking and independent confirmation', true, true],
  ['In-app alerts and optional email alerts', true, true],
  ['Check a website on demand', true, true],
  ['Browser extension: automatic checks of sites you open', false, true],
  ['Warnings for known threat and look-alike sites', false, true],
  ['Alerts when new threat data affects sites you visited', false, true],
  ['Optional sync of warnings to your dashboard', false, true],
  ['Security history', '30 days', '1 year'],
];

export function Premium() {
  const auth = useAuth();
  const { data, error, loading, reload } = useResource('/billing');
  const { toast, show } = useToast();
  const act = useAction(async (path, message) => {
    const r = await api.post(path, {});
    await reload({ quiet: true });
    await auth.refresh();
    show(r.notice || message);
  });
  if (loading) return <Shell><Loading /></Shell>;
  if (error) return <Shell><ErrorNote error={error} onRetry={reload} /></Shell>;
  const { catalog: c, entitlement: e } = data;
  const sub = e.subscription;
  return (
    <Shell>
      {toast}
      <PageHeader title="Plans" intro="Free helps you understand and reduce the risk you already have. Premium adds protection while you browse." />
      <div className="table-wrap">
        <table className="table compare">
          <caption className="sr-only">Free and Premium features</caption>
          <thead><tr><th scope="col">Feature</th><th scope="col">Free</th><th scope="col">Premium{' '}<span className="price-inline">{c.premium.display}</span></th></tr></thead>
          <tbody>
            {ROWS.map(([f, free, prem]) => (
              <tr key={f}><th scope="row">{f}</th><td>{free === true ? 'Included' : free === false ? <span className="muted">Not included</span> : free}</td><td>{prem === true ? 'Included' : prem}</td></tr>
            ))}
          </tbody>
        </table>
      </div>
      {c.premium.priceStatus === 'proposed' && <p className="small">The Premium price shown is proposed and may change before launch.</p>}

      <section className="section" aria-labelledby="your-h">
        <h2 id="your-h">Your plan</h2>
        <p>
          <Tag tone={e.plan === 'premium' ? 'good' : 'neutral'}>{e.plan === 'premium' ? 'Premium' : 'Free'}</Tag>{' '}
          {e.state === 'canceling' && `Cancelled — Premium continues until ${formatDate(sub.currentPeriodEnd)}.`}
          {(e.state === 'active' || e.state === 'trialing') && `Renews or ends on ${formatDate(sub.currentPeriodEnd)}.`}
          {e.state === 'past_due_grace' && 'Payment is overdue; Premium continues for a short grace period.'}
          {(e.state === 'expired' || e.state === 'canceled') && 'Your Premium subscription has ended. Your data and Free features are unchanged.'}
        </p>
        {sub?.isDevelopment && <Note tone="warn" title="Development subscription"><p>This Premium access was granted by the development test checkout. No payment was taken.</p></Note>}
        {e.plan !== 'premium' && (
          c.checkoutAvailable ? (
            <>
              <Note tone="warn" title="Test checkout"><p>{c.developmentNotice}</p></Note>
              <button className="btn primary" onClick={() => act.run('/billing/dev-checkout', 'Premium is active (development, no payment).')} disabled={act.busy}>Start Premium (test, no payment)</button>
            </>
          ) : (
            <Note tone="info" title="Premium isn’t available to buy yet"><p>Online payment hasn’t been set up on this server. Nothing will be charged.</p></Note>
          )
        )}
        {e.state === 'canceling' && <button className="btn" onClick={() => act.run('/billing/resume', 'Premium will continue.')} disabled={act.busy}>Keep Premium</button>}
        {(e.state === 'active' || e.state === 'trialing') && sub?.provider === 'development' && (
          <div className="row-actions">
            <button className="btn ghost" onClick={() => act.run('/billing/cancel', 'Cancelled. Premium continues until the end of the period.')} disabled={act.busy}>Cancel Premium</button>
            <button className="btn ghost small" onClick={() => act.run('/billing/dev-expire', 'Premium ended (development test).')} disabled={act.busy}>End now (test downgrade)</button>
          </div>
        )}
        <ErrorNote error={act.error} />
        <p className="small">If Premium ends, nothing is deleted: your accounts, history and settings stay, and the browser extension pauses automatic checks.</p>
      </section>
      <section className="section">
        <h2>What Premium can’t promise</h2>
        <ul className="checklist muted-list">
          <li>It only works while the extension is installed, enabled and online, in a supported browser (Chrome, Edge or Firefox).</li>
          <li>It knows about threats that are on its threat list or look like well-known brands. New or unlisted malicious sites can get through.</li>
          <li>A green result means no known threat was found — not that a site is guaranteed safe.</li>
        </ul>
      </section>
    </Shell>
  );
}
