import { useMemo, useState } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { Shell, PageHeader, Tag, Loading, ErrorNote, Empty, Time, Note, ExternalLink, ConfirmDialog, useToast } from '../components.jsx';
import { api, download } from '../lib/api.js';
import { useAction, useResource } from '../lib/hooks.js';
import {
  ACCOUNT_STATUS, DISCOVERY_SOURCE, CONFIDENCE, MFA, MFA_SOURCE, EXPOSURE, ACCOUNT_STATE, RISK_LEVEL, EVIDENCE_KIND, AUTH_RESULT, FACTOR, REMEDIATION, SEVERITY, formatDate,
} from '../lib/labels.js';

const FILTERS = [
  ['all', 'All'],
  ['attention', 'Needs attention'],
  ['breached', 'In a breach'],
  ['mfa_unknown', 'MFA unknown'],
  ['manual', 'Added by you'],
];
const SORTS = { risk: 'Risk (highest first)', name: 'Name', recent: 'Recently seen', oldest: 'Oldest first' };

function RiskCell({ a }) {
  if (a.status !== 'confirmed') return <span className="muted">Not scored</span>;
  if (a.account_state !== 'unknown') return <Tag tone="unknown">{ACCOUNT_STATE[a.account_state]}</Tag>;
  if (a.risk_score == null) return <span className="muted">Pending</span>;
  const lvl = RISK_LEVEL[a.risk_level];
  return <span className="risk-cell"><Tag tone={lvl.tone}>{lvl.label}</Tag><span className="small">{a.risk_score}{a.risk_upper > a.risk_score ? `–${a.risk_upper}` : ''}</span></span>;
}

function AddAccount({ onAdded }) {
  const [form, setForm] = useState({ serviceName: '', domain: '' });
  const { run, busy, error } = useAction(async () => {
    const r = await api.post('/accounts', { serviceName: form.serviceName || undefined, domain: form.domain || undefined });
    setForm({ serviceName: '', domain: '' });
    onAdded(r);
  });
  return (
    <form className="inline-form" onSubmit={(e) => { e.preventDefault(); run(); }} aria-label="Add an account manually">
      <label>Service name<input value={form.serviceName} maxLength={80} onChange={(e) => setForm({ ...form, serviceName: e.target.value })} placeholder="e.g. Old forum" /></label>
      <label>Website (optional)<input value={form.domain} maxLength={253} onChange={(e) => setForm({ ...form, domain: e.target.value })} placeholder="example.com" /></label>
      <button className="btn" disabled={busy || (!form.serviceName && !form.domain)}>{busy ? 'Adding…' : 'Add account'}</button>
      <ErrorNote error={error} />
    </form>
  );
}

export function Accounts() {
  const [params, setParams] = useSearchParams();
  const tab = params.get('status') || 'confirmed';
  const { data, error, loading, reload } = useResource(`/accounts?status=${tab}`);
  const [filter, setFilter] = useState('all');
  const [sort, setSort] = useState('risk');
  const [q, setQ] = useState('');
  const { toast, show } = useToast();
  const report = useAction(() => download('/reports/security.xlsx', 'footprintx-security-report.xlsx'));
  const items = useMemo(() => {
    let list = data?.items || [];
    const needle = q.trim().toLowerCase();
    if (needle) list = list.filter((a) => `${a.service_name} ${a.service_domain || ''}`.toLowerCase().includes(needle));
    if (filter === 'attention') list = list.filter((a) => ['critical', 'high'].includes(a.risk_level));
    if (filter === 'breached') list = list.filter((a) => a.exposure_status === 'confirmed_evidence');
    if (filter === 'mfa_unknown') list = list.filter((a) => a.mfa_status === 'unknown');
    if (filter === 'manual') list = list.filter((a) => a.manually_added);
    const by = {
      risk: (x, y) => (y.risk_score ?? -1) - (x.risk_score ?? -1) || x.service_name.localeCompare(y.service_name),
      name: (x, y) => x.service_name.localeCompare(y.service_name),
      recent: (x, y) => new Date(y.last_observed_at || 0) - new Date(x.last_observed_at || 0),
      oldest: (x, y) => new Date(x.first_observed_at || 0) - new Date(y.first_observed_at || 0),
    };
    return [...list].sort(by[sort]);
  }, [data, q, filter, sort]);
  const synthetic = (data?.items || []).some((a) => a.is_synthetic);

  return (
    <Shell>
      {toast}
      <PageHeader
        title="Accounts"
        intro="Online services linked to your connected email addresses, with the evidence behind each one. This is what FootprintX could find, not a complete list of every account you have."
        actions={<button className="btn ghost small" disabled={report.busy} onClick={() => report.run()}>{report.busy ? 'Preparing reportâ€¦' : 'Download Excel report'}</button>}
      />
      <ErrorNote error={report.error} />
      <div className="tabs" role="tablist" aria-label="Account status">
        {['confirmed', 'possible', 'dismissed'].map((s) => (
          <button key={s} role="tab" aria-selected={tab === s} className={`tab ${tab === s ? 'active' : ''}`} onClick={() => setParams(s === 'confirmed' ? {} : { status: s })}>{ACCOUNT_STATUS[s]}</button>
        ))}
      </div>
      {tab === 'possible' && <Note tone="info"><p>Possible matches have only weak signals (for example receipts). They don’t count toward your risk score. Confirm the ones that are yours and dismiss the rest.</p></Note>}
      {tab === 'dismissed' && <Note tone="info"><p>Dismissed accounts stay dismissed on future scans. Restore one if you dismissed it by mistake.</p></Note>}
      {synthetic && <Note tone="warn"><p>Accounts marked “Synthetic” come from the labelled test mailbox, not a real inbox.</p></Note>}

      <div className="toolbar">
        <label className="search"><span className="sr-only">Search accounts</span><input type="search" placeholder="Search by name or website" value={q} onChange={(e) => setQ(e.target.value)} /></label>
        {tab === 'confirmed' && (
          <div className="chips" role="group" aria-label="Filter">
            {FILTERS.map(([k, label]) => <button key={k} className={`chip ${filter === k ? 'active' : ''}`} aria-pressed={filter === k} onClick={() => setFilter(k)}>{label}</button>)}
          </div>
        )}
        <label className="sort">Sort <select value={sort} onChange={(e) => setSort(e.target.value)}>{Object.entries(SORTS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></label>
      </div>

      {loading ? <Loading /> : error ? <ErrorNote error={error} onRetry={reload} /> : items.length === 0 ? (
        <Empty title={q || filter !== 'all' ? 'No accounts match' : tab === 'confirmed' ? 'No accounts yet' : `No ${ACCOUNT_STATUS[tab].toLowerCase()} accounts`}>
          {tab === 'confirmed' && !q && filter === 'all' ? <p>Connect a mailbox and run a scan, or add an account below.</p> : null}
        </Empty>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <caption className="sr-only">{ACCOUNT_STATUS[tab]} accounts</caption>
            <thead>
              <tr><th scope="col">Service</th><th scope="col">Risk</th><th scope="col">Breach</th><th scope="col">Two-step</th><th scope="col">Found via</th><th scope="col">Last evidence</th></tr>
            </thead>
            <tbody>
              {items.map((a) => (
                <tr key={a.id}>
                  <th scope="row">
                    <Link to={`/accounts/${a.id}`}>{a.service_name}</Link>
                    <span className="sub">{a.service_domain || 'no website'} · {a.connection_email || a.identifier_masked || 'manual'}{a.is_synthetic ? ' · Synthetic' : ''}</span>
                  </th>
                  <td><RiskCell a={a} /></td>
                  <td><Tag tone={EXPOSURE[a.exposure_status].tone}>{EXPOSURE[a.exposure_status].label}</Tag></td>
                  <td><Tag tone={MFA[a.mfa_status].tone}>{MFA[a.mfa_status].label}</Tag></td>
                  <td className="small">{DISCOVERY_SOURCE[a.discovery_source]}</td>
                  <td className="small"><Time value={a.last_observed_at} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <section className="section" aria-labelledby="add-h">
        <h2 id="add-h">Track an account yourself</h2>
        <p className="small">Know of an account FootprintX didn’t find? Add it so it’s included in your inventory and risk score. Manual entries are labelled as added by you.</p>
        <AddAccount onAdded={(r) => { show(`Added ${r.account.service_name}.`); reload({ quiet: true }); }} />
      </section>
    </Shell>
  );
}

// ---------------------------------------------------------------------------------

export function AccountDetail() {
  const { id } = useParams();
  const { data, error, loading, reload } = useResource(`/accounts/${id}`);
  const { toast, show } = useToast();
  const [confirmDismiss, setConfirmDismiss] = useState(false);
  const patch = useAction(async (body, message) => {
    await api.patch(`/accounts/${id}`, body);
    await reload({ quiet: true });
    show(message);
  });
  const del = useAction(async () => {
    await api.del(`/accounts/${id}`);
    window.history.back();
  });
  if (loading) return <Shell><Loading /></Shell>;
  if (error) return <Shell><ErrorNote error={error} onRetry={reload} /><Link to="/accounts">Back to accounts</Link></Shell>;
  const { account: a, evidence, breaches, recommendations } = data;
  const rf = a.risk_factors || {};
  const known = [];
  const unknown = [];
  (a.mfa_status === 'unknown' ? unknown : known).push(`Two-step verification: ${MFA[a.mfa_status].label}${a.mfa_source ? ` (${MFA_SOURCE[a.mfa_source]}${a.mfa_observed_at ? `, ${formatDate(a.mfa_observed_at)}` : ''})` : ''}`);
  (a.exposure_status === 'unknown' ? unknown : known).push(`Breach exposure: ${EXPOSURE[a.exposure_status].label}${a.exposure_checked_at ? ` (checked ${formatDate(a.exposure_checked_at)})` : ''}`);
  if (ACCOUNT_STATE[a.account_state]) known.push(`Status: ${ACCOUNT_STATE[a.account_state]}`);
  unknown.push('Whether your current password is strong or reused (FootprintX never sees passwords)');

  return (
    <Shell>
      {toast}
      <Link to="/accounts" className="textlink back">Accounts</Link>
      <PageHeader
        title={a.service_name}
        intro={<>{a.service_domain || 'No website recorded'} · {a.connection_email || 'Added by you'} · {DISCOVERY_SOURCE[a.discovery_source]} · {CONFIDENCE[a.confidence]}{a.is_synthetic ? ' · Synthetic data' : ''}</>}
        actions={<RiskCell a={a} />}
      />
      {a.status === 'possible' && (
        <Note tone="info" title="Is this your account?">
          <p>FootprintX found only weak signals for this service. Confirm it to include it in your risk score, or dismiss it.</p>
          <div className="row-actions">
            <button className="btn small primary" onClick={() => patch.run({ action: 'confirm' }, 'Marked as yours.')}>Yes, it’s mine</button>
            <button className="btn small ghost" onClick={() => patch.run({ action: 'dismiss', reason: 'not_mine' }, 'Dismissed.')}>Not mine</button>
          </div>
        </Note>
      )}
      {a.status === 'dismissed' && <Note tone="info"><p>You dismissed this account. <button className="linkbtn" onClick={() => patch.run({ action: 'restore' }, 'Restored.')}>Restore it</button></p></Note>}

      <div className="two-col wide-gap">
        <section className="section" aria-labelledby="why-h">
          <h2 id="why-h">Why this risk level</h2>
          {rf.excluded === 'closed' ? <p>This account is recorded as closed, so it no longer adds to your score.</p> : null}
          {(rf.factors || []).length ? (
            <ul className="factor-list">
              {rf.factors.map((f) => (
                <li key={f.code}>
                  <div className="factor-head"><strong>{FACTOR[f.code] || f.label}</strong><span className="small">+{f.effective} pts</span></div>
                  <p className="small">{f.label}{f.remediation ? ` — reduced because you ${f.remediation === 'verified' ? 'made a change the service confirmed' : 'reported a change'}` : ''}{f.confidence ? ` · ${CONFIDENCE[f.confidence]}` : ''}</p>
                  {Array.isArray(f.provenance) && f.provenance.length > 0 && <p className="small muted">Source: {f.provenance.join('; ')}</p>}
                  {f.code !== 'BASE_EXPOSURE' && <p className="small">To reduce: {f.reduceBy}</p>}
                </li>
              ))}
            </ul>
          ) : <p className="muted">Not scored.</p>}
          {(rf.unknowns || []).length > 0 && (
            <p className="small">Unknown, so shown as a range rather than assumed safe: {rf.unknowns.map((u) => FACTOR[u.code] || u.label).join(', ')}.</p>
          )}
        </section>
        <section className="section" aria-labelledby="known-h">
          <h2 id="known-h">What FootprintX knows</h2>
          <ul className="checklist">{known.map((k) => <li key={k}>{k}</li>)}</ul>
          <h3>What it doesn’t know</h3>
          <ul className="checklist muted-list">{unknown.map((k) => <li key={k}>{k}</li>)}</ul>
          <p className="small">First evidence {formatDate(a.first_observed_at)} · latest {formatDate(a.last_observed_at)} · last checked <Time value={a.last_checked_at} /></p>
        </section>
      </div>

      {recommendations.length > 0 && (
        <section className="section" aria-labelledby="todo-h">
          <h2 id="todo-h">Recommended actions</h2>
          <ul className="plain-list">
            {recommendations.map((r) => (
              <li key={r.id} className="kv-row">
                <span><Tag tone={SEVERITY[r.severity].tone}>{SEVERITY[r.severity].label}</Tag> <Link to={`/recommendations#${r.id}`}>{r.title}</Link></span>
                <span className="kv-end">
                  <Tag tone={REMEDIATION[r.status].tone}>{REMEDIATION[r.status].label}</Tag>
                  {r.official_url && <ExternalLink href={r.official_url} kind={r.official_url_kind}>Official page</ExternalLink>}
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}

      {breaches.length > 0 && (
        <section className="section" aria-labelledby="br-h">
          <h2 id="br-h">Breach listings</h2>
          <p className="small">These are historical records. They stay here after you change your password, because changing a password doesn’t change the past.</p>
          <ul className="plain-list">
            {breaches.map((b) => (
              <li key={b.id} className="breach-item">
                <strong>{b.breach_title}</strong> {b.breach_date ? `(${b.breach_date_precision === 'year' ? String(b.breach_date).slice(0, 4) : formatDate(b.breach_date)})` : '(date unknown)'}
                {b.password_exposed && <Tag tone="bad">Passwords included</Tag>}
                {b.provider_verified === false && <Tag tone="unknown">Unverified by provider</Tag>}
                <p className="small">Exposed data: {b.data_classes.join(', ') || 'not listed'} · source: {b.provider === 'synthetic' ? 'synthetic fixture' : b.provider} · first seen by FootprintX {formatDate(b.first_seen_at)}</p>
              </li>
            ))}
          </ul>
        </section>
      )}

      <section className="section" aria-labelledby="ev-h">
        <h2 id="ev-h">Evidence</h2>
        <p className="small">Each item is a kind of email (not its content) or a breach listing, with when it happened. FootprintX doesn’t store subjects or message text.</p>
        {evidence.length ? (
          <table className="table compact">
            <thead><tr><th scope="col">What</th><th scope="col">When</th><th scope="col">Sender</th><th scope="col">Strength</th></tr></thead>
            <tbody>
              {evidence.map((e) => (
                <tr key={e.id}>
                  <td>{EVIDENCE_KIND[e.kind] || e.kind}</td>
                  <td>{formatDate(e.observed_at)}</td>
                  <td className="small">{e.sender_domain ? <span className="domain">{e.sender_domain}</span> : '—'} {e.sender_authenticated && e.kind !== 'breach_record' && e.kind !== 'mailbox_connection' ? `· ${AUTH_RESULT[e.sender_authenticated]}` : ''}</td>
                  <td className="small">{e.strength === 'strong' ? 'Strong' : 'Weak'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : <p className="muted">{a.manually_added ? 'You added this account yourself.' : 'No evidence recorded.'}</p>}
      </section>

      <section className="section" aria-labelledby="fix-h">
        <h2 id="fix-h">Correct this record</h2>
        <div className="correct-grid">
          <label>Name shown in FootprintX
            <span className="inline-edit">
              <input defaultValue={a.service_name} maxLength={80} id="rename" />
              <button className="btn small" onClick={() => patch.run({ serviceName: document.getElementById('rename').value }, 'Name updated.')}>Save</button>
            </span>
          </label>
          <label>Two-step verification (your own report)
            <select value={a.mfa_source === 'user_reported' ? a.mfa_status : ''} onChange={(e) => patch.run({ mfaStatus: e.target.value || 'unknown' }, 'Two-step verification status recorded as reported by you.')}>
              <option value="">{a.mfa_source === 'mailbox_evidence' ? `From email evidence: ${MFA[a.mfa_status].label}` : 'Not reported'}</option>
              <option value="enabled">It’s on</option>
              <option value="disabled">It’s off</option>
              <option value="unknown">I’m not sure</option>
            </select>
          </label>
          <label>Account status
            <select value={a.account_state === 'closed_user_reported' ? 'closed' : 'open'} onChange={(e) => patch.run({ accountState: e.target.value }, e.target.value === 'closed' ? 'Recorded as closed (reported by you).' : 'Recorded as open.')}>
              <option value="open">Still open / not sure</option>
              <option value="closed">I closed this account</option>
            </select>
          </label>
        </div>
        <div className="row-actions">
          {a.status !== 'dismissed' && <button className="btn ghost small" onClick={() => setConfirmDismiss(true)}>This isn’t my account</button>}
          {a.manually_added && <button className="btn danger small" onClick={() => del.run()} disabled={del.busy}>Remove from FootprintX</button>}
        </div>
        <p className="small">These change FootprintX’s records only. FootprintX never changes or deletes your account at {a.service_name}.</p>
        <ErrorNote error={patch.error || del.error} />
      </section>
      <ConfirmDialog
        open={confirmDismiss}
        title={`Dismiss ${a.service_name}?`}
        confirmLabel="Dismiss account"
        tone="neutral"
        onCancel={() => setConfirmDismiss(false)}
        onConfirm={async () => { setConfirmDismiss(false); await patch.run({ action: 'dismiss', reason: 'not_mine' }, 'Dismissed. It won’t come back on future scans.'); }}
      >
        <p>It will be removed from your inventory and risk score, and won’t be re-added by future scans. You can restore it from the Dismissed tab.</p>
      </ConfirmDialog>
    </Shell>
  );
}
