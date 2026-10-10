import { useEffect, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Shell, PageHeader, Tag, Loading, ErrorNote, Empty, Time, ExternalLink, useToast } from '../components.jsx';
import { api } from '../lib/api.js';
import { useAction, useResource } from '../lib/hooks.js';
import { ACTION, REMEDIATION, SEVERITY, formatDate } from '../lib/labels.js';

const GROUPS = [
  ['open', 'To do', (r) => r.applicable && ['recommended', 'in_progress'].includes(r.status)],
  ['done', 'Done', (r) => ['user_reported', 'verification_pending', 'verified', 'unable_to_verify'].includes(r.status)],
  ['dismissed', 'Dismissed', (r) => r.status === 'dismissed'],
];

function VerificationLine({ r }) {
  if (r.status === 'verified') {
    const ev = r.verification_evidence || {};
    return <p className="small good-text">Confirmed: {ev.senderDomain || r.service_domain} emailed you about this change on {formatDate(ev.observedAt)}. That shows the change happened; it can’t prove the setting is still the same today.</p>;
  }
  if (r.status === 'verification_pending') {
    return (
      <p className="small">
        {r.verification_scan_started
          ? 'FootprintX is checking your mailbox now for a confirmation email from the service. '
          : 'FootprintX will look for a confirmation email from the service in your next scans. '}
        It keeps looking until {formatDate(r.verification_deadline)}. Until a confirmation arrives this counts as reported by you, and many services never send one.
      </p>
    );
  }
  if (r.status === 'unable_to_verify') return <p className="small">No confirmation email arrived, so this stays recorded as reported by you. Many services don’t send one — that’s not a problem.</p>;
  if (r.status === 'user_reported') return <p className="small">{r.verification_method === 'none' ? 'FootprintX has no way to confirm this kind of change, so it’s recorded as reported by you.' : 'Reported by you.'}</p>;
  return null;
}

function RecCard({ r, onChange }) {
  const [open, setOpen] = useState(false);
  const [dismissReason, setDismissReason] = useState('not_relevant');
  const act = useAction(async (body) => onChange(await api.patch(`/recommendations/${r.id}`, body)));
  const status = REMEDIATION[r.status];
  const sev = SEVERITY[r.severity];
  return (
    <li id={r.id} className={`rec-card sev-${r.severity}`}>
      <div className="rec-head">
        <Tag tone={sev.tone}>{sev.label}</Tag>
        <h3>{r.title}</h3>
        <Tag tone={status.tone}>{status.label}</Tag>
      </div>
      <p>{r.explanation}</p>
      <p className="small"><strong>Why it matters:</strong> {r.why_it_matters}</p>
      <p className="small"><strong>Next step:</strong> {r.next_step}</p>
      <div className="rec-links">
        {r.official_url ? (
          <ExternalLink href={r.official_url} kind={r.official_url_kind}>
            {r.official_url_kind === 'help_page'
              ? `${ACTION[r.action_type]}: official guide`
              : r.official_url_kind === 'domain_root'
                ? `Open ${r.service_name || 'the service'} — find it in Settings`
                : `Open ${r.service_name || 'the service'} settings`}
          </ExternalLink>
        ) : <span className="small muted">No verified official link for this service.</span>}
        {r.account_id && <Link className="textlink" to={`/accounts/${r.account_id}`}>View account</Link>}
      </div>
      <VerificationLine r={r} />
      <button className="linkbtn small" aria-expanded={open} onClick={() => setOpen(!open)}>{open ? 'Hide details' : 'Evidence and expected effect'}</button>
      {open && (
        <div className="rec-more">
          <ul className="checklist">{r.evidence.map((e, i) => <li key={i}>{e.label}</li>)}</ul>
          <p className="small"><strong>Expected effect:</strong> {r.expected_effect}</p>
          <p className="small">Last updated {formatDate(r.updated_at, { time: true })}{r.reported_at ? ` · reported ${formatDate(r.reported_at)}` : ''}</p>
        </div>
      )}
      <div className="row-actions">
        {r.status === 'recommended' && <button className="btn small ghost" onClick={() => act.run({ status: 'in_progress' })} disabled={act.busy}>I’m working on it</button>}
        {['recommended', 'in_progress'].includes(r.status) && <button className="btn small primary" onClick={() => act.run({ status: 'user_reported' })} disabled={act.busy}>I’ve done this</button>}
        {['user_reported', 'verification_pending', 'unable_to_verify', 'dismissed', 'in_progress'].includes(r.status) && <button className="btn small ghost" onClick={() => act.run({ status: 'recommended' })} disabled={act.busy}>{r.status === 'dismissed' ? 'Restore' : 'Undo'}</button>}
        {['recommended', 'in_progress'].includes(r.status) && (
          <span className="dismiss">
            <label className="sr-only" htmlFor={`dr-${r.id}`}>Reason for dismissing</label>
            <select id={`dr-${r.id}`} value={dismissReason} onChange={(e) => setDismissReason(e.target.value)}>
              <option value="not_relevant">Not relevant</option>
              <option value="already_done">Already done earlier</option>
              <option value="accept_risk">I accept this risk</option>
              <option value="not_my_account">Not my account</option>
              <option value="other">Other</option>
            </select>
            <button className="btn small ghost" onClick={() => act.run({ status: 'dismissed', dismissedReason: dismissReason })} disabled={act.busy}>Dismiss</button>
          </span>
        )}
      </div>
      <ErrorNote error={act.error} />
    </li>
  );
}

export function Recommendations() {
  const { data, error, loading, reload } = useResource('/recommendations', { pollMs: 30000 });
  const [group, setGroup] = useState('open');
  const [historyVersion, setHistoryVersion] = useState(0);
  const { toast, show } = useToast();
  const loc = useLocation();
  useEffect(() => {
    if (loc.hash && data) document.getElementById(loc.hash.slice(1))?.scrollIntoView({ block: 'center' });
  }, [loc.hash, data]);
  const items = (data?.items || []).filter(GROUPS.find((g) => g[0] === group)[2]);
  function onChange(r) {
    const t = r.transition.to;
    show(t === 'verification_pending' ? `Recorded. FootprintX will look for a confirmation email from the service. Your score is now ${r.dasi.score}.` : t === 'user_reported' ? `Recorded as done (reported by you). Your score is now ${r.dasi.score}.` : t === 'dismissed' ? 'Dismissed.' : 'Updated.');
    reload({ quiet: true });
    setHistoryVersion((v) => v + 1);
  }
  return (
    <Shell>
      {toast}
      <PageHeader title="Recommendations" intro="Specific steps, ordered by severity and confidence. FootprintX never changes your accounts — you make each change on the service’s own site, then tell FootprintX." />
      <div className="tabs" role="tablist" aria-label="Recommendation status">
        {GROUPS.map(([k, label, fn]) => (
          <button key={k} role="tab" aria-selected={group === k} className={`tab ${group === k ? 'active' : ''}`} onClick={() => setGroup(k)}>
            {label} <span className="count">{(data?.items || []).filter(fn).length}</span>
          </button>
        ))}
      </div>
      {loading ? <Loading /> : error ? <ErrorNote error={error} onRetry={reload} /> : items.length ? (
        <ul className="rec-list">{items.map((r) => <RecCard key={r.id} r={r} onChange={onChange} />)}</ul>
      ) : (
        <Empty title={group === 'open' ? 'Nothing to do right now' : 'Nothing here yet'}>{group === 'open' ? <p>New recommendations appear when a scan or breach check finds something. <Link to="/activity">See recent activity</Link>.</p> : null}</Empty>
      )}
      <History key={historyVersion} />
    </Shell>
  );
}

function History() {
  const { data } = useResource('/recommendations/history');
  if (!data?.items?.length) return null;
  return (
    <section className="section" aria-labelledby="hist-h">
      <h2 id="hist-h">Remediation history</h2>
      <ol className="timeline">
        {data.items.slice(0, 20).map((e) => (
          <li key={e.id}>
            <Time value={e.created_at} /> — <strong>{e.title}</strong>: {REMEDIATION[e.from_status]?.label || 'New'} → {REMEDIATION[e.to_status]?.label} <span className="small">({e.actor === 'user' ? 'you' : 'FootprintX'})</span>
            {e.note && <p className="small">{e.note}</p>}
          </li>
        ))}
      </ol>
    </section>
  );
}
