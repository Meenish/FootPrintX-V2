import { useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Shell, PageHeader, Tag, Loading, ErrorNote, Empty, Time, Note } from '../components.jsx';
import { api } from '../lib/api.js';
import { useResource } from '../lib/hooks.js';
import { SCAN_STATUS, SEVERITY, REMEDIATION, REPUTATION, TRIGGER } from '../lib/labels.js';

const KINDS = { all: 'Everything', alerts: 'Alerts', scans: 'Scans', remediation: 'Remediation', score: 'Score changes', web: 'Website checks' };
const EXT_TYPE = { malicious_site_blocked: 'Extension blocked a known threat', suspicious_site_warned: 'Extension warned about a suspicious site', cached_result_escalated: 'A site you visited was later flagged' };

export function Activity() {
  const [days, setDays] = useState(30);
  const [kind, setKind] = useState('all');
  const { data, error, loading, reload } = useResource(`/activity?days=${days}`, { pollMs: 30000 });
  const events = useMemo(() => {
    if (!data) return [];
    const out = [];
    for (const a of data.alerts) out.push({ k: 'alerts', at: a.created_at, id: `a${a.id}`, node: <><Tag tone={SEVERITY[a.severity].tone}>{SEVERITY[a.severity].label}</Tag> <strong>{a.title}</strong><p className="small">{a.body}</p>{a.account_id && <Link className="small" to={`/accounts/${a.account_id}`}>View account</Link>}</>, alert: a });
    for (const s of data.scans) out.push({ k: 'scans', at: s.created_at, id: `s${s.id}`, node: <><Tag tone={SCAN_STATUS[s.status].tone}>{SCAN_STATUS[s.status].label}</Tag> Scan of {s.email_masked} ({s.trigger}){s.summary ? ` — ${s.summary.confirmed} confirmed, ${s.summary.possible} possible` : ''}{s.error_message ? <p className="small">{s.error_message}</p> : null}</> });
    for (const r of data.remediation) out.push({ k: 'remediation', at: r.created_at, id: `r${r.id}`, node: <><strong>{r.title}</strong>: {REMEDIATION[r.from_status]?.label || 'New'} → {REMEDIATION[r.to_status]?.label} <span className="small">({r.actor === 'user' ? 'you' : 'FootprintX'})</span>{r.note && <p className="small">{r.note}</p>}</> });
    for (const d of data.scoreChanges) out.push({ k: 'score', at: d.created_at, id: `d${d.id}`, node: <>Risk score {d.score ?? '—'}{d.delta ? ` (${d.delta > 0 ? '+' : ''}${d.delta})` : ''} after: {TRIGGER[d.trigger] || d.trigger}<ul className="small">{(d.change_reasons || []).slice(0, 3).map((x, i) => <li key={i}>{x.message}</li>)}</ul></> });
    for (const e of data.extensionEvents) out.push({ k: 'web', at: e.occurred_at, id: `e${e.id}`, node: <><Tag tone={e.status === 'malicious' ? 'bad' : 'warn'}>{e.status === 'malicious' ? 'Known threat' : 'Suspicious'}</Tag> {EXT_TYPE[e.type]}: <span className="domain">{e.domain}</span></> });
    for (const c of data.websiteChecks) out.push({ k: 'web', at: c.checked_at, id: `c${c.id}`, node: <>You checked <span className="domain">{c.domain}</span>: <Tag tone={REPUTATION[c.status]?.tone}>{REPUTATION[c.status]?.label || c.status}</Tag></> });
    return out.filter((e) => kind === 'all' || e.k === kind).sort((a, b) => new Date(b.at) - new Date(a.at));
  }, [data, kind]);

  async function markAllRead() {
    await api.post('/alerts/read-all', {});
    reload({ quiet: true });
  }

  return (
    <Shell>
      <PageHeader title="Activity" intro="Scans, alerts, remediation and score changes in one timeline. Website checks are listed separately from your accounts — visiting a site doesn’t mean you have an account there." actions={<button className="btn ghost small" onClick={markAllRead}>Mark alerts read</button>} />
      <div className="toolbar">
        <div className="chips" role="group" aria-label="Show">
          {Object.entries(KINDS).map(([k, l]) => <button key={k} className={`chip ${kind === k ? 'active' : ''}`} aria-pressed={kind === k} onClick={() => setKind(k)}>{l}</button>)}
        </div>
        <label className="sort">Period <select value={days} onChange={(e) => setDays(Number(e.target.value))}><option value={7}>7 days</option><option value={30}>30 days</option><option value={90}>90 days</option><option value={365}>1 year</option></select></label>
      </div>
      {data && data.days < days && <Note tone="info"><p>The Free plan shows the last {data.maxDays} days of activity. <Link to="/premium">Premium keeps a year of security history.</Link></p></Note>}
      {loading ? <Loading /> : error ? <ErrorNote error={error} onRetry={reload} /> : events.length ? (
        <ol className="timeline big">
          {events.map((e) => <li key={e.id} className={e.alert?.status === 'unread' ? 'unread' : ''}><Time value={e.at} /><div>{e.node}</div></li>)}
        </ol>
      ) : <Empty title="No activity in this period" />}
    </Shell>
  );
}
