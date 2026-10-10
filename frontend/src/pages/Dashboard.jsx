import { Link } from 'react-router-dom';
import { Shell, PageHeader, Tag, Loading, ErrorNote, Empty, Time, SyntheticBanner, Note } from '../components.jsx';
import { DasiGauge } from '../DasiGauge.jsx';
import { LastScanLine } from '../Mailbox.jsx';
import { useResource } from '../lib/hooks.js';
import { SEVERITY, ACTION, REPUTATION, TRIGGER } from '../lib/labels.js';

export function Dashboard() {
  const { data: d, error, loading, reload } = useResource('/dashboard', { pollMs: 20000 });
  if (loading) return <Shell><Loading label="Loading your overview…" /></Shell>;
  if (error) return <Shell><ErrorNote error={error} onRetry={reload} /></Shell>;
  const dasi = d.dasi;
  const activeConns = d.connections.filter((c) => c.status === 'active');
  const running = d.scans.find((s) => s.status === 'queued' || s.status === 'running');
  const premium = d.entitlement.plan === 'premium';

  return (
    <Shell>
      <PageHeader title="Overview" intro="Your accounts, the risks FootprintX has evidence for, and what to do next." />
      <SyntheticBanner show={d.syntheticData} />
      {activeConns.length === 0 && (
        <Note tone="info" title="Connect a mailbox to start">
          <p>FootprintX discovers accounts from the emails services send you. <Link to="/onboarding">Connect a mailbox</Link> or <Link to="/accounts?add=1">add accounts yourself</Link>.</p>
        </Note>
      )}
      {d.connections.some((c) => c.status === 'reauth_required') && (
        <Note tone="warn" title="A mailbox needs to be reconnected"><p>Gmail access expired or was revoked. <Link to="/settings?tab=connections">Reconnect it in Settings</Link>.</p></Note>
      )}

      <section className="overview-grid">
        <div className="overview-score">
          <h2 className="h-small">Digital Attack Surface Index</h2>
          <DasiGauge snapshot={dasi} />
          {dasi?.score != null && (
            <p className="small">
              Assessed <Time value={dasi.created_at} /> · {dasi.coverage?.accountsAssessed ?? 0} open accounts scored · <Link to="/dasi">How this is calculated</Link>
            </p>
          )}
          {dasi?.delta != null && dasi.delta !== 0 && (
            <p className="small">{dasi.delta > 0 ? `Up ${dasi.delta}` : `Down ${-dasi.delta}`} since the previous assessment ({TRIGGER[dasi.trigger] || dasi.trigger}).</p>
          )}
        </div>
        <dl className="facts">
          <div><dt>Confirmed accounts</dt><dd><Link to="/accounts">{d.accounts.confirmed}</Link></dd></div>
          <div><dt>Possible matches to review</dt><dd><Link to="/accounts?status=possible">{d.accounts.possible}</Link></dd></div>
          <div><dt>Open recommendations</dt><dd><Link to="/recommendations">{d.recommendations.open}</Link></dd></div>
          <div><dt>Awaiting confirmation</dt><dd>{d.recommendations.awaitingVerification}</dd></div>
        </dl>
      </section>
      <p className="small definitions">{d.accounts.definitions.confirmed} {d.accounts.definitions.possible}</p>

      {dasi?.critical_findings?.length > 0 && (
        <section className="section critical" aria-labelledby="crit-h">
          <h2 id="crit-h">Needs attention now</h2>
          <p className="small">These stand out regardless of your overall score.</p>
          <ul className="plain-list">
            {dasi.critical_findings.map((c) => (
              <li key={`${c.code}${c.accountId}`} className="crit-row"><Tag tone="bad">Critical</Tag> <Link to={`/accounts/${c.accountId}`}>{c.message}</Link></li>
            ))}
          </ul>
        </section>
      )}

      <div className="two-col wide-gap">
        <section className="section" aria-labelledby="todo-h">
          <h2 id="todo-h">Next steps</h2>
          {d.recommendations.top.length ? (
            <ol className="rank-list">
              {d.recommendations.top.map((r) => (
                <li key={r.id}>
                  <Tag tone={SEVERITY[r.severity].tone}>{SEVERITY[r.severity].label}</Tag>
                  <Link to={`/recommendations#${r.id}`}>{r.title}</Link>
                  <span className="small">{ACTION[r.action_type]}</span>
                </li>
              ))}
            </ol>
          ) : (
            <Empty title={dasi?.score == null ? 'No recommendations yet' : 'Nothing open'}>{dasi?.score == null ? 'They appear after your first scan.' : 'You have dealt with every current recommendation.'}</Empty>
          )}
          <Link className="textlink" to="/recommendations">All recommendations</Link>
        </section>

        <section className="section" aria-labelledby="alerts-h">
          <h2 id="alerts-h">Recent alerts</h2>
          {d.alerts.recent.length ? (
            <ul className="plain-list">
              {d.alerts.recent.slice(0, 5).map((a) => (
                <li key={a.id} className={`alert-row ${a.status === 'unread' ? 'unread' : ''}`}>
                  <Tag tone={SEVERITY[a.severity].tone}>{SEVERITY[a.severity].label}</Tag>
                  <span>{a.title}</span>
                  <span className="small"><Time value={a.created_at} /></span>
                </li>
              ))}
            </ul>
          ) : (
            <Empty title="No alerts">Alerts appear when FootprintX finds something new that needs your attention.</Empty>
          )}
          <Link className="textlink" to="/activity">All activity</Link>
        </section>
      </div>

      <div className="two-col wide-gap">
        <section className="section" aria-labelledby="mb-h">
          <h2 id="mb-h">Mailboxes</h2>
          {d.connections.length ? (
            <ul className="plain-list">
              {d.connections.map((c) => (
                <li key={c.id} className="kv-row">
                  <span>{c.email_masked}{c.is_synthetic && <span className="tag tone-warn">Synthetic</span>}</span>
                  <span>{c.status === 'active' ? <LastScanLine scan={d.scans.find((s) => s.connection_id === c.id)} /> : <Tag tone="unknown">{c.status === 'disconnected' ? 'Disconnected' : 'Reconnect needed'}</Tag>}</span>
                </li>
              ))}
            </ul>
          ) : (
            <Empty title="No mailbox connected" action={<Link className="btn small" to="/onboarding">Connect a mailbox</Link>} />
          )}
          {running && <p className="small" role="status">A scan is in progress; this page updates automatically.</p>}
          <Link className="textlink" to="/settings?tab=connections">Manage mailboxes</Link>
        </section>

        <section className="section" aria-labelledby="web-h">
          <h2 id="web-h">Browser protection</h2>
          {premium ? (
            <p>{d.extension.linkedBrowsers ? `${d.extension.linkedBrowsers} browser${d.extension.linkedBrowsers > 1 ? 's' : ''} linked. Last seen ` : 'No browser linked yet. '}{d.extension.linkedBrowsers ? <Time value={d.extension.lastSeenAt} /> : <Link to="/settings?tab=extension">Link the extension</Link>}</p>
          ) : (
            <p>Automatic warnings for known threat sites come with Premium. You can still <Link to="/website-check">check a website</Link> any time.</p>
          )}
          {d.websiteChecks.length > 0 && (
            <ul className="plain-list">
              {d.websiteChecks.map((c) => (
                <li key={c.checked_at + c.domain} className="kv-row"><span className="domain">{c.domain}</span><Tag tone={REPUTATION[c.status]?.tone}>{REPUTATION[c.status]?.label || c.status}</Tag></li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </Shell>
  );
}
