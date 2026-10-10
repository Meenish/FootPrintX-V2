import { Link } from 'react-router-dom';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts';
import { Shell, PageHeader, Loading, ErrorNote, Time, Note } from '../components.jsx';
import { DasiGauge } from '../DasiGauge.jsx';
import { useResource } from '../lib/hooks.js';
import { FACTOR, TRIGGER, formatDate } from '../lib/labels.js';

export function Dasi() {
  const cur = useResource('/dasi');
  const hist = useResource('/dasi/history');
  if (cur.loading) return <Shell><Loading /></Shell>;
  if (cur.error) return <Shell><ErrorNote error={cur.error} onRetry={cur.reload} /></Shell>;
  const { snapshot: s, methodology: m } = cur.data;
  const scored = (hist.data?.items || []).filter((h) => h.score != null).reverse();
  const cov = s?.coverage || {};
  return (
    <Shell>
      <PageHeader title="Digital Attack Surface Index" intro={m.disclaimer} />
      <section className="section dasi-top">
        <DasiGauge snapshot={s} />
        <div>
          <h2 className="h-small">Evidence behind this score</h2>
          <ul className="checklist">
            <li>{cov.accountsAssessed ?? 0} confirmed accounts scored{cov.possibleAccounts ? `; ${cov.possibleAccounts} possible matches not counted` : ''}</li>
            <li>{cov.connectionsScannedRecently ?? 0} of {cov.activeConnections ?? 0} connected mailboxes scanned in the last 30 days</li>
            <li>{cov.connectionsBreachCheckedRecently ?? 0} of {cov.activeConnections ?? 0} mailboxes checked for breaches in the last 30 days</li>
            <li>Two-step verification known for {Math.round((cov.mfaKnownShare ?? 0) * 100)}% of accounts</li>
          </ul>
          {cov.gaps?.length > 0 && (
            <Note tone="warn" title="What would make this more reliable">
              <ul>{cov.gaps.map((g) => <li key={g}>{g}</li>)}</ul>
            </Note>
          )}
          {s?.created_at && <p className="small">Assessed <Time value={s.created_at} /> · model {s.model_version}</p>}
        </div>
      </section>

      {s?.score != null && (
        <section className="section" aria-labelledby="contrib-h">
          <h2 id="contrib-h">Biggest contributors</h2>
          <table className="table compact">
            <thead><tr><th scope="col">Account</th><th scope="col">Account score</th><th scope="col">Factors</th></tr></thead>
            <tbody>
              {(s.contributors || []).map((c) => (
                <tr key={c.accountId}>
                  <th scope="row"><Link to={`/accounts/${c.accountId}`}>{c.serviceName}</Link></th>
                  <td>{c.score}</td>
                  <td className="small">{c.factors.length ? c.factors.map((f) => `${FACTOR[f.code] || f.code} (+${f.effective})`).join(', ') : 'Account exists only'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}

      <section className="section" aria-labelledby="hist-h">
        <h2 id="hist-h">How your score changed</h2>
        {scored.length >= 2 ? (
          <div className="chart" role="img" aria-label={`Score history from ${scored[0].score} to ${scored.at(-1).score}`}>
            <ResponsiveContainer width="100%" height={220}>
              <LineChart data={scored.map((h) => ({ t: formatDate(h.created_at, { time: true }), score: h.score, upper: h.upper_bound }))} margin={{ top: 10, right: 16, left: -16, bottom: 0 }}>
                <CartesianGrid stroke="#1e2e42" vertical={false} />
                <XAxis dataKey="t" stroke="#8ea3b8" tick={{ fontSize: 12 }} />
                <YAxis domain={[0, 100]} stroke="#8ea3b8" tick={{ fontSize: 12 }} />
                <Tooltip contentStyle={{ background: '#0f1a28', border: '1px solid #1e2e42', color: '#e8eef5' }} />
                <Line type="stepAfter" dataKey="upper" name="Upper bound" stroke="#5b6f86" strokeDasharray="4 4" dot={false} isAnimationActive={false} />
                <Line type="stepAfter" dataKey="score" name="Score" stroke="#3fd0ff" strokeWidth={2} dot isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        ) : <p className="muted">A chart appears once there are at least two assessments.</p>}
        <ol className="timeline">
          {(hist.data?.items || []).slice(0, 15).map((h) => (
            <li key={h.id}>
              <Time value={h.created_at} /> — <strong>{h.score ?? '—'}</strong>{h.delta != null && h.delta !== 0 ? ` (${h.delta > 0 ? '+' : ''}${h.delta})` : ''} · {TRIGGER[h.trigger] || h.trigger}
              <ul className="small">{(h.change_reasons || []).map((r, i) => <li key={i}>{r.message}</li>)}</ul>
            </li>
          ))}
        </ol>
      </section>

      <section className="section methodology" aria-labelledby="meth-h">
        <h2 id="meth-h">Methodology ({m.modelVersion})</h2>
        <p>{m.range} {m.unknowns}</p>
        <h3>Account score</h3>
        <p>Each confirmed account starts at {m.weights.BASE_EXPOSURE} points (every account is something an attacker could target). Evidence adds points, multiplied by how sure FootprintX is (high ×{m.confidenceWeights.high}, medium ×{m.confidenceWeights.medium}, low ×{m.confidenceWeights.low}) and by how much damage a takeover could do:</p>
        <table className="table compact">
          <thead><tr><th scope="col">Evidence</th><th scope="col">Points</th></tr></thead>
          <tbody>
            <tr><td>Listed in a breach that included passwords</td><td>{m.weights.CREDENTIAL_EXPOSURE_PASSWORD} (+{m.weights.ADDITIONAL_BREACH} per further breach, max +{m.weights.ADDITIONAL_BREACH_CAP})</td></tr>
            <tr><td>Listed in a breach without passwords</td><td>{m.weights.CREDENTIAL_EXPOSURE_OTHER}</td></tr>
            <tr><td>Security alert email in the last 30 / 90 / 365 days</td><td>{m.weights.ALERT_30D} / {m.weights.ALERT_90D} / {m.weights.ALERT_365D}</td></tr>
            <tr><td>Two-step verification known to be off</td><td>{m.weights.MFA_DISABLED}</td></tr>
            <tr><td>No mailbox activity for 2+ years (low confidence)</td><td>{m.weights.DORMANT}</td></tr>
            <tr><td>Service domain on a threat list</td><td>{m.weights.THREAT_LISTED}</td></tr>
          </tbody>
        </table>
        <p className="small">Impact multipliers: {Object.values(m.categoryImpact).map((c) => `${c.label} ×${c.multiplier}`).join(', ')}.</p>
        <p className="small">After a password change, the breach component is multiplied by {m.remediationMultipliers.user_reported} if you reported it, or {m.remediationMultipliers.verified} if the service’s own email confirmed it — but only if the change came after the breach. The breach record itself always stays. Two-step verification that’s on reduces the breach component (×{m.mfaDampening.mailbox_evidence} from email evidence, ×{m.mfaDampening.user_reported} if reported by you).</p>
        <h3>Overall score</h3>
        <p className="small">Accounts are sorted by score; the highest counts fully, the next half, the next a quarter and so on (×{m.aggregation.DECAY} each step), scaled by {m.aggregation.CORE_SCALE}, plus a small amount for the number of accounts ({m.aggregation.BREADTH_PER_LN} × ln(1 + accounts), at most {m.aggregation.BREADTH_CAP}). This keeps one serious problem visible without letting many small accounts dominate. Levels: {m.levels.map((l) => `${l.label} ≥ ${l.min}`).join(', ')}.</p>
        <p className="small">Critical findings (for example a breach that exposed passwords with no change recorded since) are listed separately, so they stay visible even when the overall score is moderate.</p>
      </section>
    </Shell>
  );
}
