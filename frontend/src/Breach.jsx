// Breach checks: explicit consent, provider disclosure, honest result wording.
import { useState } from 'react';
import { api } from './lib/api.js';
import { useAction, useResource } from './lib/hooks.js';
import { ErrorNote, Loading, Note, Time } from './components.jsx';

export function BreachConsent({ connectionId, compact = false, onChecked }) {
  const info = useResource('/breaches');
  const conns = useResource('/connections');
  const [result, setResult] = useState(null);
  const consent = useAction(async (granted) => {
    await api.post('/breaches/consent', { granted });
    await info.reload({ quiet: true });
  });
  const check = useAction(async (id, force = false) => {
    const r = await api.post(`/connections/${id}/breach-check`, { force });
    setResult({ id, ...r });
    await info.reload({ quiet: true });
    onChecked?.(r);
  });
  if (info.loading || conns.loading) return <Loading />;
  if (info.error) return <ErrorNote error={info.error} onRetry={info.reload} />;
  const provider = info.data.provider;
  const current = info.data.consent?.current;
  const active = (conns.data?.items || []).filter((c) => c.status === 'active' && (!connectionId || c.id === connectionId));
  const anyReal = active.some((c) => !c.is_synthetic);
  const lastCheck = (id) => info.data.checks.find((c) => c.connection_id === id);

  return (
    <div className="breach-consent">
      {!provider && anyReal && (
        <Note tone="warn" title="Breach checking is turned off on this server">
          <p>The administrator has not configured a breach-intelligence provider (BREACH_PROVIDER). Exposure will show as “Not checked”.</p>
        </Note>
      )}
      {provider && anyReal && (
        <div className="consent-box">
          <p>
            To check for breaches, FootprintX sends <strong>{provider.sends}</strong> to <strong>{provider.label}</strong>
            {provider.url ? <> (<a href={provider.url} target="_blank" rel="noopener noreferrer">{new URL(provider.url).hostname}</a>)</> : null}. No mail content is sent. Results show which breach datasets include your address — not whether your current password is known.
          </p>
          <label className="switch-row">
            <input type="checkbox" checked={!!current} disabled={consent.busy} onChange={(e) => consent.run(e.target.checked)} />
            <span>I agree to send my connected email addresses to {provider.label} for breach checks</span>
          </label>
          {info.data.consent?.granted_at && current && <p className="small">Agreed <Time value={info.data.consent.granted_at} />.</p>}
        </div>
      )}
      <ul className="plain-list">
        {active.map((c) => {
          const last = lastCheck(c.id);
          const canCheck = c.is_synthetic || (provider && current);
          return (
            <li key={c.id} className="breach-row">
              <div>
                <strong>{c.email_masked}</strong>
                {c.is_synthetic && <span className="tag tone-warn">Synthetic</span>}
                <p className="small">
                  {last ? (
                    last.status === 'ok' ? <>Checked <Time value={last.checked_at} /> with {last.provider === 'synthetic' ? 'the synthetic fixture' : last.provider}: {last.result_count} breach listing{last.result_count === 1 ? '' : 's'}.</> : <>Last check <Time value={last.checked_at} /> could not be completed ({last.error_code || last.status}). This is not a clean result.</>
                  ) : 'Not checked yet.'}
                </p>
              </div>
              <button className="btn small" disabled={!canCheck || check.busy} onClick={() => check.run(c.id, !!last)}>{check.busy ? 'Checking…' : last ? 'Check again' : 'Check now'}</button>
            </li>
          );
        })}
      </ul>
      {result && result.status === 'ok' && (
        <Note tone={result.breachCount ? 'warn' : 'info'}>
          {result.cached ? <p>This mailbox was checked recently (<Time value={result.checkedAt} />), so the saved result is shown.</p> : null}
          {result.breachCount ? (
            <p>Your address appears in {result.breachCount} breach listing{result.breachCount === 1 ? '' : 's'}. {result.added ? `${result.added} of them were for services not seen in your mailbox and were added to your accounts.` : ''}</p>
          ) : (
            !result.cached && <p>No breach listings were found by this provider today. That isn’t proof the address was never breached — providers only know about breaches that were reported to them.</p>
          )}
        </Note>
      )}
      {result && result.status === 'unavailable' && <Note tone="warn" title="The breach check could not be completed"><p>{result.message}</p></Note>}
      <ErrorNote error={check.error || consent.error} />
      {!compact && (
        <details className="limits">
          <summary>What a breach listing does and doesn’t mean</summary>
          <ul>{info.data.limitations.map((l) => <li key={l}>{l}</li>)}</ul>
        </details>
      )}
    </div>
  );
}
