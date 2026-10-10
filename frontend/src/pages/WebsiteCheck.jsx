import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Shell, PageHeader, Tag, ErrorNote, Note, Time } from '../components.jsx';
import { api } from '../lib/api.js';
import { useAction, useResource } from '../lib/hooks.js';
import { REPUTATION, REASON_CODE } from '../lib/labels.js';

function reasonText(r) {
  if (r.code === 'THREAT_LIST_MATCH') return `${r.matchType === 'parent_domain' ? `Its parent domain ${r.matchedHost} is` : 'Listed'} in ${r.sourceLabel}${r.threatType ? ` (${r.threatType})` : ''}${r.lastSeenAt ? `, last confirmed ${new Date(r.lastSeenAt).toLocaleDateString()}` : ''}.`;
  return r.message || REASON_CODE[r.code] || r.code;
}

export function WebsiteCheck() {
  const [domain, setDomain] = useState('');
  const [result, setResult] = useState(null);
  const ds = useResource('/reputation/dataset');
  const { run, busy, error } = useAction(async () => setResult(await api.post('/reputation/check', { domain })));
  const r = result && REPUTATION[result.status];
  return (
    <Shell>
      <PageHeader title="Check a website" intro="Look up whether a site is on FootprintX’s threat list or imitates a well-known brand. Only the domain name you type is sent to FootprintX — not the full address." />
      <form className="inline-form check-form" onSubmit={(e) => { e.preventDefault(); run(); }}>
        <label>Website address<input value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="example.com or a full link" required maxLength={2048} autoComplete="off" spellCheck={false} /></label>
        <button className="btn primary" disabled={busy}>{busy ? 'Checking…' : 'Check'}</button>
      </form>
      <ErrorNote error={error} />
      {result && (
        <section className={`section check-result tone-${r.tone}`} aria-live="polite">
          <h2><Tag tone={r.tone}>{r.label}</Tag> <span className="domain">{result.displayDomain}</span></h2>
          <p>{result.explanation}</p>
          {result.reasons.length > 0 && <ul className="checklist">{result.reasons.map((x, i) => <li key={i}>{reasonText(x)}</li>)}</ul>}
          {result.status === 'malicious' && <p><strong>Don’t sign in or enter payment details there.</strong> If you already did, change that password on the real site and turn on two-step verification.</p>}
          {result.status === 'suspicious' && <p>This isn’t on a threat list, but be careful: type the address of the real service yourself rather than following links.</p>}
          {result.dataset?.updatedAt && <p className="small">Threat data updated <Time value={result.dataset.updatedAt} />.</p>}
        </section>
      )}
      {ds.data && !ds.data.usable && <Note tone="warn" title="Threat data isn’t available"><p>{ds.data.reason === 'DATASET_STALE' ? 'The threat dataset is out of date, so results will say “not enough information” instead of giving a clean result.' : 'No threat dataset has been loaded on this server yet, so results will say “not enough information”.'}</p></Note>}
      <section className="section">
        <h2>Want this automatically?</h2>
        <p>With Premium, the FootprintX browser extension checks each site you open and warns you about known threats — without sending the sites you visit to FootprintX. <Link to="/premium">About Premium</Link></p>
      </section>
    </Shell>
  );
}
