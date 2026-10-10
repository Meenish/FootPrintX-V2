import { useCallback, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { Shell, PageHeader, Note } from '../components.jsx';
import { ConnectMailbox, PermissionExplainer, ScanProgress } from '../Mailbox.jsx';
import { BreachConsent } from '../Breach.jsx';
import { useConfig } from '../lib/auth.jsx';
import { useResource } from '../lib/hooks.js';

export function Onboarding() {
  const config = useConfig();
  const nav = useNavigate();
  const conns = useResource('/connections');
  const [jobId, setJobId] = useState(null);
  const [connectionId, setConnectionId] = useState(null);
  const [done, setDone] = useState(false);
  const onFinished = useCallback(() => setDone(true), []);
  const existing = conns.data?.items?.filter((c) => c.status === 'active') || [];
  const step = jobId ? (done ? 3 : 2) : 1;
  return (
    <Shell>
      <PageHeader title="Set up FootprintX" intro="Three steps: connect a mailbox, let FootprintX scan it, and optionally check it against known breaches." />
      <ol className="onboarding-steps" aria-label="Setup progress">
        {['Connect a mailbox', 'Scan', 'Check for breaches'].map((label, i) => (
          <li key={label} aria-current={step === i + 1 ? 'step' : undefined} className={step > i + 1 ? 'done' : step === i + 1 ? 'current' : ''}>{label}</li>
        ))}
      </ol>
      {step === 1 && (
        <section className="section">
          {existing.length > 0 && (
            <Note tone="info"><p>You already have {existing.length} connected mailbox{existing.length > 1 ? 'es' : ''}. <Link to="/dashboard">Go to your overview</Link> or connect another one.</p></Note>
          )}
          <PermissionExplainer scopeMode={config?.gmailScopeMode} />
          <ConnectMailbox onConnected={(r) => { setJobId(r.scanJob.id); setConnectionId(r.connectionId); }} />
        </section>
      )}
      {step >= 2 && (
        <section className="section">
          <h2>Scanning your mailbox</h2>
          <ScanProgress jobId={jobId} onFinished={onFinished} />
        </section>
      )}
      {step === 3 && (
        <section className="section">
          <h2>Check for known breaches (optional)</h2>
          <BreachConsent connectionId={connectionId} compact />
          <button className="btn primary" onClick={() => nav('/dashboard')}>Go to my overview</button>
        </section>
      )}
    </Shell>
  );
}
