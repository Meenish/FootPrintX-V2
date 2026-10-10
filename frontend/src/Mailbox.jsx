// Mailbox connection and scan progress, shared by onboarding and Settings.
import { useEffect, useState } from 'react';
import { api } from './lib/api.js';
import { useAction } from './lib/hooks.js';
import { useConfig } from './lib/auth.jsx';
import { SCAN_STATUS, relative } from './lib/labels.js';
import { ErrorNote, Note, Tag } from './components.jsx';

export function PermissionExplainer({ scopeMode = 'metadata' }) {
  return (
    <div className="explainer">
      <h3>What connecting Gmail allows</h3>
      <ul className="checklist">
        {scopeMode === 'metadata' ? (
          <li>Read-only access to message <strong>headers</strong> (sender, subject, date). Google’s “metadata” permission does not allow reading message bodies or attachments at all.</li>
        ) : (
          <li>Read-only access used to <strong>search</strong> for account emails. FootprintX requests only headers and Google’s short preview, never bodies or attachments.</li>
        )}
        <li>Subjects are classified in memory (for example “sign-up” or “security alert”) and then discarded. Only the service name, the kind of email and its date are stored.</li>
        <li>FootprintX cannot send, delete or change email, and never sees your Gmail password.</li>
      </ul>
      <h3>Limits</h3>
      <ul className="checklist muted-list">
        {scopeMode === 'metadata' && <li>With headers-only access, Gmail does not allow searching, so FootprintX reads your most recent messages (up to the server’s scan limit). Very old sign-ups may be missed.</li>}
        <li>Services that never emailed this address can’t be discovered from it. You can add accounts yourself.</li>
      </ul>
      <p className="small">You can disconnect at any time; FootprintX then revokes its access with Google and deletes the stored authorization.</p>
    </div>
  );
}

export function ConnectMailbox({ onConnected }) {
  const config = useConfig();
  const start = useAction(async () => {
    const r = await api.post('/connections/google/start', {});
    window.location.assign(r.url);
  });
  const synthetic = useAction(async () => {
    const r = await api.post('/connections/synthetic', {});
    onConnected?.(r);
  });
  if (!config) return null;
  return (
    <div className="connect">
      {config.googleConfigured ? (
        <button className="btn primary" onClick={() => start.run()} disabled={start.busy}>{start.busy ? 'Opening Google…' : 'Connect a Gmail account'}</button>
      ) : (
        <Note tone="warn" title="Gmail connection isn’t set up on this server">
          <p>An administrator needs to add Google OAuth credentials (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET). See docs/PROVIDERS.md.</p>
        </Note>
      )}
      {config.syntheticDataEnabled && (
        <div className="synthetic-option">
          <p className="small">Development server: you can use a labelled synthetic mailbox to try FootprintX without a real inbox. Results will be marked “Synthetic”.</p>
          <button className="btn ghost" onClick={() => synthetic.run()} disabled={synthetic.busy}>{synthetic.busy ? 'Connecting…' : 'Use the synthetic test mailbox'}</button>
        </div>
      )}
      <ErrorNote error={start.error || synthetic.error} />
    </div>
  );
}

const TERMINAL = new Set(['completed', 'partial', 'failed', 'cancelled']);

/** Live scan progress. Numbers come from the job record (real work done). */
export function ScanProgress({ jobId, onFinished }) {
  const [job, setJob] = useState(null);
  const [error, setError] = useState(null);
  useEffect(() => {
    if (!jobId) return undefined;
    let stop = false;
    let timer;
    const tick = async () => {
      try {
        const j = await api.get(`/scans/${jobId}`);
        if (stop) return;
        setJob(j);
        setError(null);
        if (TERMINAL.has(j.status)) onFinished?.(j);
        else timer = setTimeout(tick, 1500);
      } catch (e) {
        if (!stop) {
          setError(e);
          timer = setTimeout(tick, 4000);
        }
      }
    };
    tick();
    return () => {
      stop = true;
      clearTimeout(timer);
    };
  }, [jobId, onFinished]);
  const cancel = useAction(async () => setJob(await api.post(`/scans/${jobId}/cancel`, {})));
  if (!job) return error ? <ErrorNote error={error} /> : <p role="status">Starting scan…</p>;
  const s = SCAN_STATUS[job.status];
  const p = job.progress || {};
  const pct = p.messagesListed ? Math.min(100, Math.round(((p.messagesProcessed + (p.messagesFailed || 0)) / p.messagesListed) * 100)) : null;
  const active = !TERMINAL.has(job.status);
  return (
    <div className="scan-progress" aria-live="polite">
      <div className="scan-progress-head">
        <Tag tone={s.tone}>{s.label}</Tag>
        <span className="small">{job.stage}</span>
      </div>
      {active && (
        <div className="progressbar" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={pct ?? undefined} aria-valuetext={pct == null ? 'Waiting for the mailbox listing' : `${pct}% of listed messages read`}>
          <span style={{ width: `${pct ?? 0}%` }} className={pct == null ? 'indeterminate' : ''} />
        </div>
      )}
      <p className="small">
        {p.messagesProcessed || 0} of {p.messagesListed || 0} messages read
        {p.messagesFailed ? `, ${p.messagesFailed} could not be read` : ''} · {p.servicesSeen || 0} services seen so far
      </p>
      {job.status === 'partial' && (
        <Note tone="warn" title="Some sources could not be read">
          <p>Results from the parts that worked were saved. {job.error_message || ''}</p>
          <ul>{(job.source_results || []).filter((r) => r.status !== 'ok').map((r) => <li key={r.source}>{r.source.replace(/_/g, ' ')}: {r.status}{r.error ? ` (${r.error})` : ''}</li>)}</ul>
        </Note>
      )}
      {job.status === 'failed' && <Note tone="bad"><p>{job.error_message || 'The scan failed.'}</p></Note>}
      {job.status === 'queued' && job.error_code && <Note tone="warn"><p>{job.error_message} Retrying automatically.</p></Note>}
      {job.summary && TERMINAL.has(job.status) && (
        <p>Found <strong>{job.summary.confirmed}</strong> confirmed account{job.summary.confirmed === 1 ? '' : 's'}{job.summary.possible ? ` and ${job.summary.possible} possible association${job.summary.possible === 1 ? '' : 's'}` : ''}.</p>
      )}
      {active && <button className="btn ghost small" onClick={() => cancel.run()} disabled={cancel.busy}>Cancel scan</button>}
    </div>
  );
}

export function LastScanLine({ scan }) {
  if (!scan) return <span className="muted">Not scanned yet</span>;
  const s = SCAN_STATUS[scan.status];
  return (
    <span>
      <Tag tone={s.tone}>{s.label}</Tag> <span className="small">{relative(scan.finished_at || scan.created_at)}</span>
    </span>
  );
}
