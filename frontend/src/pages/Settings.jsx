import { useCallback, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { Shell, PageHeader, Tag, Loading, ErrorNote, Empty, Time, Note, ConfirmDialog, useToast } from '../components.jsx';
import { ConnectMailbox, LastScanLine, PermissionExplainer, ScanProgress } from '../Mailbox.jsx';
import { BreachConsent } from '../Breach.jsx';
import { api, download } from '../lib/api.js';
import { useAction, useResource } from '../lib/hooks.js';
import { useAuth, useConfig } from '../lib/auth.jsx';
import { formatDate } from '../lib/labels.js';

const TABS = { connections: 'Mailboxes', notifications: 'Notifications', extension: 'Browser extension', security: 'Sign-in & security', privacy: 'Privacy & data' };
const OAUTH_ERRORS = {
  OAUTH_STATE_INVALID: 'The authorization link expired or was already used. Please try again.',
  OAUTH_USER_MISMATCH: 'That authorization was started from a different FootprintX account.',
  SCOPE_MISSING: 'Google didn’t grant the permission FootprintX needs, so nothing was connected.',
  NO_REFRESH_TOKEN: 'Google didn’t grant ongoing access. Please try again and approve access.',
};

export function Settings() {
  const [params, setParams] = useSearchParams();
  const tab = TABS[params.get('tab')] ? params.get('tab') : 'connections';
  return (
    <Shell>
      <PageHeader title="Settings" />
      <div className="tabs" role="tablist" aria-label="Settings sections">
        {Object.entries(TABS).map(([k, label]) => (
          <button key={k} role="tab" aria-selected={tab === k} className={`tab ${tab === k ? 'active' : ''}`} onClick={() => setParams({ tab: k })}>{label}</button>
        ))}
      </div>
      {tab === 'connections' && <Connections params={params} />}
      {tab === 'notifications' && <Notifications />}
      {tab === 'extension' && <Extension />}
      {tab === 'security' && <Security />}
      {tab === 'privacy' && <Privacy />}
    </Shell>
  );
}

function Connections({ params }) {
  const config = useConfig();
  const { data, error, loading, reload } = useResource('/connections', { pollMs: 10000 });
  const [scanJob, setScanJob] = useState(params.get('scan'));
  const [disconnecting, setDisconnecting] = useState(null);
  const [deleteFindings, setDeleteFindings] = useState(false);
  const { toast, show } = useToast();
  const onFinished = useCallback(() => reload({ quiet: true }), [reload]);
  const scan = useAction(async (id) => {
    const r = await api.post(`/connections/${id}/scan`, {});
    setScanJob(r.job.id);
  });
  const disconnect = useAction(async () => {
    const r = await api.post(`/connections/${disconnecting.id}/disconnect`, { deleteFindings });
    setDisconnecting(null);
    show(r.revokeResult === 'revoked' ? 'Disconnected. Google access was revoked.' : r.revokeResult === 'failed' ? 'Disconnected. FootprintX deleted its access, but Google could not be reached to revoke it — you can also remove it at myaccount.google.com/permissions.' : 'Disconnected.');
    reload({ quiet: true });
  });
  const remove = useAction(async (id) => {
    await api.del(`/connections/${id}`);
    reload({ quiet: true });
  });
  const oauth = params.get('oauth');
  return (
    <>
      {toast}
      {oauth === 'connected' && <Note tone="good"><p>Mailbox connected. The first scan has started.</p></Note>}
      {oauth === 'denied' && <Note tone="info"><p>You didn’t grant access, so no mailbox was connected.</p></Note>}
      {oauth === 'error' && <Note tone="bad"><p>{OAUTH_ERRORS[params.get('reason')] || 'Connecting the mailbox failed. Please try again.'}</p></Note>}
      {scanJob && <section className="section"><h2>Scan progress</h2><ScanProgress jobId={scanJob} onFinished={onFinished} /></section>}
      <section className="section">
        <h2>Connected mailboxes</h2>
        {loading ? <Loading /> : error ? <ErrorNote error={error} onRetry={reload} /> : data.items.length ? (
          <ul className="plain-list">
            {data.items.map((c) => (
              <li key={c.id} className="conn-row">
                <div>
                  <strong>{c.email_masked}</strong> {c.is_synthetic && <Tag tone="warn">Synthetic</Tag>}
                  <p className="small">
                    {c.provider === 'gmail' ? `Gmail · ${c.scope_mode === 'metadata' ? 'headers only, read-only' : 'read-only search'}` : 'Synthetic test mailbox'} · connected {formatDate(c.connected_at)}
                    {c.status === 'disconnected' && ` · disconnected ${formatDate(c.disconnected_at)}${c.token_revoke_result === 'revoked' ? ', Google access revoked' : ''}`}
                  </p>
                  {c.status === 'active' && <p className="small">Last scan: <LastScanLine scan={c.latestScan} /></p>}
                </div>
                <div className="row-actions">
                  {c.status === 'active' && <button className="btn small" onClick={() => scan.run(c.id)} disabled={scan.busy}>Scan now</button>}
                  {c.status === 'reauth_required' && <Tag tone="warn">Reconnect needed</Tag>}
                  {c.status !== 'disconnected' && <button className="btn small ghost" onClick={() => { setDeleteFindings(false); setDisconnecting(c); }}>Disconnect</button>}
                  {c.status === 'disconnected' && <button className="btn small danger" onClick={() => remove.run(c.id)}>Delete with its findings</button>}
                </div>
              </li>
            ))}
          </ul>
        ) : <Empty title="No mailbox connected yet" />}
        <ErrorNote error={scan.error || remove.error} />
      </section>
      <section className="section">
        <h2>Add a mailbox</h2>
        <p className="small">You can connect several Gmail addresses; each has its own permission and can be disconnected separately. Reconnecting an address that needs it uses the same button.</p>
        <PermissionExplainer scopeMode={config?.gmailScopeMode} />
        <ConnectMailbox onConnected={(r) => { setScanJob(r.scanJob.id); reload({ quiet: true }); }} />
      </section>
      <section className="section">
        <h2>Breach checks</h2>
        <BreachConsent />
      </section>
      <ConfirmDialog
        open={!!disconnecting}
        title={`Disconnect ${disconnecting?.email_masked || ''}?`}
        confirmLabel="Disconnect"
        busy={disconnect.busy}
        onCancel={() => setDisconnecting(null)}
        onConfirm={() => disconnect.run()}
      >
        <p>FootprintX will stop scanning this mailbox, revoke its access with Google and delete the stored authorization.</p>
        <label className="switch-row"><input type="checkbox" checked={deleteFindings} onChange={(e) => setDeleteFindings(e.target.checked)} /><span>Also delete the accounts and breach results found through this mailbox</span></label>
        {!deleteFindings && <p className="small">Otherwise they stay in your inventory as history; you can delete them later.</p>}
        <ErrorNote error={disconnect.error} />
      </ConfirmDialog>
    </>
  );
}

const PREFS = [
  ['security_alerts_email', 'Important security alerts', 'High-severity findings, such as a breach that exposed your password. At most a few per day; each finding is sent once.'],
  ['remediation_reminders_email', 'Reminders', 'A weekly nudge about steps you marked as in progress.'],
  ['periodic_summary_email', 'Weekly summary', 'Your score and open items, once a week.'],
  ['product_updates_email', 'Product updates', 'Occasional news about FootprintX features.'],
];

function Notifications() {
  const { data, error, loading, reload } = useResource('/notifications/preferences');
  const deliveries = useResource('/notifications/deliveries');
  const save = useAction(async (key, value) => {
    await api.patch('/notifications/preferences', { [key]: value });
    reload({ quiet: true });
  });
  if (loading) return <Loading />;
  if (error) return <ErrorNote error={error} onRetry={reload} />;
  return (
    <>
      <section className="section">
        <h2>Email notifications</h2>
        {!data.emailDeliveryConfigured && <Note tone="warn"><p>Email delivery isn’t configured on this server, so no emails will be sent. In-app alerts still work.</p></Note>}
        <p className="small">In-app alerts always appear in FootprintX, and the browser extension’s warnings work regardless of these settings. A routine scan never sends an email.</p>
        <ul className="plain-list">
          {PREFS.map(([key, label, desc]) => (
            <li key={key} className="pref-row">
              <label className="switch-row"><input type="checkbox" checked={!!data.preferences[key]} disabled={save.busy} onChange={(e) => save.run(key, e.target.checked)} /><span><strong>{label}</strong><br /><span className="small">{desc}</span></span></label>
            </li>
          ))}
        </ul>
        <p className="small">{data.essentialNote}</p>
        <ErrorNote error={save.error} />
      </section>
      <section className="section">
        <h2>Recent email delivery</h2>
        {deliveries.data?.items?.length ? (
          <table className="table compact">
            <thead><tr><th scope="col">When</th><th scope="col">Type</th><th scope="col">Result</th></tr></thead>
            <tbody>{deliveries.data.items.map((d, i) => <tr key={i}><td><Time value={d.created_at} /></td><td>{d.category.replace(/_/g, ' ')}</td><td>{d.status}{d.reason ? ` (${d.reason.replace(/_/g, ' ')})` : ''}</td></tr>)}</tbody>
          </table>
        ) : <p className="muted">No emails yet.</p>}
      </section>
    </>
  );
}

const BROWSER_STEPS = {
  chromium: [
    'Unzip the downloaded file to a folder you can keep — the browser loads it from that folder, so deleting it removes the extension.',
    'Open chrome://extensions (or edge://extensions) and turn on Developer mode.',
    'Choose "Load unpacked" and select the unzipped folder.',
  ],
  firefox: [
    'Open about:debugging#/runtime/this-firefox.',
    'Choose "Load Temporary Add-on" and select the downloaded .zip file.',
    'Firefox removes temporary add-ons when it restarts; a signed build is needed for a permanent install.',
  ],
};

function ExtensionDownload() {
  const pkg = useResource('/extension/package');
  const [target, setTarget] = useState('chromium');
  const get = useAction(() => download(`/extension/package/${target}`, `footprintx-${target}.zip`));
  if (pkg.loading) return <Loading />;
  const info = pkg.data?.targets?.[target];
  return (
    <section className="section">
      <h2>1. Get the extension</h2>
      <p className="small">
        FootprintX is not in any browser store yet, so this is a developer build that you load yourself.
        It is built for this server ({pkg.data?.apiBase}), so it talks to your own FootprintX and nothing else.
      </p>
      <div className="field">
        <label htmlFor="ext-target">Your browser</label>
        <select id="ext-target" value={target} onChange={(e) => setTarget(e.target.value)}>
          {Object.entries(pkg.data?.targets || {}).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
        </select>
      </div>
      <button className="btn primary" onClick={() => get.run()} disabled={get.busy || !info?.available}>
        {get.busy ? 'Preparing…' : `Download for ${target === 'firefox' ? 'Firefox' : 'Chrome / Edge'}`}
      </button>
      {info && !info.prebuilt && <p className="small muted">The package is built on request the first time, which can take a few seconds.</p>}
      {info && !info.available && <Note tone="warn"><p>No package has been built on this server. Run <code>npm run build -w extension -- --zip</code> and reload.</p></Note>}
      <ErrorNote error={get.error} />
      <h3>Then install it</h3>
      <ol className="steps-inline">
        {BROWSER_STEPS[target].map((s) => <li key={s}>{s}</li>)}
      </ol>
    </section>
  );
}

function Extension() {
  const auth = useAuth();
  const devices = useResource('/extension/devices');
  const [code, setCode] = useState(null);
  const create = useAction(async () => setCode(await api.post('/extension/link-codes', {})));
  const unlink = useAction(async (id) => {
    await api.del(`/extension/devices/${id}`);
    devices.reload({ quiet: true });
  });
  const premium = auth.entitlement?.plan === 'premium';
  return (
    <>
      <ExtensionDownload />
      <section className="section">
        <h2>2. Link it to your account</h2>
        {!premium && <Note tone="info"><p>Linking works on Free so you can check sites on demand from the extension. Automatic checks of every site you open need Premium.</p></Note>}
        <ol className="steps-inline">
          <li>Create a one-time code here. It expires in 10 minutes.</li>
          <li>Open the extension’s settings (right-click its toolbar icon → Options) and enter the code.</li>
          <li>Your FootprintX password is never typed into the extension.</li>
        </ol>
        {code ? (
          <p className="link-code" aria-live="polite">Your code: <strong>{code.code}</strong> <span className="small">expires {formatDate(code.expiresAt, { time: true })}</span></p>
        ) : null}
        <button className="btn primary" onClick={() => create.run()} disabled={create.busy}>{code ? 'Create a new code' : 'Create link code'}</button>
        <ErrorNote error={create.error} />
      </section>
      <section className="section">
        <h2>Linked browsers</h2>
        {devices.loading ? <Loading /> : devices.data?.items?.length ? (
          <ul className="plain-list">
            {devices.data.items.map((d) => (
              <li key={d.id} className="kv-row">
                <span>{d.label} <span className="small">linked {formatDate(d.created_at)} · last seen <Time value={d.last_seen_at} /> · event sharing {d.extension_sync_enabled ? 'on' : 'off'}</span></span>
                <button className="btn small ghost" onClick={() => unlink.run(d.id)}>Unlink</button>
              </li>
            ))}
          </ul>
        ) : <Empty title="No browsers linked" />}
      </section>
      <section className="section">
        <h2>What the extension does with your browsing</h2>
        <ul className="checklist">
          <li>Reputation checks send the first 8 characters of domain hashes and compare the returned matches on your device.</li>
          <li>It never reads page content, form fields, passwords or cookies, and has no access to the sites themselves.</li>
          <li>Account awareness sends only the hostname to check your inventory; this lookup is not stored as browsing history. It cannot determine your current website login.</li>
          <li>Clean reputation results are cached locally for six hours; known threats can remain for seven days during an outage. Paths and queries are never uploaded.</li>
          <li>If you turn on event sharing in the extension, only warnings (known threat, suspicious site, site later flagged) are sent, with the domain name and time.</li>
        </ul>
      </section>
    </>
  );
}

function Security() {
  const sessions = useResource('/auth/sessions');
  const [form, setForm] = useState({ currentPassword: '', newPassword: '' });
  const { toast, show } = useToast();
  const change = useAction(async () => {
    await api.post('/auth/password/change', form);
    setForm({ currentPassword: '', newPassword: '' });
    show('Password changed. Other sessions were signed out.');
    sessions.reload({ quiet: true });
  });
  const revoke = useAction(async (id) => {
    await api.del(`/auth/sessions/${id}`);
    sessions.reload({ quiet: true });
  });
  return (
    <>
      {toast}
      <section className="section">
        <h2>Change your FootprintX password</h2>
        <form className="form narrow" onSubmit={(e) => { e.preventDefault(); change.run(); }}>
          <label>Current password<input type="password" autoComplete="current-password" required value={form.currentPassword} onChange={(e) => setForm({ ...form, currentPassword: e.target.value })} /></label>
          <label>New password<input type="password" autoComplete="new-password" minLength={12} maxLength={128} required value={form.newPassword} onChange={(e) => setForm({ ...form, newPassword: e.target.value })} /></label>
          <ErrorNote error={change.error} />
          <button className="btn primary" disabled={change.busy}>{change.busy ? 'Saving…' : 'Change password'}</button>
        </form>
      </section>
      <section className="section">
        <h2>Where you’re signed in</h2>
        {sessions.loading ? <Loading /> : (
          <ul className="plain-list">
            {(sessions.data?.items || []).map((s) => (
              <li key={s.id} className="kv-row">
                <span>{s.kind === 'extension' ? 'Browser extension' : 'Web'} · {s.label || 'Unknown device'} {s.current && <Tag tone="good">This session</Tag>}<span className="small"> · signed in {formatDate(s.created_at)} · last active <Time value={s.last_seen_at} /></span></span>
                {!s.current && <button className="btn small ghost" onClick={() => revoke.run(s.id)}>Sign out</button>}
              </li>
            ))}
          </ul>
        )}
      </section>
    </>
  );
}

function Privacy() {
  const auth = useAuth();
  const nav = useNavigate();
  const retention = useResource('/privacy/retention');
  const [confirm, setConfirm] = useState(false);
  const [password, setPassword] = useState('');
  const exp = useAction(() => download('/privacy/export', 'footprintx-export.json'));
  const del = useAction(async () => {
    await api.del('/account', { password, confirm: 'DELETE' });
    await auth.refresh();
    nav('/', { replace: true });
  });
  const r = retention.data?.retentionDays;
  return (
    <>
      <section className="section">
        <h2>What FootprintX stores</h2>
        <ul className="checklist">
          <li>Your FootprintX account (email, name, a hashed password).</li>
          <li>For each connected mailbox: the address (encrypted) and Google’s authorization (encrypted, deleted when you disconnect).</li>
          <li>Discovered services with the kind and date of each piece of evidence — never message subjects, bodies or attachments.</li>
          <li>Breach listings for your addresses, your risk scores over time, recommendations and what you did about them.</li>
          <li>Security alerts, email delivery outcomes (not content), and warnings the browser extension shared if you turned that on.</li>
        </ul>
        <h3>Who else receives data</h3>
        <ul className="checklist">
          <li>Google: only through the read-only permission you grant.</li>
          <li>The breach provider shown in Mailboxes, only if you consent: your email address.</li>
          <li>Threat lists are downloaded to FootprintX; nothing about you is sent to them.</li>
          <li>FootprintX does not sell data or use it for advertising.</li>
        </ul>
        {r && <p className="small">Retention: extension events {r.extensionEventsDays} days, website checks {r.domainChecksDays} days, scan records {r.scanJobsDays} days, audit log {r.auditEventsDays} days. Everything else is kept until you delete it or your account.</p>}
      </section>
      <section className="section">
        <h2>Download your data</h2>
        <p className="small">A JSON file with everything FootprintX holds about you, excluding secrets such as encrypted tokens.</p>
        <button className="btn" onClick={() => exp.run()} disabled={exp.busy}>{exp.busy ? 'Preparing…' : 'Download my data'}</button>
        <ErrorNote error={exp.error} />
      </section>
      <section className="section danger-zone">
        <h2>Delete your FootprintX account</h2>
        <p>This revokes Google access for every connected mailbox, then permanently deletes your accounts, findings, history, settings and linked browsers. It does not affect your accounts at other services.</p>
        <p className="small">Data is removed from the live database immediately. Backups expire on the documented backup schedule.</p>
        <button className="btn danger" onClick={() => setConfirm(true)}>Delete my account</button>
      </section>
      <ConfirmDialog open={confirm} title="Delete your FootprintX account?" confirmLabel="Delete permanently" busy={del.busy} onCancel={() => setConfirm(false)} onConfirm={() => del.run()}>
        <p>This can’t be undone. Enter your FootprintX password to confirm.</p>
        <label>Password<input type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} /></label>
        <ErrorNote error={del.error} />
      </ConfirmDialog>
    </>
  );
}
