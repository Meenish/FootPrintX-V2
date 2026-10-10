import { useState } from 'react';
import { Shell, PageHeader, ErrorNote, Note } from '../components.jsx';
import { useConfig } from '../lib/auth.jsx';
import { useAction } from '../lib/hooks.js';
import { api } from '../lib/api.js';

export function Contact() {
  const config = useConfig();
  const [form, setForm] = useState({ name: '', email: '', message: '' });
  const [sent, setSent] = useState(null);
  const action = useAction(async () => { setSent(await api.post('/contact', form)); setForm({ name: '', email: '', message: '' }); });
  return <Shell>
    <PageHeader title="Contact us" intro="Send the FootprintX team a question or report a problem." />
    <p>Please do not include passwords, one-time codes, recovery codes, or private mailbox contents.</p>
    {!config?.contactConfigured && <Note tone="warn"><p>Contact delivery is not configured on this server.</p></Note>}
    {sent && <Note tone="good"><p>{sent.message}</p><p>Reference: {sent.id}</p></Note>}
    <form className="form" onSubmit={(e) => { e.preventDefault(); setSent(null); action.run(); }}>
      <label>Name<input required maxLength={100} autoComplete="name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></label>
      <label>Reply email<input required type="email" maxLength={254} autoComplete="email" value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></label>
      <label>Message<textarea required minLength={10} maxLength={5000} rows={7} value={form.message} onChange={(e) => setForm({ ...form, message: e.target.value })} /></label>
      <ErrorNote error={action.error} />
      <button className="btn primary" disabled={action.busy || !config?.contactConfigured}>{action.busy ? 'Sending…' : 'Send message'}</button>
      <p className="small">Submitted messages are encrypted in FootprintX and retained for 90 days. Email is delivered through the configured mail service.</p>
    </form>
  </Shell>;
}
