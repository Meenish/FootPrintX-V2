import { useState } from 'react';
import { Link, Navigate, useNavigate, useSearchParams } from 'react-router-dom';
import { Logo, Note, ErrorNote } from '../components.jsx';
import { useAuth, useConfig } from '../lib/auth.jsx';
import { api } from '../lib/api.js';
import { useAction } from '../lib/hooks.js';

function PublicNav() {
  const auth = useAuth();
  return (
    <header className="public-nav">
      <Logo />
      <nav aria-label="Account">
        {auth.status === 'signed_in' ? (
          <Link className="btn primary small" to="/dashboard">Open dashboard</Link>
        ) : (
          <>
            <Link className="textlink" to="/login">Sign in</Link>
            <Link className="btn primary small" to="/register">Create account</Link>
          </>
        )}
      </nav>
    </header>
  );
}

const WORKFLOW = [
  ['Discover', 'Connect Gmail with read-only, headers-only permission. FootprintX looks for sign-up, password and security emails from online services.'],
  ['Assess', 'Each account is scored from the evidence: breach listings, recent security alerts, two-step verification status. Unknowns stay visible.'],
  ['Secure', 'You get specific next steps with links to the official settings pages, and FootprintX confirms changes when the service emails you about them.'],
  ['Monitor', 'Rescans and breach checks keep the picture current. With Premium, the browser extension warns you about known threat sites.'],
];

export function Landing() {
  const config = useConfig();
  const price = config?.billing?.premium;
  return (
    <div className="public">
      <PublicNav />
      <main id="main">
        <section className="hero">
          <h1>Secure your digital past.<br />Protect your online future.</h1>
          <p className="hero-lede">Your inbox remembers every service you ever signed up for. FootprintX reads only the evidence of those accounts, shows which ones put you at risk, and walks you through fixing them.</p>
          <div className="hero-actions">
            <Link className="btn primary" to="/register">Create a free account</Link>
            <Link className="btn ghost" to="/login">Sign in</Link>
          </div>
          <div className="hero-sample">
            <p className="sample-label">Example finding</p>
            <div className="sample-row">
              <span className="sample-service">Adobe</span>
              <span className="tag tone-bad">Password exposed in a 2013 breach</span>
            </div>
            <p className="sample-evidence">Evidence: a 2017 welcome email from adobe.com (sender verified) and a breach listing for your address.</p>
            <p className="sample-step">Next step: change the password on account.adobe.com, then turn on two-step verification.</p>
          </div>
        </section>

        <section className="workflow" aria-labelledby="how-h">
          <h2 id="how-h">How it works</h2>
          <ol className="steps">
            {WORKFLOW.map(([t, d]) => (
              <li key={t}><h3>{t}</h3><p>{d}</p></li>
            ))}
          </ol>
        </section>

        <section className="honesty" aria-labelledby="honest-h">
          <h2 id="honest-h">What FootprintX can and can’t see</h2>
          <div className="two-col">
            <div>
              <h3>It reads</h3>
              <ul>
                <li>Sender, subject and date of messages in a mailbox you connect (subjects are classified in memory and discarded).</li>
                <li>Breach listings for your address, only after you agree to send it to the breach provider.</li>
                <li>With the browser extension: short hashes for threat checks and normalized domains for account-inventory matching. Paths, queries and page contents are never sent.</li>
              </ul>
            </div>
            <div>
              <h3>It never</h3>
              <ul>
                <li>Asks for or stores your email or website passwords, one-time codes or recovery codes.</li>
                <li>Changes anything in your other accounts. You make every change on the official site.</li>
                <li>Claims to find every account or every threat. Services that never email you can’t be discovered this way.</li>
              </ul>
            </div>
          </div>
        </section>

        <section className="plans-preview" aria-labelledby="plans-h">
          <h2 id="plans-h">Free covers your existing risk. Premium watches ahead.</h2>
          <div className="two-col">
            <div className="plan-box">
              <h3>Free</h3>
              <p>Unlimited mailboxes and scans, account inventory, breach checks, risk score, recommendations, verification and history.</p>
            </div>
            <div className="plan-box plan-box-premium">
              <h3>Premium{price ? ` · ${price.display}` : ''}{price?.priceStatus === 'proposed' ? ' (proposed price)' : ''}</h3>
              <p>Everything in Free, plus the browser extension’s automatic warnings for known threat sites, alerts when new threat intelligence affects you, and a year of security history.</p>
            </div>
          </div>
        </section>
      </main>
      <footer className="public-foot">
        <Link to="/contact">Contact us</Link>
        <p>FootprintX is an evidence-based tool. Its risk score is FootprintX’s own index, not an industry standard.</p>
      </footer>
    </div>
  );
}

function AuthFrame({ title, children, footer }) {
  return (
    <div className="public auth-page">
      <PublicNav />
      <main id="main" className="auth-main">
        <h1>{title}</h1>
        {children}
        {footer && <div className="auth-foot">{footer}</div>}
      </main>
    </div>
  );
}

const safeNext = (n) => (n && n.startsWith('/') && !n.startsWith('//') ? n : '/dashboard');

export function Login() {
  const auth = useAuth();
  const nav = useNavigate();
  const [params] = useSearchParams();
  const [form, setForm] = useState({ email: '', password: '' });
  const { run, busy, error } = useAction(async () => {
    await auth.login(form.email, form.password);
    nav(safeNext(params.get('next')), { replace: true });
  });
  if (auth.status === 'signed_in') return <Navigate to={safeNext(params.get('next'))} replace />;
  return (
    <AuthFrame title="Sign in" footer={<p>New here? <Link to="/register">Create an account</Link></p>}>
      <form className="form" onSubmit={(e) => { e.preventDefault(); run(); }}>
        <label>Email<input type="email" autoComplete="email" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></label>
        <label>Password<input type="password" autoComplete="current-password" required value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} /></label>
        <ErrorNote error={error} />
        <button className="btn primary" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
        <Link to="/forgot-password" className="textlink">Forgot your password?</Link>
      </form>
    </AuthFrame>
  );
}

export function Register() {
  const auth = useAuth();
  const nav = useNavigate();
  const [form, setForm] = useState({ email: '', password: '', displayName: '' });
  const { run, busy, error } = useAction(async () => {
    await auth.register(form.email, form.password, form.displayName);
    nav('/onboarding', { replace: true });
  });
  // Signed-in users (including right after registering) continue to setup.
  if (auth.status === 'signed_in') return <Navigate to="/onboarding" replace />;
  const tooShort = form.password.length > 0 && form.password.length < 12;
  return (
    <AuthFrame title="Create your account" footer={<p>Already have an account? <Link to="/login">Sign in</Link></p>}>
      <p className="lede">This is your FootprintX password. It is separate from your email account — FootprintX never asks for your Gmail password.</p>
      <form className="form" onSubmit={(e) => { e.preventDefault(); run(); }}>
        <label>Name (optional)<input autoComplete="name" maxLength={60} value={form.displayName} onChange={(e) => setForm({ ...form, displayName: e.target.value })} /></label>
        <label>Email<input type="email" autoComplete="email" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} /></label>
        <label>
          Password
          <input type="password" autoComplete="new-password" required minLength={12} maxLength={128} aria-describedby="pw-help" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
          <span id="pw-help" className={`hint ${tooShort ? 'hint-bad' : ''}`}>At least 12 characters. A short phrase is easier to remember than symbols.</span>
        </label>
        <ErrorNote error={error} />
        <button className="btn primary" disabled={busy}>{busy ? 'Creating account…' : 'Create account'}</button>
      </form>
    </AuthFrame>
  );
}

export function ForgotPassword() {
  const [email, setEmail] = useState('');
  const [done, setDone] = useState(null);
  const { run, busy, error } = useAction(async () => setDone(await api.post('/auth/password/reset-request', { email })));
  return (
    <AuthFrame title="Reset your password" footer={<p><Link to="/login">Back to sign in</Link></p>}>
      {done ? (
        <Note tone="info">
          <p>{done.message}</p>
          {!done.emailDeliveryConfigured && <p>Note: email delivery is not configured on this server, so no message can be sent. Ask the administrator to configure SMTP.</p>}
        </Note>
      ) : (
        <form className="form" onSubmit={(e) => { e.preventDefault(); run(); }}>
          <label>Email<input type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} /></label>
          <ErrorNote error={error} />
          <button className="btn primary" disabled={busy}>{busy ? 'Sending…' : 'Send reset link'}</button>
        </form>
      )}
    </AuthFrame>
  );
}

export function ResetPassword() {
  const [params] = useSearchParams();
  const [password, setPassword] = useState('');
  const [done, setDone] = useState(false);
  const token = params.get('token') || '';
  const { run, busy, error } = useAction(async () => {
    await api.post('/auth/password/reset', { token, newPassword: password });
    setDone(true);
  });
  return (
    <AuthFrame title="Choose a new password">
      {done ? (
        <Note tone="good"><p>Your password was changed and all other sessions were signed out. <Link to="/login">Sign in</Link> with your new password.</p></Note>
      ) : !token ? (
        <Note tone="bad"><p>This link is incomplete. <Link to="/forgot-password">Request a new reset link</Link>.</p></Note>
      ) : (
        <form className="form" onSubmit={(e) => { e.preventDefault(); run(); }}>
          <label>New password<input type="password" autoComplete="new-password" minLength={12} maxLength={128} required value={password} onChange={(e) => setPassword(e.target.value)} /></label>
          <ErrorNote error={error} />
          <button className="btn primary" disabled={busy}>{busy ? 'Saving…' : 'Save new password'}</button>
        </form>
      )}
    </AuthFrame>
  );
}

export function Unsubscribe() {
  const [params] = useSearchParams();
  const [state, setState] = useState('idle');
  const category = params.get('c') || '';
  const names = { security_alerts: 'security alert', remediation_reminders: 'reminder', periodic_summary: 'weekly summary', product_updates: 'product update' };
  async function confirm() {
    setState('busy');
    try {
      await api.post('/notifications/unsubscribe', { u: params.get('u'), c: category, t: params.get('t') });
      setState('done');
    } catch {
      setState('error');
    }
  }
  return (
    <AuthFrame title="Email preferences">
      {state === 'done' ? (
        <Note tone="good"><p>You won’t receive {names[category] || ''} emails any more. In-app alerts continue. You can change this any time in Settings.</p></Note>
      ) : (
        <>
          <p className="lede">Stop receiving FootprintX {names[category] || ''} emails?</p>
          {state === 'error' && <Note tone="bad"><p>This link is invalid or expired. Sign in and change email preferences in Settings.</p></Note>}
          <button className="btn primary" onClick={confirm} disabled={state === 'busy'}>Unsubscribe</button>
        </>
      )}
    </AuthFrame>
  );
}

export function NotFound() {
  return (
    <AuthFrame title="Page not found">
      <p className="lede">This address doesn’t match a FootprintX page.</p>
      <Link className="btn primary" to="/">Go to the home page</Link>
    </AuthFrame>
  );
}
