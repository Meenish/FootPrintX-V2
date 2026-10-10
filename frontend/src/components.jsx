import { useEffect, useId, useRef, useState } from 'react';
import { Link, NavLink, useLocation } from 'react-router-dom';
import { useAuth } from './lib/auth.jsx';
import { formatDate, relative } from './lib/labels.js';

export function Logo({ to = '/' }) {
  return (
    <Link to={to} className="logo" aria-label="FootprintX home">
      <svg viewBox="0 0 64 64" width="26" height="26" aria-hidden="true">
        <path d="M32 4 56 13v17c0 15-10 26-24 30C18 56 8 45 8 30V13z" fill="none" stroke="currentColor" strokeWidth="5" />
        <path d="M22 33l7 7 14-15" fill="none" stroke="currentColor" strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      <span>FootprintX</span>
    </Link>
  );
}

const NAV = [
  ['/dashboard', 'Overview'],
  ['/accounts', 'Accounts'],
  ['/recommendations', 'Recommendations'],
  ['/dasi', 'Risk score'],
  ['/activity', 'Activity'],
  ['/website-check', 'Website check'],
  ['/settings', 'Settings'],
  ['/contact', 'Contact us'],
];

export function Shell({ children }) {
  const auth = useAuth();
  const loc = useLocation();
  const [open, setOpen] = useState(false);
  useEffect(() => setOpen(false), [loc.pathname]);
  const premium = auth.entitlement?.plan === 'premium';
  return (
    <div className="shell">
      <a className="skip" href="#main">Skip to content</a>
      <header className="topbar">
        <Logo to="/dashboard" />
        <button className="btn ghost menu-btn" aria-expanded={open} aria-controls="sidenav" onClick={() => setOpen(!open)}>
          {open ? 'Close menu' : 'Menu'}
        </button>
      </header>
      <nav id="sidenav" className={`sidenav ${open ? 'open' : ''}`} aria-label="Main">
        <div className="sidenav-logo"><Logo to="/dashboard" /></div>
        <ul>
          {NAV.map(([to, label]) => (
            <li key={to}>
              <NavLink to={to} className={({ isActive }) => `navlink ${isActive ? 'active' : ''}`}>{label}</NavLink>
            </li>
          ))}
        </ul>
        <div className="sidenav-foot">
          <Link to="/premium" className={`plan-chip ${premium ? 'premium' : ''}`}>{premium ? 'Premium' : 'Free plan'}</Link>
          <p className="who" title={auth.user?.email}>{auth.user?.email}</p>
          <button className="btn ghost small" onClick={auth.logout}>Sign out</button>
        </div>
      </nav>
      <main id="main" className="content" tabIndex={-1}>{children}</main>
    </div>
  );
}

export function PageHeader({ title, intro, actions }) {
  return (
    <header className="page-header">
      <div>
        <h1>{title}</h1>
        {intro && <p className="intro">{intro}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </header>
  );
}

/** Status tag. Tone conveys severity; the text always says it in words. */
export function Tag({ tone = 'neutral', children, title }) {
  return <span className={`tag tone-${tone}`} title={title}>{children}</span>;
}

export function Loading({ label = 'Loading…' }) {
  return <div className="state-loading" role="status">{label}</div>;
}

export function ErrorNote({ error, onRetry }) {
  if (!error) return null;
  return (
    <div className="note note-bad" role="alert">
      <p>{error.message || 'Something went wrong.'}</p>
      {onRetry && <button className="btn small" onClick={() => onRetry()}>Try again</button>}
    </div>
  );
}

export function Note({ tone = 'info', children, title }) {
  return (
    <div className={`note note-${tone}`} role={tone === 'bad' ? 'alert' : undefined}>
      {title && <p className="note-title">{title}</p>}
      {children}
    </div>
  );
}

export function Empty({ title, children, action }) {
  return (
    <div className="empty">
      <p className="empty-title">{title}</p>
      {children && <div className="empty-body">{children}</div>}
      {action}
    </div>
  );
}

export function Time({ value, withTime = false }) {
  if (!value) return <span className="muted">never</span>;
  return <time dateTime={new Date(value).toISOString()} title={formatDate(value, { time: true })}>{withTime ? formatDate(value, { time: true }) : relative(value)}</time>;
}

export function SyntheticBanner({ show }) {
  if (!show) return null;
  return (
    <Note tone="warn" title="Synthetic development data">
      <p>Some results on this page come from FootprintX’s labelled test mailbox, not a real inbox. They exist to demonstrate the product and are marked “Synthetic”.</p>
    </Note>
  );
}

export function ExternalLink({ href, children, kind }) {
  return (
    <a className="extlink" href={href} target="_blank" rel="noopener noreferrer">
      {children}
      <span className="sr-only"> (opens the official site in a new tab)</span>
      {kind === 'help_page' && <span className="extlink-kind">help article</span>}
      {kind === 'domain_root' && <span className="extlink-kind">home page — not a verified deep link</span>}
    </a>
  );
}

/** Modal confirmation using the native <dialog> element (focus-trapped, Esc closes). */
export function ConfirmDialog({ open, title, children, confirmLabel, tone = 'bad', busy, onConfirm, onCancel }) {
  const ref = useRef(null);
  const titleId = useId();
  useEffect(() => {
    const d = ref.current;
    if (!d) return;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog ref={ref} className="dialog" aria-labelledby={titleId} onCancel={(e) => { e.preventDefault(); onCancel(); }}>
      <h2 id={titleId}>{title}</h2>
      <div className="dialog-body">{children}</div>
      <div className="dialog-actions">
        <button className="btn ghost" onClick={onCancel} disabled={busy}>Cancel</button>
        <button className={`btn ${tone === 'bad' ? 'danger' : 'primary'}`} onClick={onConfirm} disabled={busy}>{busy ? 'Working…' : confirmLabel}</button>
      </div>
    </dialog>
  );
}

export function Toast({ message, onDone }) {
  useEffect(() => {
    if (!message) return undefined;
    const t = setTimeout(onDone, 5000);
    return () => clearTimeout(t);
  }, [message, onDone]);
  return <div className="toast" role="status" aria-live="polite">{message}</div>;
}

export function useToast() {
  const [message, setMessage] = useState('');
  return { toast: <Toast message={message} onDone={() => setMessage('')} />, show: setMessage };
}
