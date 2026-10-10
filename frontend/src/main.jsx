import { StrictMode, Suspense, lazy, useEffect } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Routes, Route, useLocation } from 'react-router-dom';
import '@fontsource/atkinson-hyperlegible/400.css';
import '@fontsource/atkinson-hyperlegible/700.css';
import './styles.css';
import { AppProviders, RequireAuth } from './lib/auth.jsx';
import { Landing, Login, Register, ForgotPassword, ResetPassword, Unsubscribe, NotFound } from './pages/Public.jsx';
import { Onboarding } from './pages/Onboarding.jsx';
import { Dashboard } from './pages/Dashboard.jsx';
import { Accounts, AccountDetail } from './pages/Accounts.jsx';
import { Recommendations } from './pages/Recommendations.jsx';
import { Activity } from './pages/Activity.jsx';
import { WebsiteCheck } from './pages/WebsiteCheck.jsx';
import { Settings } from './pages/Settings.jsx';
import { Contact } from './pages/Contact.jsx';
import { Premium } from './pages/Premium.jsx';

// The chart library is only needed on the risk-score page; load it on demand.
const Dasi = lazy(() => import('./pages/Dasi.jsx').then((m) => ({ default: m.Dasi })));

const TITLES = { '/': 'Secure your digital past', '/login': 'Sign in', '/register': 'Create account', '/dashboard': 'Overview', '/accounts': 'Accounts', '/recommendations': 'Recommendations', '/dasi': 'Risk score', '/activity': 'Activity', '/website-check': 'Check a website', '/settings': 'Settings', '/premium': 'Plans', '/onboarding': 'Set up' };

function RouteEffects() {
  const loc = useLocation();
  useEffect(() => {
    const base = `/${loc.pathname.split('/')[1]}`;
    document.title = `${TITLES[loc.pathname] || TITLES[base] || 'FootprintX'} — FootprintX`;
    // Move focus to the main region on navigation so screen readers announce the new page.
    if (!loc.hash) document.getElementById('main')?.focus({ preventScroll: true });
    window.scrollTo(0, 0);
  }, [loc.pathname, loc.hash]);
  return null;
}

const guarded = (el) => <RequireAuth>{el}</RequireAuth>;

function App() {
  return (
    <>
      <RouteEffects />
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/reset-password" element={<ResetPassword />} />
        <Route path="/unsubscribe" element={<Unsubscribe />} />
        <Route path="/onboarding" element={guarded(<Onboarding />)} />
        <Route path="/dashboard" element={guarded(<Dashboard />)} />
        <Route path="/accounts" element={guarded(<Accounts />)} />
        <Route path="/accounts/:id" element={guarded(<AccountDetail />)} />
        <Route path="/recommendations" element={guarded(<Recommendations />)} />
        <Route path="/dasi" element={guarded(<Suspense fallback={<div className="boot" role="status">Loading…</div>}><Dasi /></Suspense>)} />
        <Route path="/activity" element={guarded(<Activity />)} />
        <Route path="/website-check" element={guarded(<WebsiteCheck />)} />
        <Route path="/settings" element={guarded(<Settings />)} />
        <Route path="/contact" element={guarded(<Contact />)} />
        <Route path="/premium" element={guarded(<Premium />)} />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </>
  );
}

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <BrowserRouter>
      <AppProviders>
        <App />
      </AppProviders>
    </BrowserRouter>
  </StrictMode>
);
