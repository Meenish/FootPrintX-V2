import { Router } from 'express';
import { z } from 'zod';
import { ah, validate, HttpError } from '../http.js';
import { limits, requireAuth, setSessionCookies, clearSessionCookies } from '../middleware.js';
import {
  registerUser, verifyLogin, createSession, revokeSession, revokeAllSessions, listSessions, verifyPasswordForUser, setPassword,
  createPasswordReset, consumePasswordReset, passwordProblems,
} from '../services/auth.js';
import { getEntitlement } from '../services/billing.js';
import { sendEmail } from '../services/notifications.js';
import { audit } from '../services/audit.js';
import { getConfig } from '../config.js';

const email = z.string().trim().toLowerCase().email().max(254);
const password = z.string().min(1).max(128);

export const authRouter = Router();

function publicUser(u) {
  return { id: u.id, email: u.email, displayName: u.displayName ?? u.display_name ?? null, role: u.role, createdAt: u.createdAt ?? u.created_at };
}

async function startSession(req, res, user) {
  const { token, csrfToken, session } = await createSession(user.id, 'web', { label: String(req.headers['user-agent'] || 'Web browser').slice(0, 60) });
  setSessionCookies(res, { token, csrfToken, expiresAt: session.expires_at });
  return { csrfToken, expiresAt: session.expires_at };
}

authRouter.post(
  '/register',
  limits.auth,
  validate({ body: z.object({ email, password, displayName: z.string().trim().max(60).optional() }).strict() }),
  ah(async (req, res) => {
    const user = await registerUser(req.body);
    await audit('user_registered', { userId: user.id, req });
    const s = await startSession(req, res, user);
    res.status(201).json({ user: publicUser(user), csrfToken: s.csrfToken });
  })
);

authRouter.post(
  '/login',
  limits.auth,
  validate({ body: z.object({ email, password }).strict() }),
  ah(async (req, res) => {
    const result = await verifyLogin(req.body.email, req.body.password);
    if (!result.ok) {
      if (result.userId) await audit(result.locked ? 'login_blocked_locked' : result.lockedNow ? 'login_locked' : 'login_failed', { userId: result.userId, req });
      if (result.locked) throw new HttpError(429, 'ACCOUNT_LOCKED', 'Too many failed attempts. Try again in 15 minutes or reset your password.');
      throw new HttpError(401, 'INVALID_CREDENTIALS', 'Incorrect email or password.');
    }
    const s = await startSession(req, res, result.user);
    await audit('login', { userId: result.user.id, req });
    res.json({ user: publicUser(result.user), csrfToken: s.csrfToken });
  })
);

authRouter.post(
  '/logout',
  requireAuth({ kinds: ['web'] }),
  ah(async (req, res) => {
    await revokeSession(req.auth.session.id, req.user.id);
    clearSessionCookies(res);
    await audit('logout', { userId: req.user.id, sessionId: req.auth.session.id, req });
    res.status(204).end();
  })
);

authRouter.get(
  '/me',
  requireAuth({ kinds: ['web'] }),
  ah(async (req, res) => {
    res.json({ user: publicUser(req.user), session: { id: req.auth.session.id, expiresAt: req.auth.session.expiresAt }, entitlement: await getEntitlement(req.user.id) });
  })
);

authRouter.post(
  '/password/change',
  requireAuth({ kinds: ['web'] }),
  limits.sensitive,
  validate({ body: z.object({ currentPassword: password, newPassword: password }).strict() }),
  ah(async (req, res) => {
    if (!(await verifyPasswordForUser(req.user.id, req.body.currentPassword))) throw new HttpError(400, 'INVALID_CREDENTIALS', 'Your current password is incorrect.');
    await setPassword(req.user.id, req.body.newPassword, req.user.email);
    await revokeAllSessions(req.user.id, { exceptSessionId: req.auth.session.id });
    await audit('password_changed', { userId: req.user.id, req });
    res.json({ ok: true, otherSessionsSignedOut: true });
  })
);

authRouter.post(
  '/password/reset-request',
  limits.passwordReset,
  validate({ body: z.object({ email }).strict() }),
  ah(async (req, res) => {
    const reset = await createPasswordReset(req.body.email);
    if (reset) {
      const link = `${getConfig().appUrl}/reset-password?token=${encodeURIComponent(reset.token)}`;
      const outcome = await sendEmail(reset.user.id, {
        category: 'essential',
        essential: true,
        dedupKey: `reset:${Date.now()}`,
        subject: '[FootprintX] Reset your password',
        text: `Someone (hopefully you) asked to reset your FootprintX password.\n\nReset it here within 30 minutes: ${link}\n\nIf this wasn't you, ignore this email; your password is unchanged.`,
      });
      await audit('password_reset_requested', { userId: reset.user.id, req, detail: { delivery: outcome.status } });
    }
    // Same response whether or not the account exists (no account enumeration).
    res.status(202).json({ ok: true, message: 'If an account exists for that email, a reset link has been sent.', emailDeliveryConfigured: getConfig().smtp.configured });
  })
);

authRouter.post(
  '/password/reset',
  limits.passwordReset,
  validate({ body: z.object({ token: z.string().min(20).max(200), newPassword: password }).strict() }),
  ah(async (req, res) => {
    const problems = passwordProblems(req.body.newPassword);
    if (problems.length) throw new HttpError(400, 'WEAK_PASSWORD', problems.join(' '));
    const user = await consumePasswordReset(req.body.token, req.body.newPassword);
    await audit('password_reset_completed', { userId: user.id, req });
    res.json({ ok: true });
  })
);

authRouter.get(
  '/sessions',
  requireAuth({ kinds: ['web'] }),
  ah(async (req, res) => {
    const rows = await listSessions(req.user.id);
    res.json({ items: rows.map((s) => ({ ...s, current: s.id === req.auth.session.id })) });
  })
);

authRouter.delete(
  '/sessions/:id',
  requireAuth({ kinds: ['web'] }),
  validate({ params: z.object({ id: z.string().uuid() }) }),
  ah(async (req, res) => {
    await revokeSession(req.params.id, req.user.id);
    await audit('session_revoked', { userId: req.user.id, req, detail: { sessionId: req.params.id } });
    res.status(204).end();
  })
);
