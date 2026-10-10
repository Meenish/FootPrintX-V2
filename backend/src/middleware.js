// Request middleware: authentication, CSRF, rate limits, request ids.
import crypto from 'node:crypto';
import rateLimit from 'express-rate-limit';
import { getConfig } from './config.js';
import { resolveSession } from './services/auth.js';
import { sha256, timingSafeEqualHex, keyedHash } from './crypto.js';
import { HttpError } from './http.js';

export const cookieNames = () =>
  getConfig().cookieSecure ? { session: '__Host-fx_session', csrf: '__Host-fx_csrf' } : { session: 'fx_session', csrf: 'fx_csrf' };

export function setSessionCookies(res, { token, csrfToken, expiresAt }) {
  const { session, csrf } = cookieNames();
  const secure = getConfig().cookieSecure;
  const expires = new Date(expiresAt);
  res.cookie(session, token, { httpOnly: true, secure, sameSite: 'lax', path: '/', expires });
  // Readable by the web app so it can echo the value in X-CSRF-Token.
  res.cookie(csrf, csrfToken, { httpOnly: false, secure, sameSite: 'lax', path: '/', expires });
}

export function clearSessionCookies(res) {
  const { session, csrf } = cookieNames();
  const secure = getConfig().cookieSecure;
  res.clearCookie(session, { httpOnly: true, secure, sameSite: 'lax', path: '/' });
  res.clearCookie(csrf, { httpOnly: false, secure, sameSite: 'lax', path: '/' });
}

export function requestId(req, res, next) {
  req.id = crypto.randomUUID();
  res.setHeader('X-Request-Id', req.id);
  next();
}

const UNSAFE = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

/**
 * Rejects state-changing requests that are not JSON. HTML forms cannot send
 * application/json cross-site without a CORS preflight, which our CORS policy
 * refuses, so this blocks login-CSRF and similar form-based attacks.
 */
export function requireJsonForUnsafe(req, res, next) {
  if (UNSAFE.has(req.method) && req.headers['content-length'] !== '0' && (req.headers['content-length'] || req.headers['transfer-encoding'])) {
    if (!req.is('application/json')) return next(new HttpError(415, 'UNSUPPORTED_MEDIA_TYPE', 'Requests must be sent as application/json.'));
  }
  next();
}

/** Resolves the caller from the session cookie (web) or Bearer token (extension). */
export async function authenticate(req, res, next) {
  try {
    const { session: cookieName } = cookieNames();
    const header = req.headers.authorization || '';
    const bearer = header.startsWith('Bearer ') ? header.slice(7).trim() : null;
    const cookieToken = req.cookies?.[cookieName];
    if (bearer) {
      const resolved = await resolveSession(bearer);
      if (resolved && resolved.session.kind === 'extension') req.auth = { ...resolved, via: 'bearer' };
    } else if (cookieToken) {
      const resolved = await resolveSession(cookieToken);
      if (resolved && resolved.session.kind === 'web') req.auth = { ...resolved, via: 'cookie' };
    }
    next();
  } catch (err) {
    next(err);
  }
}

/**
 * Requires an authenticated caller of one of the allowed session kinds. For
 * cookie sessions, unsafe methods must carry a valid CSRF token.
 */
export function requireAuth({ kinds = ['web'] } = {}) {
  return (req, res, next) => {
    if (!req.auth) return next(new HttpError(401, 'UNAUTHENTICATED', 'Please sign in to continue.'));
    if (!kinds.includes(req.auth.session.kind)) return next(new HttpError(403, 'WRONG_SESSION_KIND', 'This endpoint is not available to this client.'));
    if (req.auth.via === 'cookie' && UNSAFE.has(req.method)) {
      const presented = req.headers['x-csrf-token'];
      if (typeof presented !== 'string' || !timingSafeEqualHex(sha256(presented), req.auth.session.csrfHash || '')) {
        return next(new HttpError(403, 'CSRF_FAILED', 'Security token missing or invalid. Reload the page and try again.'));
      }
    }
    req.user = req.auth.user;
    next();
  };
}

export const requireAdmin = (req, res, next) =>
  req.user?.role === 'admin' ? next() : next(new HttpError(403, 'FORBIDDEN', 'Administrator access required.'));

// ---- Rate limits ------------------------------------------------------------
// In-memory counters (per process). A multi-instance deployment should use a
// shared store; see docs/DEPLOYMENT.md.
function limiter({ windowMs, limit, key, code = 'RATE_LIMITED', message = 'Too many requests. Please wait and try again.' }) {
  return rateLimit({
    windowMs,
    limit,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    keyGenerator: key,
    handler: (req, res, next) => next(new HttpError(429, code, message)),
    skip: () => getConfig().isTest && process.env.FX_TEST_RATE_LIMITS !== 'true',
  });
}

const ipKey = (req) => keyedHash('ratelimit-ip', req.ip || 'unknown');
const userKey = (req) => (req.auth ? `u:${req.auth.user.id}` : ipKey(req));
const sessionKey = (req) => (req.auth ? `s:${req.auth.session.id}` : ipKey(req));

export const limits = {
  contact: limiter({ windowMs: 60 * 60e3, limit: 5, key: userKey }),
  global: limiter({ windowMs: 15 * 60e3, limit: 600, key: ipKey }),
  auth: limiter({ windowMs: 15 * 60e3, limit: 10, key: ipKey, message: 'Too many sign-in attempts. Please wait 15 minutes and try again.' }),
  passwordReset: limiter({ windowMs: 60 * 60e3, limit: 5, key: ipKey }),
  sensitive: limiter({ windowMs: 15 * 60e3, limit: 30, key: userKey }),
  scans: limiter({ windowMs: 60 * 60e3, limit: 20, key: userKey, message: 'Too many scans started. Please wait before scanning again.' }),
  breach: limiter({ windowMs: 60 * 60e3, limit: 10, key: userKey }),
  manualReputation: limiter({ windowMs: 60 * 60e3, limit: 60, key: userKey }),
  extensionLookup: limiter({ windowMs: 60 * 60e3, limit: 1200, key: sessionKey }),
  extensionEvents: limiter({ windowMs: 60 * 60e3, limit: 120, key: sessionKey }),
  extensionLink: limiter({ windowMs: 15 * 60e3, limit: 10, key: ipKey }),
};
