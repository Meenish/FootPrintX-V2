// Gmail API integration (server-side only; the client secret and tokens never
// reach the browser or the extension).
//
// Scope modes (GMAIL_SCOPE_MODE):
//   metadata (default) — https://www.googleapis.com/auth/gmail.metadata
//       Headers and labels only; message bodies are technically inaccessible.
//       Gmail's search parameter `q` is NOT available with this scope, so the
//       scan pages through the most recent messages (up to SCAN_MAX_MESSAGES)
//       and classifies by subject line. Older signups beyond the cap may be
//       missed — this limitation is shown to the user.
//   readonly — https://www.googleapis.com/auth/gmail.readonly
//       Allows targeted search queries across the whole mailbox history (deeper
//       discovery) but grants broader access. We still request only metadata
//       format + snippet and never fetch bodies or attachments.
// Both are Google "restricted" scopes; a public production launch requires
// Google's OAuth verification and security assessment (docs/PROVIDERS.md).
import { google } from 'googleapis';
import { getConfig } from '../config.js';

export const SCOPES = Object.freeze({
  metadata: ['https://www.googleapis.com/auth/gmail.metadata'],
  readonly: ['https://www.googleapis.com/auth/gmail.readonly'],
});

const REQUEST_TIMEOUT_MS = 15000;
const BATCH = 10;
const MIN_BATCH_MS = 250; // keeps us well under Gmail's per-user quota

export class ProviderError extends Error {
  constructor(code, message, { transient = false, status } = {}) {
    super(message);
    this.code = code;
    this.transient = transient;
    this.status = status;
  }
}

export function classifyGoogleError(err) {
  if (err instanceof ProviderError) return err;
  const status = err?.response?.status ?? err?.status ?? err?.code;
  const reason = err?.response?.data?.error || err?.errors?.[0]?.reason || '';
  if (reason === 'invalid_grant' || status === 401) return new ProviderError('AUTH_REVOKED', 'Gmail access was revoked or has expired. Reconnect the mailbox.', { status: 401 });
  if (status === 403 && /insufficient|scope/i.test(JSON.stringify(err?.response?.data || reason))) return new ProviderError('SCOPE_MISSING', 'The mailbox was connected without the permission FootprintX needs. Reconnect and approve access.', { status: 403 });
  if (status === 429 || (status === 403 && /rate|quota/i.test(JSON.stringify(err?.response?.data || '')))) return new ProviderError('RATE_LIMITED', 'Gmail is temporarily limiting requests.', { transient: true, status: 429 });
  if (typeof status === 'number' && status >= 500) return new ProviderError('PROVIDER_UNAVAILABLE', 'Gmail is temporarily unavailable.', { transient: true, status });
  if (['ECONNRESET', 'ETIMEDOUT', 'ECONNABORTED', 'ENOTFOUND', 'EAI_AGAIN', 'ECONNREFUSED'].includes(err?.code) || /timeout/i.test(err?.message || '')) {
    return new ProviderError('NETWORK_ERROR', 'Could not reach Gmail.', { transient: true });
  }
  return new ProviderError('PROVIDER_ERROR', 'Gmail returned an unexpected error.', { status });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Retries transient failures with exponential backoff + jitter. */
export async function withRetry(fn, { retries = 3, baseMs = 800 } = {}) {
  let attempt = 0;
  for (;;) {
    try {
      return await fn();
    } catch (raw) {
      const err = classifyGoogleError(raw);
      if (!err.transient || attempt >= retries) throw err;
      const retryAfter = Number(raw?.response?.headers?.['retry-after']);
      const wait = Math.min(30000, Number.isFinite(retryAfter) ? retryAfter * 1000 : baseMs * 2 ** attempt + Math.random() * 250);
      await sleep(wait);
      attempt += 1;
    }
  }
}

export function oauthClient() {
  const g = getConfig().google;
  return new google.auth.OAuth2(g.clientId, g.clientSecret, g.redirectUri);
}

export function buildAuthUrl({ state, pkce, scopeMode }) {
  return oauthClient().generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    include_granted_scopes: false,
    scope: SCOPES[scopeMode],
    state,
    code_challenge: pkce.challenge,
    code_challenge_method: pkce.method,
  });
}

/** Exchanges the authorization code; returns { email, refreshToken, grantedScopes }. */
export async function exchangeCode({ code, verifier, scopeMode }) {
  const client = oauthClient();
  const { tokens } = await client.getToken({ code, codeVerifier: verifier });
  if (!tokens.refresh_token) throw new ProviderError('NO_REFRESH_TOKEN', 'Google did not grant offline access. Please try connecting again and approve access.');
  const granted = String(tokens.scope || '').split(/\s+/).filter(Boolean);
  if (!SCOPES[scopeMode].every((s) => granted.includes(s))) {
    await client.revokeToken(tokens.refresh_token).catch(() => {});
    throw new ProviderError('SCOPE_MISSING', 'The requested Gmail permission was not granted, so no mailbox was connected.');
  }
  client.setCredentials(tokens);
  const gmail = google.gmail({ version: 'v1', auth: client, timeout: REQUEST_TIMEOUT_MS });
  const profile = await withRetry(() => gmail.users.getProfile({ userId: 'me' }));
  return { email: profile.data.emailAddress, refreshToken: tokens.refresh_token, grantedScopes: granted.join(' ') };
}

/** Revokes a refresh token at Google. Returns 'revoked' | 'already_invalid' | 'failed'. */
export async function revokeRefreshToken(refreshToken) {
  try {
    await Promise.race([oauthClient().revokeToken(refreshToken), sleep(REQUEST_TIMEOUT_MS).then(() => Promise.reject(new Error('timeout')))]);
    return 'revoked';
  } catch (err) {
    const status = err?.response?.status;
    if (status === 400) return 'already_invalid';
    return 'failed';
  }
}

// Search windows used in readonly mode so old signups are not crowded out.
const ACCOUNT_TERMS = ['welcome to', 'verify your email', 'confirm your account', 'confirm your email', 'account created', 'activate your account', 'thanks for signing up',
  'password reset', 'reset your password', 'password changed', 'new sign-in', 'security alert', 'unusual activity', '2-step verification', 'two-factor', 'account deleted', 'account closed'];
export function buildSearchWindows(now = new Date()) {
  const base = `(${ACCOUNT_TERMS.map((t) => `"${t}"`).join(' OR ')})`;
  const fmt = (d) => `${d.getUTCFullYear()}/${d.getUTCMonth() + 1}/${d.getUTCDate()}`;
  const ago = (years) => {
    const d = new Date(now);
    d.setUTCFullYear(d.getUTCFullYear() - years);
    return fmt(d);
  };
  return [
    { id: 'last_year', q: `${base} after:${ago(1)}` },
    { id: '1_3_years', q: `${base} after:${ago(3)} before:${ago(1)}` },
    { id: '3_6_years', q: `${base} after:${ago(6)} before:${ago(3)}` },
    { id: 'over_6_years', q: `${base} before:${ago(6)}` },
  ];
}

/**
 * Streams message metadata in batches. Yields { source, messages } and
 * finally returns per-source outcomes. The caller decides what to keep.
 */
export async function* iterateMailbox({ refreshToken, scopeMode, maxMessages }) {
  const client = oauthClient();
  client.setCredentials({ refresh_token: refreshToken });
  const gmail = google.gmail({ version: 'v1', auth: client, timeout: REQUEST_TIMEOUT_MS });
  const sources = scopeMode === 'readonly' ? buildSearchWindows() : [{ id: 'recent_messages', q: null }];
  const perSource = Math.ceil(maxMessages / sources.length);

  for (const source of sources) {
    const outcome = { source: source.id, status: 'ok', listed: 0, fetched: 0, failed: 0 };
    let ids = [];
    try {
      let pageToken;
      do {
        const { data } = await withRetry(() =>
          gmail.users.messages.list({ userId: 'me', maxResults: Math.min(500, perSource - ids.length), pageToken, includeSpamTrash: false, ...(source.q ? { q: source.q } : {}) })
        );
        for (const m of data.messages || []) ids.push(m.id);
        pageToken = data.nextPageToken;
      } while (pageToken && ids.length < perSource);
      outcome.listed = ids.length;
    } catch (err) {
      const e = classifyGoogleError(err);
      if (!e.transient) throw e; // auth/scope problems end the whole scan
      outcome.status = 'failed';
      outcome.error = e.code;
      yield { source: source.id, messages: [], outcome };
      continue;
    }

    for (let i = 0; i < ids.length; i += BATCH) {
      const started = Date.now();
      const settled = await Promise.allSettled(
        ids.slice(i, i + BATCH).map((id) =>
          withRetry(() => gmail.users.messages.get({ userId: 'me', id, format: 'metadata', metadataHeaders: ['From', 'Subject', 'Authentication-Results'] }))
        )
      );
      const messages = [];
      for (const s of settled) {
        if (s.status === 'rejected') {
          const e = classifyGoogleError(s.reason);
          if (e.code === 'AUTH_REVOKED' || e.code === 'SCOPE_MISSING') throw e;
          outcome.failed += 1;
          continue;
        }
        const d = s.value.data;
        const header = (n) => d.payload?.headers?.find((h) => h.name.toLowerCase() === n)?.value || '';
        messages.push({ id: d.id, from: header('from'), subject: header('subject'), snippet: scopeMode === 'readonly' ? d.snippet || '' : '', authResults: header('authentication-results'), internalDate: Number(d.internalDate) });
      }
      outcome.fetched += messages.length;
      if (outcome.failed && outcome.failed >= Math.max(5, outcome.listed * 0.2)) outcome.status = 'degraded';
      yield { source: source.id, messages, outcome: { ...outcome, inProgress: i + BATCH < ids.length } };
      const elapsed = Date.now() - started;
      if (elapsed < MIN_BATCH_MS) await sleep(MIN_BATCH_MS - elapsed);
    }
    if (outcome.failed && outcome.status === 'ok') outcome.status = 'degraded';
    yield { source: source.id, messages: [], outcome };
  }
}
