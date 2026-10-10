// Breach intelligence. Separate from account discovery and from website
// reputation. What a result does and does NOT establish (shown in the UI):
//   * A listing means the email address appeared in that service's breach
//     dataset. It does not prove the current password is known, that the
//     password was reused, that the account is compromised today, or that
//     the service is still vulnerable.
//   * No listing means "no evidence found by <provider> on <date>", never
//     "never breached". Provider errors are "unavailable", never clean.
//
// Providers:
//   xposedornot — free, no key; 25 requests/hour, 100/day per IP; intended
//                 for personal/low-volume use (paid plans exist for products).
//   hibp        — Have I Been Pwned v3; requires a paid API key.
//   synthetic   — fixture provider, used only for synthetic dev mailboxes.
import { query, queryOne, transaction } from '../db.js';
import { getConfig } from '../config.js';
import { log } from '../logger.js';
import { normalizeHost } from '@footprintx/shared/domain';
import { HttpError } from '../http.js';
import { connectionEmail, getOwnedConnection } from './connections.js';
import { syntheticBreachProvider } from './synthetic.js';
import { canonicalServiceDomain, categoryFor } from './catalog.js';
import { recalculate } from './risk.js';

export const CONSENT_POLICY_VERSION = '2026-10-breach-v2';
const TIMEOUT_MS = 10000;
const MAX_BODY = 2 * 1024 * 1024;

export const PROVIDER_INFO = Object.freeze({
  xposedornot: { label: 'XposedOrNot', url: 'https://xposedornot.com', sends: 'your email address' },
  hibp: { label: 'Have I Been Pwned', url: 'https://haveibeenpwned.com', sends: 'your email address' },
  synthetic: { label: 'Synthetic breach fixture (development only)', url: null, sends: 'nothing (local fixture)' },
});

class ProviderFailure extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

async function fetchJson(url, headers) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, { headers: { 'user-agent': 'FootprintX/2.0', accept: 'application/json', ...headers }, signal: ctrl.signal, redirect: 'error' });
    const text = await res.text();
    if (text.length > MAX_BODY) throw new ProviderFailure('MALFORMED_RESPONSE', 'Response too large');
    let body = null;
    if (text) {
      try {
        body = JSON.parse(text);
      } catch {
        if (res.status === 200) throw new ProviderFailure('MALFORMED_RESPONSE', 'Response was not JSON');
      }
    }
    return { status: res.status, headers: res.headers, body };
  } catch (err) {
    if (err instanceof ProviderFailure) throw err;
    throw new ProviderFailure(err.name === 'AbortError' ? 'TIMEOUT' : 'NETWORK_ERROR', 'Provider unreachable');
  } finally {
    clearTimeout(t);
  }
}

// ---- Normalizers (pure, exported for tests) ---------------------------------
export function normalizeXon(d) {
  if (!d || typeof d !== 'object' || !d.breach) return null;
  const year = String(d.xposedDate || '').trim();
  const classes = (Array.isArray(d.xposed_data) ? d.xposed_data : String(d.xposed_data || '').split(';')).map((c) => String(c).trim()).filter(Boolean).slice(0, 40);
  const dom = d.domain ? normalizeHost(String(d.domain))?.registrableDomain : null;
  return {
    name: String(d.breach).slice(0, 120),
    title: String(d.breach).slice(0, 120),
    domain: dom ? canonicalServiceDomain(dom) : null,
    date: /^\d{4}$/.test(year) ? `${year}-01-01` : null,
    datePrecision: /^\d{4}$/.test(year) ? 'year' : 'unknown',
    dataClasses: classes,
    verified: String(d.verified || '').toLowerCase() === 'yes' ? true : String(d.verified || '').toLowerCase() === 'no' ? false : null,
  };
}

export function normalizeHibp(b, { includeSensitive }) {
  if (!b || typeof b !== 'object' || !b.Name) return null;
  if (b.IsFabricated || b.IsSpamList) return null;
  if (b.IsSensitive && !includeSensitive) return null;
  const dom = b.Domain ? normalizeHost(String(b.Domain))?.registrableDomain : null;
  const date = /^\d{4}-\d{2}-\d{2}$/.test(b.BreachDate || '') ? b.BreachDate : null;
  return {
    name: String(b.Name).slice(0, 120),
    title: String(b.Title || b.Name).slice(0, 120),
    domain: dom ? canonicalServiceDomain(dom) : null,
    date,
    datePrecision: date ? 'day' : 'unknown',
    dataClasses: Array.isArray(b.DataClasses) ? b.DataClasses.map(String).slice(0, 40) : [],
    verified: b.IsVerified === true ? true : b.IsVerified === false ? false : null,
  };
}

/** Password *hints* are not passwords. */
export const exposesPasswords = (b) => b.dataClasses.some((c) => /password/i.test(c) && !/hint/i.test(c));

// ---- Providers ----------------------------------------------------------------
const xposedOrNot = {
  name: 'xposedornot',
  async checkEmail(email) {
    const res = await fetchJson(`https://api.xposedornot.com/v1/breach-analytics?email=${encodeURIComponent(email)}`);
    if (res.status === 429) throw new ProviderFailure('RATE_LIMITED', 'Rate limited');
    if (res.status === 404) return { breaches: [] };
    if (res.status !== 200) throw new ProviderFailure('PROVIDER_ERROR', `Status ${res.status}`);
    const exposed = res.body?.ExposedBreaches;
    // Documented "not found" shape; anything else unexpected fails closed.
    if (exposed === null || (res.body && res.body.Error === 'Not found')) return { breaches: [] };
    if (!exposed || !Array.isArray(exposed.breaches_details)) throw new ProviderFailure('MALFORMED_RESPONSE', 'Unexpected response shape');
    return { breaches: exposed.breaches_details };
  },
  normalize: (d) => normalizeXon(d),
};

const hibp = {
  name: 'hibp',
  async checkEmail(email) {
    const key = getConfig().breach.hibpApiKey;
    const res = await fetchJson(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`, { 'hibp-api-key': key });
    if (res.status === 404) return { breaches: [] };
    if (res.status === 429) throw new ProviderFailure('RATE_LIMITED', 'Rate limited');
    if (res.status === 401 || res.status === 403) throw new ProviderFailure('PROVIDER_AUTH', 'Provider rejected the API key');
    if (res.status !== 200) throw new ProviderFailure('PROVIDER_ERROR', `Status ${res.status}`);
    if (!Array.isArray(res.body)) throw new ProviderFailure('MALFORMED_RESPONSE', 'Unexpected response shape');
    return { breaches: res.body };
  },
  normalize: (b) => normalizeHibp(b, { includeSensitive: getConfig().breach.includeSensitive }),
};

const synthetic = { ...syntheticBreachProvider, normalize: (d) => normalizeXon(d) };

/** Exposed for tests of the real provider parsing (with a stubbed fetch). */
export const builtInProviders = Object.freeze({ xposedornot: xposedOrNot, hibp });

const providerOverrides = {};
/** Test hook: substitute a provider implementation (e.g. to simulate outages). */
export function setBreachProvider(name, impl) {
  providerOverrides[name] = impl;
}

function providerFor(connection) {
  if (connection.is_synthetic) return providerOverrides.synthetic || synthetic;
  const name = getConfig().breach.provider;
  if (name === 'none') return null;
  return providerOverrides[name] || (name === 'hibp' ? hibp : xposedOrNot);
}

export function configuredProvider() {
  const name = getConfig().breach.provider;
  return name === 'none' ? null : { name, ...PROVIDER_INFO[name] };
}

// ---- Consent ----------------------------------------------------------------------
export async function getConsent(userId) {
  return queryOne("SELECT provider, policy_version, granted_at, revoked_at FROM consents WHERE user_id = $1 AND kind = 'breach_lookup'", [userId]);
}

export async function setConsent(userId, granted) {
  const p = configuredProvider();
  if (granted && !p) throw new HttpError(503, 'BREACH_PROVIDER_DISABLED', 'Breach checking is not enabled on this server.');
  await query(
    `INSERT INTO consents (user_id, kind, provider, policy_version, granted_at, revoked_at) VALUES ($1, 'breach_lookup', $2, $3, $4, $5)
     ON CONFLICT (user_id, kind) DO UPDATE SET provider = EXCLUDED.provider, policy_version = EXCLUDED.policy_version, granted_at = EXCLUDED.granted_at, revoked_at = EXCLUDED.revoked_at, updated_at = now()`,
    [userId, p?.name || 'none', CONSENT_POLICY_VERSION, granted ? new Date() : null, granted ? null : new Date()]
  );
  return getConsent(userId);
}

const consentValid = (c, providerName) => !!c && !!c.granted_at && !c.revoked_at && c.provider === providerName && c.policy_version === CONSENT_POLICY_VERSION;

// ---- Check ---------------------------------------------------------------------------
const STATUS_MESSAGES = {
  RATE_LIMITED: 'The breach provider is rate-limiting requests (free tier: about 25 per hour). Try again later.',
  TIMEOUT: 'The breach provider did not respond in time.',
  NETWORK_ERROR: 'The breach provider could not be reached.',
  MALFORMED_RESPONSE: 'The breach provider returned a response FootprintX could not interpret, so no result was recorded.',
  PROVIDER_AUTH: 'The breach provider rejected the server’s API key.',
  PROVIDER_ERROR: 'The breach provider returned an error.',
};

export async function runBreachCheck(userId, connectionId, { force = false } = {}) {
  const conn = await getOwnedConnection(userId, connectionId);
  if (!conn) throw new HttpError(404, 'NOT_FOUND', 'Mailbox connection not found.');
  if (conn.status !== 'active') throw new HttpError(409, 'CONNECTION_INACTIVE', 'Reconnect this mailbox before checking it for breaches.');
  const provider = providerFor(conn);
  if (!provider) throw new HttpError(503, 'BREACH_PROVIDER_DISABLED', 'Breach checking is not enabled on this server (BREACH_PROVIDER=none).');
  if (!conn.is_synthetic && !consentValid(await getConsent(userId), provider.name)) {
    throw new HttpError(403, 'CONSENT_REQUIRED', `Breach checking sends your email address to ${PROVIDER_INFO[provider.name]?.label}. Turn on consent first.`);
  }
  const recent = await queryOne(
    `SELECT checked_at, result_count FROM breach_checks WHERE connection_id = $1 AND provider = $2 AND status = 'ok' AND checked_at > now() - make_interval(hours => $3) ORDER BY checked_at DESC LIMIT 1`,
    [conn.id, provider.name, getConfig().breach.recheckMinHours]
  );
  if (recent && !force) return { status: 'ok', cached: true, provider: provider.name, checkedAt: recent.checked_at, breachCount: recent.result_count };

  let raw;
  try {
    raw = await provider.checkEmail(conn.is_synthetic ? null : connectionEmail(conn));
  } catch (err) {
    const code = err instanceof ProviderFailure ? err.code : 'PROVIDER_ERROR';
    log.warn('breach provider failure', { provider: provider.name, code });
    await query('INSERT INTO breach_checks (user_id, connection_id, provider, status, error_code, is_synthetic) VALUES ($1, $2, $3, $4, $5, $6)', [userId, conn.id, provider.name, code === 'RATE_LIMITED' ? 'rate_limited' : 'unavailable', code, conn.is_synthetic]);
    return { status: 'unavailable', provider: provider.name, errorCode: code, message: STATUS_MESSAGES[code] || STATUS_MESSAGES.PROVIDER_ERROR };
  }
  if (!raw || !Array.isArray(raw.breaches)) {
    await query('INSERT INTO breach_checks (user_id, connection_id, provider, status, error_code, is_synthetic) VALUES ($1, $2, $3, $4, $5, $6)', [userId, conn.id, provider.name, 'unavailable', 'MALFORMED_RESPONSE', conn.is_synthetic]);
    return { status: 'unavailable', provider: provider.name, errorCode: 'MALFORMED_RESPONSE', message: STATUS_MESSAGES.MALFORMED_RESPONSE };
  }
  const breaches = raw.breaches.map((b) => provider.normalize(b)).filter(Boolean);
  const summary = await applyBreaches(userId, conn, provider.name, breaches);
  await recalculate(userId, 'breach_check');
  return { status: 'ok', cached: false, provider: provider.name, checkedAt: new Date().toISOString(), breachCount: breaches.length, ...summary };
}

async function applyBreaches(userId, conn, providerName, breaches) {
  return transaction(async (tx) => {
    await query('INSERT INTO breach_checks (user_id, connection_id, provider, status, result_count, is_synthetic) VALUES ($1, $2, $3, $4, $5, $6)', [userId, conn.id, providerName, 'ok', breaches.length, conn.is_synthetic], tx);
    const accounts = await query('SELECT id, service_key, service_name, service_domain, status FROM discovered_accounts WHERE user_id = $1 AND connection_id = $2', [userId, conn.id], tx);
    const squash = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]/g, '');
    let matched = 0;
    let added = 0;
    const touched = new Set();
    for (const b of breaches) {
      // Exact registrable-domain match first; exact name match only when the breach has no domain.
      let account = b.domain ? accounts.find((a) => a.service_domain === b.domain) : accounts.find((a) => squash(a.service_name) === squash(b.title));
      if (!account) {
        const key = b.domain || `name:${squash(b.title)}`;
        account = await queryOne(
          `INSERT INTO discovered_accounts (user_id, connection_id, service_key, service_name, service_domain, category, identifier_masked, status, discovery_source, confidence, first_observed_at, last_observed_at, last_checked_at, is_synthetic)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'breach_record',$9,$10,$10, now(), $11)
           ON CONFLICT (user_id, connection_id, service_key) DO UPDATE SET last_checked_at = now() RETURNING id, service_domain, service_name, status`,
          [userId, conn.id, key, b.title, b.domain, categoryFor(b.domain), conn.email_masked, b.domain ? 'confirmed' : 'possible', b.domain ? 'medium' : 'low', b.date ? new Date(b.date) : new Date(), conn.is_synthetic],
          tx
        );
        accounts.push(account);
        added += 1;
        await query(
          `INSERT INTO account_evidence (account_id, user_id, connection_id, kind, strength, source, sender_domain, sender_authenticated, source_ref_hash, observed_at, is_synthetic)
           VALUES ($1,$2,$3,'breach_record','strong',$4,NULL,'unknown',$5,$6,$7) ON CONFLICT (account_id, source_ref_hash) DO NOTHING`,
          [account.id, userId, conn.id, `breach_provider:${providerName}`, `breach:${providerName}:${b.name}`, b.date ? new Date(b.date) : new Date(), conn.is_synthetic],
          tx
        );
      } else matched += 1;
      touched.add(account.id);
      await query(
        `INSERT INTO breach_findings (user_id, connection_id, account_id, provider, breach_name, breach_title, breach_domain, breach_date, breach_date_precision, data_classes, password_exposed, provider_verified, is_synthetic)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11,$12,$13)
         ON CONFLICT (connection_id, provider, breach_name) DO UPDATE SET last_seen_at = now(), account_id = EXCLUDED.account_id, data_classes = EXCLUDED.data_classes,
           password_exposed = EXCLUDED.password_exposed, provider_verified = EXCLUDED.provider_verified`,
        [userId, conn.id, account.id, providerName, b.name, b.title, b.domain, b.date, b.datePrecision, JSON.stringify(b.dataClasses), exposesPasswords(b), b.verified, conn.is_synthetic],
        tx
      );
    }
    // Accounts on this mailbox with no listing: "no evidence found" (not "safe").
    await query(
      `UPDATE discovered_accounts SET exposure_status = CASE WHEN id = ANY($3::uuid[]) THEN 'confirmed_evidence' ELSE 'no_evidence_found' END, exposure_checked_at = now()
        WHERE user_id = $1 AND connection_id = $2`,
      [userId, conn.id, [...touched]],
      tx
    );
    return { matched, added };
  });
}

export async function breachOverview(userId) {
  const checks = await query(
    `SELECT DISTINCT ON (connection_id) connection_id, provider, status, result_count, error_code, checked_at, is_synthetic FROM breach_checks WHERE user_id = $1 ORDER BY connection_id, checked_at DESC`,
    [userId]
  );
  const findings = await query(
    `SELECT f.id, f.connection_id, f.account_id, f.provider, f.breach_title, f.breach_domain, f.breach_date, f.breach_date_precision, f.data_classes, f.password_exposed,
            f.provider_verified, f.first_seen_at, f.last_seen_at, f.is_synthetic, a.service_name
       FROM breach_findings f LEFT JOIN discovered_accounts a ON a.id = f.account_id WHERE f.user_id = $1 ORDER BY f.breach_date DESC NULLS LAST`,
    [userId]
  );
  return { checks, findings };
}
