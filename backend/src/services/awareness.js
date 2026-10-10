// Read-only account association. No current-login integration is supported.
import { normalizeHost, hostCandidates } from '@footprintx/shared/domain';
import { canonicalServiceDomain } from './catalog.js';
import { query } from '../db.js';
import { HttpError } from '../http.js';

export async function accountAwareness(userId, domain) {
  const n = normalizeHost(domain);
  if (!n || n.isLocal || n.isIp || !n.registrableDomain) throw new HttpError(400, 'INVALID_DOMAIN', 'Enter a public website domain.');
  const candidates = [...new Set(hostCandidates(n.hostname).map(canonicalServiceDomain))];
  const rows = await query(`SELECT a.id, a.service_name, a.status, a.confidence, a.discovery_source,
    a.last_observed_at, a.account_state, c.status AS connection_status
    FROM discovered_accounts a LEFT JOIN email_connections c ON c.id = a.connection_id AND c.user_id = a.user_id
    WHERE a.user_id = $1 AND a.service_domain = ANY($2::text[]) AND a.status <> 'dismissed'
    ORDER BY a.last_observed_at DESC NULLS LAST LIMIT 100`, [userId, candidates]);
  const known = rows.some((r) => r.status === 'confirmed');
  return {
    domain: n.hostname,
    state: known ? 'account_known' : rows.length ? 'possible_association' : 'no_match',
    message: known ? 'Account known, login status unknown.' : rows.length ? 'Possible account association; confirmation is needed.' : 'No matching account found in your FootprintX inventory.',
    login: { state: 'unavailable', message: 'Login status unavailable. FootprintX has no supported signal for your current session.' },
    matches: rows.map((r) => ({ id: r.id, serviceName: r.service_name, association: r.status, confidence: r.confidence, source: r.discovery_source, observedAt: r.last_observed_at, accountState: r.account_state, sourceStatus: r.connection_status || 'manual' })),
    checkedAt: new Date().toISOString(),
    limitation: 'Inventory evidence may be partial or historical. Account recognition does not establish a current login or website safety.',
  };
}
