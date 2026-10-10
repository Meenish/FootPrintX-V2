// Website/domain reputation. Separate from breach intelligence and account
// discovery: a website check never creates or changes an account record.
//
// Data: a local threat dataset (threat_indicators) refreshed from configured
// feeds. Lookups never require sending a visited URL to a third party:
//   * the browser extension sends only 32-bit SHA-256 hash prefixes of the
//     hostname and its parent domains; the server returns full hashes for
//     matching entries and the extension compares locally;
//   * the web app's manual check sends the domain the user typed (disclosed).
// Statuses (shared/src/threat.js): no_known_threat, suspicious, malicious,
// unknown, unavailable. Errors and stale/empty datasets are never "clean".
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import { query, queryOne } from '../db.js';
import { getConfig } from '../config.js';
import { log } from '../logger.js';
import { normalizeHost, buildHashLookup, indicatorMatches, hostCandidates, HASH_PREFIX_HEX_LENGTH } from '@footprintx/shared/domain';
import { validateIndicatorHost, combineVerdict, STATUS_EXPLANATION, REPUTATION_STATUS } from '@footprintx/shared/threat';
import { analyzeLookalike } from '@footprintx/shared/lookalike';
import { HttpError } from '../http.js';
import { createAlert } from './notifications.js';
import { recalculate } from './risk.js';

export const FEEDS = Object.freeze({
  phishing_database: {
    label: 'Phishing.Database — active phishing domains',
    url: 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt',
    homepage: 'https://github.com/mitchellkrogza/Phishing.Database',
    threatType: 'phishing',
  },
});

const FETCH_TIMEOUT_MS = 90e3;
const MAX_FEED_BYTES = 64 * 1024 * 1024;
const CHUNK = 2000;
// If a feed suddenly shrinks this much, assume a truncated/broken download and
// keep the previous entries active rather than silently dropping protection.
const MIN_RETAIN_RATIO = 0.5;

const sha256Hex = (s) => crypto.createHash('sha256').update(s).digest('hex');

export function parseFeed(text, maxEntries) {
  const accepted = new Set();
  const rejected = {};
  let fetched = 0;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/#.*/, '').trim();
    if (!line) continue;
    fetched += 1;
    // hosts-file style "0.0.0.0 domain" or plain "domain"
    const host = line.split(/[\s,]+/).filter(Boolean).pop();
    const v = validateIndicatorHost(host);
    if (v.rejected) rejected[v.rejected] = (rejected[v.rejected] || 0) + 1;
    else if (accepted.size < maxEntries) accepted.add(v.hostname);
    else rejected.over_limit = (rejected.over_limit || 0) + 1;
  }
  return { fetched, accepted: [...accepted], rejected };
}

async function fetchFeedText(feed) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(feed.url, { signal: ctrl.signal, headers: { 'user-agent': 'FootprintX/2.0 threat-sync' } });
    if (!res.ok) throw new Error(`Feed responded with HTTP ${res.status}`);
    const len = Number(res.headers.get('content-length') || 0);
    if (len > MAX_FEED_BYTES) throw new Error('Feed too large');
    const text = await res.text();
    if (text.length > MAX_FEED_BYTES) throw new Error('Feed too large');
    return text;
  } finally {
    clearTimeout(t);
  }
}

/** Ingests one feed. `source` is the feed id; `text` may be supplied (tests, local file). */
export async function syncFeed(source, { text, threatType = 'phishing' } = {}) {
  const run = await queryOne(`INSERT INTO threat_feed_runs (source, status) VALUES ($1, 'running') RETURNING id, started_at`, [source]);
  try {
    let body = text;
    if (body === undefined) {
      if (source === 'local_file') body = await fs.readFile(getConfig().threat.feedFile, 'utf8');
      else if (FEEDS[source]) body = await fetchFeedText(FEEDS[source]);
      else throw new Error(`Unknown feed "${source}"`);
      threatType = FEEDS[source]?.threatType || threatType;
    }
    const parsed = parseFeed(body, getConfig().threat.maxEntries);
    const runAt = new Date();
    let added = 0;
    const newHosts = [];
    for (let i = 0; i < parsed.accepted.length; i += CHUNK) {
      const hosts = parsed.accepted.slice(i, i + CHUNK);
      const full = hosts.map(sha256Hex);
      const rows = await query(
        `INSERT INTO threat_indicators (hostname, source, hash_full, hash_prefix, category, threat_type, active, first_seen_at, last_seen_at)
         SELECT h, $2, f, left(f, ${HASH_PREFIX_HEX_LENGTH}), 'malicious', $3, true, $4, $4 FROM unnest($1::text[], $5::text[]) AS t(h, f)
         ON CONFLICT (hostname, source) DO UPDATE SET active = true, last_seen_at = EXCLUDED.last_seen_at
         RETURNING hostname, (xmax = 0) AS inserted`,
        [hosts, source, threatType, runAt, full]
      );
      for (const r of rows) if (r.inserted) {
        added += 1;
        if (newHosts.length < 50000) newHosts.push(r.hostname);
      }
    }
    const prevActive = await queryOne('SELECT count(*)::int AS n FROM threat_indicators WHERE source = $1 AND active', [source]);
    let deactivated = 0;
    if (parsed.accepted.length >= prevActive.n * MIN_RETAIN_RATIO) {
      const rows = await query('UPDATE threat_indicators SET active = false WHERE source = $1 AND active AND last_seen_at < $2 RETURNING hostname', [source, runAt]);
      deactivated = rows.length;
    } else {
      log.warn('threat feed shrank sharply; previous entries kept active', { source, accepted: parsed.accepted.length, previous: prevActive.n });
    }
    const rejectedCount = Object.values(parsed.rejected).reduce((a, b) => a + b, 0);
    await query(
      `UPDATE threat_feed_runs SET status = 'ok', fetched_count = $2, accepted_count = $3, rejected_count = $4, added_count = $5, deactivated_count = $6, rejected_by_reason = $7::jsonb, finished_at = now() WHERE id = $1`,
      [run.id, parsed.fetched, parsed.accepted.length, rejectedCount, added, deactivated, JSON.stringify(parsed.rejected)]
    );
    // Previously-seen runs exist → this is an update; alert users whose data it affects.
    const hadPrevious = await queryOne(`SELECT 1 AS x FROM threat_feed_runs WHERE source = $1 AND status = 'ok' AND id <> $2 LIMIT 1`, [source, run.id]);
    if (hadPrevious && newHosts.length) await notifyThreatUpdate(newHosts, source);
    return { source, fetched: parsed.fetched, accepted: parsed.accepted.length, rejected: parsed.rejected, added, deactivated };
  } catch (err) {
    await query(`UPDATE threat_feed_runs SET status = 'failed', error = $2, finished_at = now() WHERE id = $1`, [run.id, String(err.message).slice(0, 300)]);
    log.error('threat feed sync failed', { source, err });
    throw err;
  }
}

export async function syncAllFeeds() {
  const cfg = getConfig().threat;
  const results = [];
  for (const f of cfg.feeds) {
    if (!FEEDS[f]) {
      log.warn('unknown threat feed in THREAT_FEEDS ignored', { feed: f });
      continue;
    }
    results.push(await syncFeed(f).catch((err) => ({ source: f, error: err.message })));
  }
  if (cfg.feedFile) results.push(await syncFeed('local_file').catch((err) => ({ source: 'local_file', error: err.message })));
  return results;
}

/** When new indicators appear, re-evaluate what users already have. */
async function notifyThreatUpdate(newHosts, source) {
  const set = new Set(newHosts);
  // 1. Tracked account domains (exact registrable-domain listing only).
  const accounts = await query('SELECT DISTINCT user_id FROM discovered_accounts WHERE service_domain = ANY($1::text[])', [newHosts]);
  for (const a of accounts) await recalculate(a.user_id, 'threat_update').catch((err) => log.error('recalc after threat update failed', { err }));
  // 2. Domains the user was shown or checked recently (synced extension events, manual checks).
  const seen = await query(
    `SELECT user_id, domain, max(at) AS at FROM (
        SELECT user_id, domain, occurred_at AS at FROM extension_events WHERE occurred_at > now() - interval '30 days' AND status <> 'malicious'
        UNION ALL SELECT user_id, domain, checked_at AS at FROM domain_checks WHERE checked_at > now() - interval '30 days' AND status <> 'malicious'
     ) s GROUP BY user_id, domain`
  );
  for (const s of seen) {
    const match = hostCandidates(s.domain).find((c) => set.has(c));
    if (!match) continue;
    await createAlert(s.user_id, {
      kind: 'threat_intel',
      severity: 'high',
      title: `A site you visited is now listed as a threat: ${s.domain}`,
      body: `New threat intelligence (${source}) lists ${match === s.domain ? s.domain : `${match}, which ${s.domain} belongs to`}. If you entered a password or payment details there, change that password on the real site and watch for unusual activity.`,
      domain: s.domain,
      dedupKey: `threat_update:${s.domain}`,
    });
  }
}

export async function datasetStatus() {
  const runs = await query(
    `SELECT DISTINCT ON (source) source, status, finished_at, accepted_count, added_count, deactivated_count, rejected_by_reason, error FROM threat_feed_runs ORDER BY source, started_at DESC`
  );
  const lastOk = await queryOne(`SELECT max(finished_at) AS at FROM threat_feed_runs WHERE status = 'ok'`);
  const count = await queryOne('SELECT count(*)::int AS n FROM threat_indicators WHERE active');
  const ageHours = lastOk?.at ? (Date.now() - new Date(lastOk.at).getTime()) / 3600e3 : null;
  const maxAge = getConfig().threat.maxDatasetAgeHours;
  let reason = null;
  if (!lastOk?.at || count.n === 0) reason = 'DATASET_NOT_LOADED';
  else if (ageHours > maxAge) reason = 'DATASET_STALE';
  return {
    usable: !reason,
    reason,
    version: lastOk?.at ? `${new Date(lastOk.at).getTime()}-${count.n}` : null,
    updatedAt: lastOk?.at || null,
    ageHours: ageHours == null ? null : Math.round(ageHours * 10) / 10,
    maxAgeHours: maxAge,
    indicatorCount: count.n,
    sources: runs.map((r) => ({ source: r.source, label: FEEDS[r.source]?.label || (r.source === 'local_file' ? 'Local threat file' : r.source), status: r.status, finishedAt: r.finished_at, accepted: r.accepted_count, rejectedByReason: r.rejected_by_reason, error: r.status === 'failed' ? 'Last update failed' : null })),
  };
}

const PREFIX_RE = new RegExp(`^[0-9a-f]{${HASH_PREFIX_HEX_LENGTH}}$`);

/** Hash-prefix lookup for the extension. Returns full hashes of matching entries. */
export async function lookupPrefixes(prefixes) {
  if (!Array.isArray(prefixes) || !prefixes.length || prefixes.length > 10 || !prefixes.every((p) => typeof p === 'string' && PREFIX_RE.test(p))) {
    throw new HttpError(400, 'INVALID_PREFIXES', `Send 1–10 lowercase hex prefixes of ${HASH_PREFIX_HEX_LENGTH} characters.`);
  }
  const rows = await query(
    `SELECT hash_full, source, threat_type, min(first_seen_at) AS first_seen_at, max(last_seen_at) AS last_seen_at FROM threat_indicators
      WHERE active AND hash_prefix = ANY($1::text[]) GROUP BY hash_full, source, threat_type LIMIT 200`,
    [[...new Set(prefixes)]]
  );
  const ds = await datasetStatus();
  return {
    matches: rows.map((r) => ({ fullHash: r.hash_full, source: r.source, sourceLabel: FEEDS[r.source]?.label || r.source, threatType: r.threat_type, firstSeenAt: r.first_seen_at, lastSeenAt: r.last_seen_at })),
    dataset: { usable: ds.usable, reason: ds.reason, version: ds.version, updatedAt: ds.updatedAt, ageHours: ds.ageHours },
  };
}

/** Full check of one domain (web app manual check; Free plan). */
export async function checkDomain(userId, input) {
  const n = normalizeHost(input);
  if (!n) throw new HttpError(400, 'INVALID_DOMAIN', 'Enter a website address such as example.com.');
  if (n.isLocal) throw new HttpError(400, 'LOCAL_DOMAIN', 'Local and private network addresses are not checked.');
  const heuristics = analyzeLookalike(n.hostname);
  let lookup;
  let ds = null;
  try {
    ds = await datasetStatus();
    const entries = await buildHashLookup(n.hostname);
    const fulls = entries.map((e) => e.fullHash);
    const rows = fulls.length
      ? await query(`SELECT hostname, source, threat_type, first_seen_at, last_seen_at FROM threat_indicators WHERE active AND hash_full = ANY($1::text[])`, [fulls])
      : [];
    const matches = rows
      .filter((r) => indicatorMatches(n.hostname, r.hostname))
      .map((r) => ({ matchedHost: r.hostname, matchType: r.hostname === n.hostname ? 'exact' : 'parent_domain', source: r.source, sourceLabel: FEEDS[r.source]?.label || r.source, threatType: r.threat_type, firstSeenAt: r.first_seen_at, lastSeenAt: r.last_seen_at }));
    lookup = { ok: true, matches, datasetUsable: ds.usable, datasetReason: ds.reason };
  } catch (err) {
    log.error('reputation lookup failed', { err });
    lookup = { ok: false, errorCode: 'LOOKUP_FAILED' };
  }
  const verdict = combineVerdict({ lookup, heuristics });
  const result = {
    domain: n.hostname,
    displayDomain: n.unicodeHostname,
    registrableDomain: n.registrableDomain,
    status: verdict.status,
    reasons: verdict.reasons,
    explanation: STATUS_EXPLANATION[verdict.status],
    dataset: ds ? { version: ds.version, updatedAt: ds.updatedAt, ageHours: ds.ageHours, usable: ds.usable } : null,
    checkedAt: new Date().toISOString(),
  };
  if (verdict.status !== REPUTATION_STATUS.UNAVAILABLE) {
    await query('INSERT INTO domain_checks (user_id, domain, status, reasons, dataset_version) VALUES ($1, $2, $3, $4::jsonb, $5)', [userId, n.hostname, verdict.status, JSON.stringify(verdict.reasons.map((r) => r.code)), ds?.version || null]);
  }
  return result;
}

export async function reportFalsePositive(userId, { domain, reportedStatus, note }) {
  const n = normalizeHost(domain);
  if (!n) throw new HttpError(400, 'INVALID_DOMAIN', 'Invalid domain.');
  await query('INSERT INTO false_positive_reports (user_id, domain, reported_status, note) VALUES ($1, $2, $3, $4)', [userId, n.hostname, reportedStatus, note ? String(note).slice(0, 500) : null]);
}
