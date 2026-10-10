// DASI — Digital Attack Surface Index. FootprintX's own, project-defined
// methodology (NOT an industry standard). Pure functions only: same input and
// model version always give the same output. Full specification with
// rationale: docs/DASI.md. Keep the two in sync and bump MODEL_VERSION on any
// change to weights, thresholds or aggregation.
//
// Direction: 0–100, higher = greater observed risk.
// Unknowns are never scored as safe: they widen the "upper bound" (the score
// if every unknown turned out unfavourable) and lower the stated confidence.
import { CATEGORY_IMPACT } from './catalog.js';

export const MODEL_VERSION = 'dasi-2.0.0';

const DAY = 864e5;

export const WEIGHTS = Object.freeze({
  BASE_EXPOSURE: 3, // every confirmed, open account is attack surface
  CREDENTIAL_EXPOSURE_PASSWORD: 40, // listed in a breach that included passwords
  CREDENTIAL_EXPOSURE_OTHER: 15, // listed in a breach without password data
  ADDITIONAL_BREACH: 5, // each further distinct breach of the same account...
  ADDITIONAL_BREACH_CAP: 10, // ...capped (correlated evidence)
  ALERT_30D: 30,
  ALERT_90D: 20,
  ALERT_365D: 8,
  MFA_DISABLED: 12,
  DORMANT: 6, // no mailbox evidence for 2+ years (inactivity NOT confirmed)
  THREAT_LISTED: 35,
});

export const CONFIDENCE_WEIGHT = Object.freeze({ high: 1.0, medium: 0.7, low: 0.5 });

// Remediation adjustments applied to the *current* component only. History
// (the breach record itself) is never removed.
export const REMEDIATION_MULTIPLIER = Object.freeze({
  verified: 0.2, // e.g. a "password changed" security email from the service after the breach
  user_reported: 0.5, // the user told us; we could not independently verify
});
// MFA reduces the chance that an exposed password alone leads to takeover.
export const MFA_DAMPENING = Object.freeze({ mailbox_evidence: 0.6, user_reported: 0.8 });

export const ACCOUNT_LEVELS = Object.freeze([
  { min: 70, level: 'critical' },
  { min: 45, level: 'high' },
  { min: 20, level: 'medium' },
  { min: 0, level: 'low' },
]);
export const DASI_LEVELS = Object.freeze([
  { min: 80, level: 'severe', label: 'Severe' },
  { min: 60, level: 'high', label: 'High' },
  { min: 40, level: 'elevated', label: 'Elevated' },
  { min: 20, level: 'guarded', label: 'Guarded' },
  { min: 0, level: 'low', label: 'Low' },
]);

export const AGGREGATION = Object.freeze({ DECAY: 0.5, CORE_SCALE: 0.6, BREADTH_PER_LN: 2.5, BREADTH_CAP: 15 });

const REPORTED_STATES = new Set(['user_reported', 'verification_pending', 'unable_to_verify']);
const clamp = (n, lo = 0, hi = 100) => Math.max(lo, Math.min(hi, n));
const levelFor = (score, table) => (score == null ? null : table.find((t) => score >= t.min));
const ts = (d) => (d ? new Date(d).getTime() : null);

function remediationState(rem, afterTs) {
  // A remediation only counts if it happened after the risk arose.
  if (!rem) return null;
  const at = ts(rem.at);
  if (afterTs && at && at < afterTs) return null;
  if (rem.status === 'verified') return 'verified';
  if (REPORTED_STATES.has(rem.status)) return 'user_reported';
  return null;
}

/**
 * Account-level assessment.
 * @param {object} a  see buildAccountInput() in dasiService.js for the shape
 * @param {number} now epoch ms
 */
export function assessAccount(a, now = Date.now()) {
  const factors = [];
  const unknowns = [];
  const critical = [];
  if (a.status !== 'confirmed') {
    return { score: null, upper: null, level: null, factors, unknowns, critical, excluded: a.status === 'possible' ? 'unconfirmed' : 'dismissed' };
  }
  if (a.accountState === 'closed_user_reported' || a.accountState === 'closed_evidence') {
    return { score: 0, upper: 0, level: 'low', factors, unknowns, critical, excluded: 'closed' };
  }
  const impact = CATEGORY_IMPACT[a.category] ?? 1;
  const mfaStatus = a.mfa?.status || 'unknown';
  const mfaDamp = mfaStatus === 'enabled' ? MFA_DAMPENING[a.mfa.source] ?? 1 : 1;

  factors.push({ code: 'BASE_EXPOSURE', label: 'Account exists', points: WEIGHTS.BASE_EXPOSURE, confidence: 'high', effective: WEIGHTS.BASE_EXPOSURE, provenance: a.discoverySource, reduceBy: 'Close the account if you no longer need it.' });

  // Credential exposure: correlated breach evidence counted once (max) plus a small capped increment.
  const breaches = a.breaches || [];
  if (breaches.length) {
    const pw = breaches.some((b) => b.passwordExposed);
    const latestBreach = Math.max(...breaches.map((b) => ts(b.date) || 0));
    let points = pw ? WEIGHTS.CREDENTIAL_EXPOSURE_PASSWORD : WEIGHTS.CREDENTIAL_EXPOSURE_OTHER;
    points += Math.min(WEIGHTS.ADDITIONAL_BREACH_CAP, (breaches.length - 1) * WEIGHTS.ADDITIONAL_BREACH);
    const conf = breaches.every((b) => b.providerVerified !== false) ? 'high' : 'medium';
    const rem = remediationState(a.remediation?.change_password, latestBreach || null);
    const remMult = rem ? REMEDIATION_MULTIPLIER[rem] : 1;
    const effective = points * CONFIDENCE_WEIGHT[conf] * remMult * mfaDamp;
    factors.push({
      code: pw ? 'CREDENTIAL_EXPOSURE_PASSWORD' : 'CREDENTIAL_EXPOSURE',
      label: pw ? 'Listed in a breach that exposed passwords' : 'Listed in a data breach (no passwords reported)',
      points,
      confidence: conf,
      remediation: rem,
      mfaDampening: mfaDamp < 1 ? mfaDamp : undefined,
      effective,
      provenance: breaches.map((b) => `${b.provider || 'breach provider'}: ${b.title}${b.date ? ` (${new Date(b.date).getFullYear()})` : ''}`),
      reduceBy: 'Change the password on the official site (and anywhere you reused it), then turn on two-step verification. The historical breach record remains.',
    });
    if (pw && !rem) critical.push({ code: 'UNREMEDIATED_PASSWORD_EXPOSURE', message: `${a.serviceName}: a breach exposed passwords and no password change has been recorded since.` });
  }

  // Security alerts (evidence of an event, e.g. "new sign-in" email).
  if (a.latestAlertAt) {
    const age = (now - ts(a.latestAlertAt)) / DAY;
    const points = age <= 30 ? WEIGHTS.ALERT_30D : age <= 90 ? WEIGHTS.ALERT_90D : age <= 365 ? WEIGHTS.ALERT_365D : 0;
    if (points > 0) {
      const conf = a.alertAuthenticated ? 'high' : 'medium';
      const rem = remediationState(a.remediation?.review_sessions, ts(a.latestAlertAt));
      const remMult = rem ? REMEDIATION_MULTIPLIER[rem] : 1;
      factors.push({
        code: 'RECENT_SECURITY_ALERT',
        label: `Security alert email ${Math.round(age)} day(s) ago`,
        points,
        confidence: conf,
        remediation: rem,
        effective: points * CONFIDENCE_WEIGHT[conf] * remMult,
        provenance: [`Mailbox evidence observed ${new Date(a.latestAlertAt).toISOString().slice(0, 10)}`],
        reduceBy: 'Review recent sign-ins and active sessions on the official site and sign out devices you do not recognise.',
      });
      if (age <= 30 && !rem) critical.push({ code: 'RECENT_ALERT_UNREVIEWED', message: `${a.serviceName}: a security alert arrived in the last 30 days and has not been reviewed.` });
    }
  }

  // MFA: only a known "disabled" adds points; "unknown" widens the upper bound.
  if (mfaStatus === 'disabled') {
    factors.push({
      code: 'MFA_DISABLED',
      label: 'Two-step verification reported as turned off',
      points: WEIGHTS.MFA_DISABLED,
      confidence: 'medium',
      effective: WEIGHTS.MFA_DISABLED * CONFIDENCE_WEIGHT.medium,
      provenance: [a.mfa.source === 'user_reported' ? 'Reported by you' : 'Security notification email'],
      reduceBy: 'Turn on two-step verification on the official site.',
    });
    if (impact >= 1.3) critical.push({ code: 'MFA_OFF_HIGH_IMPACT', message: `${a.serviceName}: two-step verification appears to be off on a high-impact account.` });
  } else if (mfaStatus === 'unknown') {
    unknowns.push({ code: 'MFA_UNKNOWN', label: 'Two-step verification status unknown', worstCasePoints: WEIGHTS.MFA_DISABLED * CONFIDENCE_WEIGHT.medium });
  }
  if (a.exposureStatus === 'unknown') unknowns.push({ code: 'EXPOSURE_NOT_CHECKED', label: 'Breach exposure not checked', worstCasePoints: 0 });

  // Dormancy: absence of mailbox evidence is weak evidence of inactivity.
  if (a.lastObservedAt && (now - ts(a.lastObservedAt)) / DAY > 730 && a.discoverySource !== 'manual') {
    factors.push({
      code: 'DORMANT',
      label: 'No account activity seen in your mailbox for 2+ years',
      points: WEIGHTS.DORMANT,
      confidence: 'low',
      effective: WEIGHTS.DORMANT * CONFIDENCE_WEIGHT.low,
      provenance: [`Last mailbox evidence ${new Date(a.lastObservedAt).toISOString().slice(0, 10)}`],
      reduceBy: 'If you no longer use this account, close it on the official site.',
    });
  }

  if (a.threatListed) {
    factors.push({
      code: 'THREAT_LISTED',
      label: 'Service domain appears in a threat-intelligence dataset',
      points: WEIGHTS.THREAT_LISTED,
      confidence: 'medium',
      effective: WEIGHTS.THREAT_LISTED * CONFIDENCE_WEIGHT.medium,
      provenance: a.threatSources || [],
      reduceBy: 'Avoid signing in through links; verify the address independently.',
    });
    critical.push({ code: 'THREAT_LISTED', message: `${a.serviceName}: the service domain is listed in a threat dataset.` });
  }

  const raw = factors.reduce((s, f) => s + f.effective, 0);
  const worst = unknowns.reduce((s, u) => s + u.worstCasePoints, 0);
  const score = clamp(Math.round(raw * impact));
  const upper = clamp(Math.round((raw + worst) * impact));
  for (const f of factors) f.effective = Math.round(f.effective * impact * 10) / 10;
  return { score, upper, level: levelFor(score, ACCOUNT_LEVELS).level, impact, factors, unknowns, critical, excluded: null };
}

function aggregate(scores) {
  const sorted = [...scores].sort((x, y) => y - x);
  const core = sorted.reduce((s, v, i) => s + v * AGGREGATION.DECAY ** i, 0);
  const breadth = Math.min(AGGREGATION.BREADTH_CAP, AGGREGATION.BREADTH_PER_LN * Math.log(1 + sorted.length));
  return clamp(Math.round(AGGREGATION.CORE_SCALE * core + breadth));
}

/**
 * Coverage → confidence. Inputs describe how much evidence exists, not risk.
 */
export function assessConfidence(c) {
  const fresh = c.activeConnections > 0 && c.connectionsScannedRecently === c.activeConnections;
  const breachOk = c.activeConnections > 0 && c.connectionsBreachCheckedRecently === c.activeConnections;
  const mfaShare = c.confirmedAccounts ? c.accountsWithKnownMfa / c.confirmedAccounts : 0;
  let confidence = 'low';
  if (fresh && c.lastScanComplete && breachOk && mfaShare >= 0.5) confidence = 'high';
  else if (fresh && (breachOk || mfaShare >= 0.25)) confidence = 'medium';
  const gaps = [];
  if (!c.activeConnections) gaps.push('No mailbox is connected, so discovery relies on manual entries only.');
  else if (!fresh) gaps.push('At least one connected mailbox has not been scanned successfully in the last 30 days.');
  if (fresh && !c.lastScanComplete) gaps.push('The latest scan only partially completed.');
  if (!breachOk) gaps.push('Breach exposure has not been checked recently for every connected mailbox.');
  if (mfaShare < 0.5) gaps.push('Two-step verification status is unknown for most accounts.');
  return { confidence, gaps, mfaKnownShare: Math.round(mfaShare * 100) / 100 };
}

/**
 * User-level DASI from assessed accounts.
 * @param accounts [{ id, serviceName, risk: assessAccount() result }]
 * @param coverage see assessConfidence()
 */
export function computeDasi(accounts, coverage) {
  const included = accounts.filter((a) => a.risk.score != null && !a.risk.excluded);
  const hasEvidence = coverage.everScanned || accounts.some((a) => a.manual);
  if (!hasEvidence) {
    return { modelVersion: MODEL_VERSION, score: null, upper: null, level: null, levelLabel: 'Not assessed', confidence: 'none', coverage: { ...coverage, gaps: ['No scan has completed yet.'] }, contributors: [], criticalFindings: [] };
  }
  const score = aggregate(included.map((a) => a.risk.score));
  const upper = Math.max(score, aggregate(included.map((a) => a.risk.upper)));
  const conf = assessConfidence(coverage);
  const lvl = levelFor(score, DASI_LEVELS);
  const contributors = included
    .filter((a) => a.risk.score > 0)
    .sort((x, y) => y.risk.score - x.risk.score)
    .slice(0, 10)
    .map((a) => ({ accountId: a.id, serviceName: a.serviceName, score: a.risk.score, factors: a.risk.factors.filter((f) => f.code !== 'BASE_EXPOSURE').map((f) => ({ code: f.code, effective: f.effective })) }));
  const criticalFindings = included.flatMap((a) => a.risk.critical.map((c) => ({ ...c, accountId: a.id, serviceName: a.serviceName })));
  return {
    modelVersion: MODEL_VERSION,
    score,
    upper,
    level: lvl.level,
    levelLabel: lvl.label,
    confidence: conf.confidence,
    coverage: { ...coverage, gaps: conf.gaps, mfaKnownShare: conf.mfaKnownShare, accountsAssessed: included.length },
    contributors,
    criticalFindings,
  };
}

/**
 * Explains a score change by diffing per-account contributions between the
 * previous snapshot and the new result. Returns the largest movements.
 */
export const FACTOR_LABELS = Object.freeze({
  CREDENTIAL_EXPOSURE_PASSWORD: 'password exposed in a breach',
  CREDENTIAL_EXPOSURE: 'listed in a breach',
  RECENT_SECURITY_ALERT: 'recent security alert',
  MFA_DISABLED: 'two-step verification off',
  DORMANT: 'no activity for 2+ years',
  THREAT_LISTED: 'domain on a threat list',
});
const label = (code) => FACTOR_LABELS[code] || code;

export function explainChange(previous, current) {
  if (!previous) return [{ kind: 'first_assessment', message: 'First assessment.' }];
  const reasons = [];
  if (previous.model_version !== current.modelVersion) reasons.push({ kind: 'model_change', message: `Scoring model updated from ${previous.model_version} to ${current.modelVersion}.` });
  const before = new Map((previous.contributors || []).map((c) => [c.accountId, c]));
  const after = new Map(current.contributors.map((c) => [c.accountId, c]));
  const ids = new Set([...before.keys(), ...after.keys()]);
  const moves = [];
  for (const id of ids) {
    const b = before.get(id);
    const a = after.get(id);
    const delta = (a?.score || 0) - (b?.score || 0);
    if (!delta) continue;
    const bCodes = new Set((b?.factors || []).map((f) => f.code));
    const aCodes = new Set((a?.factors || []).map((f) => f.code));
    const added = [...aCodes].filter((c) => !bCodes.has(c));
    const removed = [...bCodes].filter((c) => !aCodes.has(c));
    moves.push({ accountId: id, serviceName: a?.serviceName || b?.serviceName, delta, added, removed });
  }
  moves.sort((x, y) => Math.abs(y.delta) - Math.abs(x.delta));
  for (const m of moves.slice(0, 5)) {
    const parts = [];
    if (m.added.length) parts.push(`new: ${m.added.map(label).join(', ')}`);
    if (m.removed.length) parts.push(`no longer present: ${m.removed.map(label).join(', ')}`);
    if (!parts.length) parts.push(m.delta < 0 ? 'risk reduced (e.g. remediation or older evidence)' : 'risk increased');
    reasons.push({ kind: 'account', accountId: m.accountId, serviceName: m.serviceName, delta: m.delta, message: `${m.serviceName} ${m.delta > 0 ? '+' : ''}${m.delta}: ${parts.join('; ')}` });
  }
  if (previous.confidence !== current.confidence) reasons.push({ kind: 'confidence', message: `Confidence changed from ${previous.confidence} to ${current.confidence}.` });
  return reasons.length ? reasons : [{ kind: 'none', message: 'Evidence was re-evaluated; no factor changed materially.' }];
}
