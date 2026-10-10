// Unit tests: discovery classification, DASI scoring, recommendation rules, breach normalizers.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyMessage, identifyService, addMessage, finalize, parseAuthResults } from '../src/services/discovery.js';
import { assessAccount, computeDasi, explainChange, assessConfidence, MODEL_VERSION, WEIGHTS } from '../src/services/dasi.js';
import { recommendationsFor } from '../src/services/recommendationRules.js';
import { officialLinkFor, registeredOfficialDomains, categoryFor } from '../src/services/catalog.js';
import { normalizeXon, normalizeHibp, exposesPasswords } from '../src/services/breach.js';

const DAY = 864e5;
const NOW = Date.UTC(2026, 9, 10);
const msg = (id, from, subject, daysAgo, auth = 'dmarc=pass') => ({ id, from, subject, internalDate: NOW - daysAgo * DAY, authResults: auth });

// ---- Discovery -------------------------------------------------------------------
test('discovery: classifies strong, weak and ignored evidence', () => {
  assert.deepEqual(classifyMessage({ subject: 'Welcome to GitHub' }), { kind: 'signup', strength: 'strong' });
  assert.deepEqual(classifyMessage({ subject: 'Verify your email address' }), { kind: 'signup', strength: 'strong' });
  assert.equal(classifyMessage({ subject: 'Unusual sign-in activity detected' }).kind, 'security_alert');
  assert.equal(classifyMessage({ subject: 'New sign-in on Linux' }).kind, 'login_notice');
  assert.equal(classifyMessage({ subject: 'Your password was changed' }).kind, 'password_changed');
  assert.equal(classifyMessage({ subject: 'Two-step verification is now turned on' }).kind, 'mfa_enabled');
  assert.equal(classifyMessage({ subject: '2-Step Verification turned off' }).kind, 'mfa_disabled');
  assert.equal(classifyMessage({ subject: 'Your account has been deleted' }).kind, 'account_closed');
  assert.deepEqual(classifyMessage({ subject: 'Your receipt from Example' }), { kind: 'billing', strength: 'weak' });
  assert.equal(classifyMessage({ subject: 'Welcome to our weekly digest' }).strength, 'ignored');
  assert.equal(classifyMessage({ subject: 'Lunch on Friday?' }), null);
});

test('discovery: identifies services by registrable domain, ignores personal mailbox senders', () => {
  assert.deepEqual(identifyService('GitHub <noreply@github.com>').domain, 'github.com');
  assert.equal(identifyService('Bank <alerts@mail.hdfcbank.com>').domain, 'hdfcbank.com');
  assert.equal(identifyService('Friend <friend@gmail.com>'), null);
  assert.equal(identifyService('Google <no-reply@accounts.google.com>').domain, 'google.com');
  assert.equal(identifyService('YouTube <no-reply@youtube.com>').domain, 'google.com');
  const platform = identifyService('Swiggy <noreply@sendgrid.net>');
  assert.equal(platform.domain, null);
  assert.equal(platform.key, 'name:swiggy');
  assert.equal(identifyService('garbage'), null);
});

test('discovery: sender authentication parsing', () => {
  assert.equal(parseAuthResults('mx.google.com; dkim=pass; spf=pass; dmarc=pass (p=REJECT) header.from=github.com', 'github.com'), 'pass');
  assert.equal(parseAuthResults('spf=fail; dkim=none; dmarc=fail header.from=paypal.com', 'paypal.com'), 'fail');
  assert.equal(parseAuthResults('dkim=pass header.i=@github.com', 'github.com'), 'pass');
  assert.equal(parseAuthResults('', 'x.com'), 'unknown');
});

test('discovery: weak evidence never becomes a confirmed account; newsletters never create records', () => {
  const found = new Map();
  addMessage(found, msg('1', 'Shop <orders@shop.example>', 'Your receipt', 10), 'r1');
  addMessage(found, msg('2', 'News <news@media.example>', 'Weekly digest', 2), 'r2');
  addMessage(found, msg('3', 'News <news@media.example>', 'Weekly digest', 3), 'r3');
  let out = finalize(found);
  assert.equal(out.length, 0, 'one receipt and newsletters are not enough');
  addMessage(found, msg('4', 'Shop <orders@shop.example>', 'Your order confirmation', 20), 'r4');
  out = finalize(found);
  assert.equal(out.length, 1);
  assert.equal(out[0].status, 'possible');
  assert.equal(out[0].confidence, 'low');
});

test('discovery: spoofed (DMARC-failing) security mail is downgraded and cannot confirm an account', () => {
  const found = new Map();
  addMessage(found, msg('1', 'PayPal <service@paypal.com>', 'Security alert: unusual sign-in', 1, 'spf=fail; dkim=none; dmarc=fail'), 'r1');
  assert.equal(finalize(found).length, 0);
});

test('discovery: de-duplicates services across messages and derives MFA and closure from the latest evidence', () => {
  const found = new Map();
  addMessage(found, msg('1', 'Dropbox <no-reply@dropbox.com>', 'Verify your email', 500), 'a');
  addMessage(found, msg('2', 'Dropbox <no-reply@em.dropbox.com>', 'Two-step verification is now turned on', 300), 'b');
  addMessage(found, msg('3', 'Dropbox <no-reply@dropbox.com>', 'Two-step verification was turned off', 100), 'c');
  addMessage(found, msg('4', 'Netflix <info@account.netflix.com>', 'Welcome to Netflix', 300), 'd');
  addMessage(found, msg('5', 'Netflix <info@account.netflix.com>', 'Your account has been closed', 10), 'e');
  const out = finalize(found);
  assert.equal(out.length, 2);
  const dropbox = out.find((a) => a.serviceDomain === 'dropbox.com');
  assert.equal(dropbox.status, 'confirmed');
  assert.equal(dropbox.confidence, 'high');
  assert.equal(dropbox.mfa.status, 'disabled');
  assert.equal(dropbox.evidence.length, 3);
  assert.equal(dropbox.serviceName, 'Dropbox');
  const netflix = out.find((a) => a.serviceDomain === 'netflix.com');
  assert.ok(netflix.closedAt);
  // Nothing derived from message text is kept except the classified kind.
  assert.ok(!JSON.stringify(out).includes('turned off'));
});

// ---- DASI ----------------------------------------------------------------------------
const base = (over = {}) => ({
  id: 'a1', serviceName: 'Example', serviceDomain: 'example.com', category: 'other', status: 'confirmed', accountState: 'unknown', discoverySource: 'gmail_metadata',
  exposureStatus: 'no_evidence_found', mfa: { status: 'unknown', source: null }, breaches: [], latestAlertAt: null, lastObservedAt: new Date(NOW - 10 * DAY), threatListed: false, remediation: {}, ...over,
});
const pwBreach = { provider: 'xposedornot', title: 'Example', date: '2019-01-01', passwordExposed: true, providerVerified: true };

test('dasi: deterministic for the same input and model version', () => {
  const a = assessAccount(base({ breaches: [pwBreach] }), NOW);
  const b = assessAccount(base({ breaches: [pwBreach] }), NOW);
  assert.deepEqual(a, b);
  assert.equal(MODEL_VERSION, 'dasi-2.0.0');
});

test('dasi: unknown MFA is not scored as safe — it raises the upper bound', () => {
  const unknown = assessAccount(base({ category: 'identity_email' }), NOW);
  const enabled = assessAccount(base({ category: 'identity_email', mfa: { status: 'enabled', source: 'mailbox_evidence' } }), NOW);
  const disabled = assessAccount(base({ category: 'identity_email', mfa: { status: 'disabled', source: 'mailbox_evidence' } }), NOW);
  assert.ok(unknown.upper > unknown.score, 'unknown widens the range');
  assert.equal(enabled.upper, enabled.score);
  assert.ok(disabled.score > enabled.score);
  assert.ok(unknown.unknowns.some((u) => u.code === 'MFA_UNKNOWN'));
});

test('dasi: correlated breaches are counted once plus a capped increment', () => {
  const one = assessAccount(base({ breaches: [pwBreach] }), NOW);
  const many = assessAccount(base({ breaches: Array.from({ length: 8 }, (_, i) => ({ ...pwBreach, title: `B${i}` })) }), NOW);
  const f1 = one.factors.find((f) => f.code === 'CREDENTIAL_EXPOSURE_PASSWORD');
  const f8 = many.factors.find((f) => f.code === 'CREDENTIAL_EXPOSURE_PASSWORD');
  assert.equal(f1.points, WEIGHTS.CREDENTIAL_EXPOSURE_PASSWORD);
  assert.equal(f8.points, WEIGHTS.CREDENTIAL_EXPOSURE_PASSWORD + WEIGHTS.ADDITIONAL_BREACH_CAP);
  assert.equal(many.factors.filter((f) => f.code.startsWith('CREDENTIAL')).length, 1);
});

test('dasi: remediation reduces only the current credential component and only if after the breach', () => {
  const none = assessAccount(base({ breaches: [pwBreach] }), NOW);
  const reported = assessAccount(base({ breaches: [pwBreach], remediation: { change_password: { status: 'user_reported', at: new Date(NOW - DAY) } } }), NOW);
  const verified = assessAccount(base({ breaches: [pwBreach], remediation: { change_password: { status: 'verified', at: new Date(NOW - DAY) } } }), NOW);
  const beforeBreach = assessAccount(base({ breaches: [pwBreach], remediation: { change_password: { status: 'verified', at: new Date('2018-01-01') } } }), NOW);
  assert.ok(none.score > reported.score && reported.score > verified.score);
  assert.equal(beforeBreach.score, none.score, 'a change before the breach does not count');
  assert.ok(verified.factors.some((f) => f.code === 'CREDENTIAL_EXPOSURE_PASSWORD'), 'historical exposure stays visible');
  assert.equal(verified.critical.length, 0);
  assert.equal(none.critical[0].code, 'UNREMEDIATED_PASSWORD_EXPOSURE');
});

test('dasi: critical findings remain visible even when the aggregate is moderate', () => {
  const accounts = [
    { id: 'x', serviceName: 'Leaky', risk: assessAccount(base({ breaches: [pwBreach] }), NOW) },
    ...Array.from({ length: 5 }, (_, i) => ({ id: `l${i}`, serviceName: `Low${i}`, risk: assessAccount(base({ id: `l${i}` }), NOW) })),
  ];
  const d = computeDasi(accounts, { everScanned: true, activeConnections: 1, connectionsScannedRecently: 1, lastScanComplete: true, connectionsBreachCheckedRecently: 1, confirmedAccounts: 6, accountsWithKnownMfa: 0 });
  assert.ok(d.score < 60, `aggregate is moderate (${d.score})`);
  assert.equal(d.criticalFindings.length, 1);
  assert.equal(d.criticalFindings[0].serviceName, 'Leaky');
});

test('dasi: no evidence means "not assessed", never zero', () => {
  const d = computeDasi([], { everScanned: false, activeConnections: 0 });
  assert.equal(d.score, null);
  assert.equal(d.confidence, 'none');
});

test('dasi: possible, dismissed and closed accounts do not contribute', () => {
  assert.equal(assessAccount(base({ status: 'possible', breaches: [pwBreach] }), NOW).score, null);
  assert.equal(assessAccount(base({ status: 'dismissed', breaches: [pwBreach] }), NOW).score, null);
  assert.equal(assessAccount(base({ accountState: 'closed_user_reported', breaches: [pwBreach] }), NOW).score, 0);
});

test('dasi: alert recency and dormancy factors', () => {
  const recent = assessAccount(base({ latestAlertAt: new Date(NOW - 5 * DAY), alertAuthenticated: true }), NOW);
  const old = assessAccount(base({ latestAlertAt: new Date(NOW - 400 * DAY) }), NOW);
  assert.ok(recent.factors.some((f) => f.code === 'RECENT_SECURITY_ALERT' && f.points === WEIGHTS.ALERT_30D));
  assert.ok(!old.factors.some((f) => f.code === 'RECENT_SECURITY_ALERT'));
  const dormant = assessAccount(base({ lastObservedAt: new Date(NOW - 800 * DAY) }), NOW);
  assert.ok(dormant.factors.some((f) => f.code === 'DORMANT' && f.confidence === 'low'));
});

test('dasi: confidence reflects evidence coverage', () => {
  assert.equal(assessConfidence({ activeConnections: 1, connectionsScannedRecently: 1, lastScanComplete: true, connectionsBreachCheckedRecently: 1, confirmedAccounts: 4, accountsWithKnownMfa: 2 }).confidence, 'high');
  assert.equal(assessConfidence({ activeConnections: 1, connectionsScannedRecently: 1, lastScanComplete: true, connectionsBreachCheckedRecently: 0, confirmedAccounts: 4, accountsWithKnownMfa: 0 }).confidence, 'low');
  assert.equal(assessConfidence({ activeConnections: 2, connectionsScannedRecently: 1, lastScanComplete: true, connectionsBreachCheckedRecently: 2, confirmedAccounts: 4, accountsWithKnownMfa: 4 }).confidence, 'low');
});

test('dasi: score changes are explained by factor differences', () => {
  const prev = { model_version: MODEL_VERSION, confidence: 'medium', contributors: [{ accountId: 'a', serviceName: 'GitHub', score: 40, factors: [{ code: 'RECENT_SECURITY_ALERT' }] }] };
  const cur = { modelVersion: MODEL_VERSION, confidence: 'medium', contributors: [{ accountId: 'a', serviceName: 'GitHub', score: 20, factors: [] }] };
  const reasons = explainChange(prev, cur);
  assert.equal(reasons[0].delta, -20);
  assert.match(reasons[0].message, /no longer present: recent security alert/);
  assert.equal(explainChange(null, cur)[0].kind, 'first_assessment');
  assert.equal(explainChange({ ...prev, model_version: 'dasi-1.0.0' }, cur)[0].kind, 'model_change');
});

// ---- Recommendations -------------------------------------------------------------------
test('recommendations: derived from evidenced factors, with registry-only official links', () => {
  const input = base({ serviceName: 'Google Account', serviceDomain: 'google.com', category: 'identity_email', breaches: [pwBreach] });
  const recs = recommendationsFor(input, assessAccount(input, NOW));
  const types = recs.map((r) => r.actionType);
  assert.deepEqual(types.sort(), ['change_password', 'enable_mfa', 'update_recovery']);
  const cp = recs.find((r) => r.actionType === 'change_password');
  assert.equal(cp.severity, 'critical');
  assert.equal(cp.officialUrl, 'https://myaccount.google.com/signinoptions/password');
  assert.equal(cp.verificationMethod, 'mailbox_security_notification');
  assert.match(cp.explanation, /does not prove your current password/);
  // A service outside the registry never gets an invented settings path. It
  // falls back to that service's own bare origin, labelled 'domain_root'.
  const unknownSvc = base({ serviceName: 'Obscure', serviceDomain: 'obscure-service.example', breaches: [pwBreach] });
  const r2 = recommendationsFor(unknownSvc, assessAccount(unknownSvc, NOW)).find((r) => r.actionType === 'change_password');
  assert.equal(r2.officialUrlKind, 'domain_root');
  assert.equal(r2.officialUrl, 'https://obscure-service.example/', 'bare origin only — no guessed path');
  assert.match(r2.nextStep, /type the address yourself/i, 'still tells the user not to trust emailed links');

  // A service whose domain is not a usable hostname still gets no link at all.
  const noDomain = base({ serviceName: 'Combo list', serviceDomain: null, breaches: [pwBreach] });
  const r3 = recommendationsFor(noDomain, assessAccount(noDomain, NOW)).find((r) => r.actionType === 'change_password');
  assert.equal(r3.officialUrl, null);
  assert.equal(r3.officialUrlKind, 'none');
});

test('recommendations: every registry URL is https and on the provider’s own domain family', () => {
  for (const domain of registeredOfficialDomains()) {
    for (const action of ['enable_mfa', 'change_password', 'review_sessions', 'review_connected_apps', 'update_recovery']) {
      const l = officialLinkFor(domain, action);
      if (!l.url) continue;
      const host = new URL(l.url).hostname;
      assert.equal(new URL(l.url).protocol, 'https:');
      const family = domain.split('.')[0].replace('x', 'x');
      assert.ok(host.includes(family) || ['support.google.com', 'myaccount.google.com', 'docs.github.com', 'support.microsoft.com', 'support.apple.com', 'account.apple.com', 'helpx.adobe.com', 'help.instagram.com', 'help.x.com'].includes(host), `${domain} -> ${host}`);
    }
  }
});

test('recommendations: possible / dismissed accounts get none; MFA-unknown high-impact accounts get a check', () => {
  const possible = base({ status: 'possible', breaches: [pwBreach] });
  assert.equal(recommendationsFor(possible, assessAccount(possible, NOW)).length, 0);
  const bank = base({ serviceName: 'Bank', serviceDomain: 'hdfcbank.com', category: categoryFor('hdfcbank.com') });
  assert.equal(bank.category, 'financial');
  const recs = recommendationsFor(bank, assessAccount(bank, NOW));
  assert.deepEqual(recs.map((r) => [r.actionType, r.severity]), [['enable_mfa', 'medium']]);
});

// ---- Breach normalizers --------------------------------------------------------------
test('breach: provider records normalize safely; hints are not passwords; fabricated/spam/sensitive filtered', () => {
  const x = normalizeXon({ breach: 'Adobe', domain: 'adobe.com', xposedDate: '2013', xposed_data: 'Email addresses;Password hints;Usernames', verified: 'Yes' });
  assert.equal(x.date, '2013-01-01');
  assert.equal(x.datePrecision, 'year');
  assert.equal(exposesPasswords(x), false);
  assert.equal(exposesPasswords({ dataClasses: ['Passwords'] }), true);
  assert.equal(normalizeXon({}), null);
  assert.equal(normalizeXon('garbage'), null);
  assert.equal(normalizeHibp({ Name: 'Spam', IsSpamList: true }, { includeSensitive: false }), null);
  assert.equal(normalizeHibp({ Name: 'Fake', IsFabricated: true }, { includeSensitive: false }), null);
  assert.equal(normalizeHibp({ Name: 'Adult', IsSensitive: true }, { includeSensitive: false }), null);
  const h = normalizeHibp({ Name: 'LinkedIn', Title: 'LinkedIn', Domain: 'www.linkedin.com', BreachDate: '2012-05-05', DataClasses: ['Email addresses', 'Passwords'], IsVerified: true }, { includeSensitive: false });
  assert.equal(h.domain, 'linkedin.com');
  assert.equal(h.datePrecision, 'day');
});
