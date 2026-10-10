// Deterministic recommendation rules. Each recommendation is derived from a
// specific, evidenced factor; nothing here is generic filler. Pure functions.
import { officialLinkFor, CATEGORY_IMPACT } from './catalog.js';

const SEVERITY_WEIGHT = { critical: 100, high: 70, medium: 40, low: 15 };

// Which actions FootprintX can independently verify, and how. Anything not
// listed can only ever be "user-reported".
export const VERIFIABLE_ACTIONS = Object.freeze({
  change_password: { evidenceKind: 'password_changed', method: 'mailbox_security_notification' },
  enable_mfa: { evidenceKind: 'mfa_enabled', method: 'mailbox_security_notification' },
});

const ACTION_TEXT = {
  change_password: {
    title: (s) => `Change your ${s} password`,
    next: 'Open the official site (type the address yourself or use the link below), change the password to a new unique one, and update it anywhere you reused it. A password manager makes this easier.',
    effect: 'Reduces the current credential-exposure component of this account’s risk. The historical breach record stays visible.',
  },
  enable_mfa: {
    title: (s) => `Turn on two-step verification for ${s}`,
    next: 'In the service’s security settings, turn on two-step verification, preferably with an authenticator app or passkey rather than SMS. Store the recovery codes somewhere safe — FootprintX never asks for them.',
    effect: 'Makes a leaked or guessed password much less useful to an attacker and lowers the account’s risk once recorded.',
  },
  review_sessions: {
    title: (s) => `Review recent sign-ins and devices on ${s}`,
    next: 'On the official site, open the list of signed-in devices or recent activity. Sign out anything you don’t recognise, then change the password if anything looks wrong.',
    effect: 'Addresses the security-alert component once you report the review.',
  },
  review_connected_apps: {
    title: (s) => `Review apps connected to ${s}`,
    next: 'Open the list of third-party apps with access to the account and remove any you no longer use or don’t recognise.',
    effect: 'Reduces ways into the account that bypass your password.',
  },
  update_recovery: {
    title: (s) => `Check recovery email and phone for ${s}`,
    next: 'Make sure the recovery email and phone number are yours and current. Attackers often change these after taking over an account.',
    effect: 'Helps you regain the account if it is ever taken over.',
  },
  close_account: {
    title: (s) => `Close ${s} if you no longer use it`,
    next: 'If you don’t need this account, sign in on the official site and use its account-deletion option. Only you can do this; FootprintX never changes external accounts.',
    effect: 'Removes the account from your attack surface. FootprintX records closure as user-reported.',
  },
  review_activity: {
    title: (s) => `Check recent security activity for ${s}`,
    next: 'Look at the service’s recent security events for changes you did not make.',
    effect: 'Confirms whether a reported event was you.',
  },
};

function rec(account, actionType, severity, explanation, why, evidence, confidence = 'high') {
  const text = ACTION_TEXT[actionType];
  const link = officialLinkFor(account.serviceDomain, actionType);
  const impact = CATEGORY_IMPACT[account.category] ?? 1;
  return {
    accountId: account.id,
    domain: null,
    actionType,
    severity,
    priority: Math.round(SEVERITY_WEIGHT[severity] * (confidence === 'high' ? 1 : confidence === 'medium' ? 0.8 : 0.6) * impact),
    title: text.title(account.serviceName),
    explanation,
    whyItMatters: why,
    nextStep: link.url ? text.next : `${text.next} ${link.note}`,
    evidence,
    officialUrl: link.url,
    officialUrlKind: link.kind,
    officialUrlNote: link.note,
    expectedEffect: text.effect,
    verificationMethod: VERIFIABLE_ACTIONS[actionType] ? VERIFIABLE_ACTIONS[actionType].method : 'none',
  };
}

/**
 * Builds the set of applicable recommendations for one account.
 * @param account account input (see dasiService.buildAccountInput)
 * @param risk    assessAccount() output
 */
export function recommendationsFor(account, risk) {
  if (account.status !== 'confirmed' || risk.excluded) return [];
  const out = [];
  const codes = new Map(risk.factors.map((f) => [f.code, f]));
  const highImpact = ['identity_email', 'financial', 'cloud_storage', 'developer'].includes(account.category);

  const cred = codes.get('CREDENTIAL_EXPOSURE_PASSWORD') || codes.get('CREDENTIAL_EXPOSURE');
  if (cred) {
    const pw = cred.code === 'CREDENTIAL_EXPOSURE_PASSWORD';
    out.push(
      rec(
        account,
        'change_password',
        pw ? 'critical' : 'medium',
        pw
          ? `Your email address appears in a breach of ${account.serviceName} that included passwords. This does not prove your current password is known to attackers, but a password from that time may be.`
          : `Your email address appears in a breach of ${account.serviceName}. Passwords were not reported as exposed, but the exposed details can be used for targeted phishing.`,
        pw ? 'Attackers routinely try leaked passwords on other sites (credential stuffing).' : 'Exposed personal details make convincing phishing messages easier.',
        cred.provenance.map((p) => ({ type: 'breach', label: p })),
        cred.confidence
      )
    );
    if (account.mfa?.status !== 'enabled') {
      out.push(rec(account, 'enable_mfa', pw ? 'high' : 'medium', `${account.serviceName} has breach evidence and two-step verification is ${account.mfa?.status === 'disabled' ? 'reported off' : 'not known to be on'}.`, 'Two-step verification blocks most attacks that use a leaked password.', [{ type: 'factor', label: cred.label }]));
    }
    if (pw && account.category === 'identity_email') {
      out.push(rec(account, 'update_recovery', 'medium', `${account.serviceName} is an identity account that can reset passwords for other services.`, 'Taking over an email account often means taking over everything linked to it.', [{ type: 'factor', label: cred.label }]));
    }
  }

  const alert = codes.get('RECENT_SECURITY_ALERT');
  if (alert) {
    const sev = alert.points >= 30 ? 'high' : 'medium';
    out.push(rec(account, 'review_sessions', sev, `${account.serviceName} sent a security alert (${alert.label.toLowerCase()}). If it was you, no action is needed beyond confirming; if not, act quickly.`, 'Unrecognised sign-ins are a common early sign of account takeover.', alert.provenance.map((p) => ({ type: 'mailbox', label: p })), alert.confidence));
    if (highImpact) out.push(rec(account, 'review_connected_apps', 'medium', `Following a security alert on ${account.serviceName}, check which apps can access the account.`, 'Connected apps keep access even after a password change.', [{ type: 'factor', label: alert.label }]));
  }

  if (codes.has('MFA_DISABLED') && !out.some((r) => r.actionType === 'enable_mfa')) {
    out.push(rec(account, 'enable_mfa', highImpact ? 'high' : 'medium', `Two-step verification on ${account.serviceName} is reported as turned off.`, 'Without it, a password alone is enough to sign in.', codes.get('MFA_DISABLED').provenance.map((p) => ({ type: 'mfa', label: p }))));
  } else if (account.mfa?.status === 'unknown' && highImpact && !out.some((r) => r.actionType === 'enable_mfa')) {
    out.push(rec(account, 'enable_mfa', 'medium', `FootprintX can’t tell whether two-step verification is on for ${account.serviceName}. Because this is a high-impact account, please check.`, 'High-impact accounts (email, finance, cloud, developer) are prime targets.', [{ type: 'unknown', label: 'MFA status unknown' }], 'medium'));
  }

  if (codes.has('DORMANT')) {
    out.push(rec(account, 'close_account', 'low', `No activity from ${account.serviceName} has appeared in your mailbox for over two years. That does not prove the account is unused — you decide.`, 'Forgotten accounts are rarely monitored and often have old, reused passwords.', codes.get('DORMANT').provenance.map((p) => ({ type: 'mailbox', label: p })), 'low'));
  }

  if (codes.has('THREAT_LISTED')) {
    const t = codes.get('THREAT_LISTED');
    out.push(rec(account, 'review_activity', 'high', `The domain ${account.serviceDomain} appears in a threat-intelligence dataset. This may mean the domain was compromised or misused, or it may be a listing error.`, 'Signing in through a compromised domain could expose your credentials.', (t.provenance || []).map((p) => ({ type: 'threat', label: p })), 'medium'));
  }
  return out;
}
