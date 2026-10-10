// Plain-language labels for every status the API returns. Keeping them in one
// place keeps wording consistent across screens.

export const ACCOUNT_STATUS = { confirmed: 'Confirmed', possible: 'Possible', dismissed: 'Dismissed' };

export const DISCOVERY_SOURCE = {
  mailbox_connection: 'Connected mailbox',
  gmail_metadata: 'Gmail message headers',
  gmail_search: 'Gmail search',
  synthetic: 'Synthetic test mailbox',
  breach_record: 'Breach listing',
  manual: 'Added by you',
};

export const CONFIDENCE = { high: 'High confidence', medium: 'Medium confidence', low: 'Low confidence' };

export const MFA = {
  enabled: { label: 'On', tone: 'good' },
  disabled: { label: 'Off', tone: 'bad' },
  unknown: { label: 'Unknown', tone: 'unknown' },
};
export const MFA_SOURCE = { mailbox_evidence: 'from a security email', user_reported: 'reported by you' };

export const EXPOSURE = {
  confirmed_evidence: { label: 'In a breach', tone: 'bad' },
  no_evidence_found: { label: 'No breach found', tone: 'neutral' },
  unknown: { label: 'Not checked', tone: 'unknown' },
};

export const ACCOUNT_STATE = { unknown: null, closed_user_reported: 'Closed (reported by you)', closed_evidence: 'Closed (closure email found)' };

export const RISK_LEVEL = {
  critical: { label: 'Critical', tone: 'bad' },
  high: { label: 'High', tone: 'bad' },
  medium: { label: 'Medium', tone: 'warn' },
  low: { label: 'Low', tone: 'neutral' },
};

export const DASI_LEVEL_TONE = { severe: 'bad', high: 'bad', elevated: 'warn', guarded: 'warn', low: 'good' };

export const EVIDENCE_KIND = {
  mailbox_connection: 'Mailbox connected to FootprintX',
  signup: 'Sign-up or verification email',
  password_reset: 'Password reset email',
  password_changed: 'Password changed notification',
  security_alert: 'Security alert email',
  login_notice: 'New sign-in notification',
  mfa_enabled: 'Two-step verification turned on',
  mfa_disabled: 'Two-step verification turned off',
  account_closed: 'Account closure email',
  billing: 'Receipt or billing email',
  generic_account: 'General account email',
  breach_record: 'Listed in a breach dataset',
};

export const AUTH_RESULT = { pass: 'Sender verified', fail: 'Sender failed verification', unknown: 'Sender not verified' };

export const FACTOR = {
  BASE_EXPOSURE: 'Account exists',
  CREDENTIAL_EXPOSURE_PASSWORD: 'Password exposed in a breach',
  CREDENTIAL_EXPOSURE: 'Listed in a breach',
  RECENT_SECURITY_ALERT: 'Recent security alert',
  MFA_DISABLED: 'Two-step verification off',
  DORMANT: 'No activity seen for 2+ years',
  THREAT_LISTED: 'Domain on a threat list',
  MFA_UNKNOWN: 'Two-step verification unknown',
  EXPOSURE_NOT_CHECKED: 'Breach exposure not checked',
};

export const ACTION = {
  change_password: 'Change password',
  enable_mfa: 'Turn on two-step verification',
  review_sessions: 'Review sign-ins and devices',
  review_connected_apps: 'Review connected apps',
  update_recovery: 'Check recovery details',
  close_account: 'Close the account',
  review_activity: 'Check security activity',
  avoid_site: 'Avoid this site',
};

export const REMEDIATION = {
  recommended: { label: 'To do', tone: 'neutral' },
  in_progress: { label: 'In progress', tone: 'info' },
  user_reported: { label: 'Done (reported by you)', tone: 'info' },
  verification_pending: { label: 'Done — awaiting confirmation', tone: 'info' },
  verified: { label: 'Confirmed by the service', tone: 'good' },
  unable_to_verify: { label: 'Done — couldn’t confirm', tone: 'warn' },
  dismissed: { label: 'Dismissed', tone: 'unknown' },
};

export const SEVERITY = { critical: { label: 'Critical', tone: 'bad' }, high: { label: 'High', tone: 'bad' }, medium: { label: 'Medium', tone: 'warn' }, low: { label: 'Low', tone: 'neutral' }, info: { label: 'Info', tone: 'neutral' } };

export const SCAN_STATUS = {
  queued: { label: 'Queued', tone: 'info' },
  running: { label: 'Scanning', tone: 'info' },
  completed: { label: 'Completed', tone: 'good' },
  partial: { label: 'Partially completed', tone: 'warn' },
  failed: { label: 'Failed', tone: 'bad' },
  cancelled: { label: 'Cancelled', tone: 'unknown' },
};

export const REPUTATION = {
  no_known_threat: { label: 'No known threat found', tone: 'good' },
  suspicious: { label: 'Suspicious signs', tone: 'warn' },
  malicious: { label: 'Known threat', tone: 'bad' },
  unknown: { label: 'Not enough information', tone: 'unknown' },
  unavailable: { label: 'Check unavailable', tone: 'unknown' },
};

export const REASON_CODE = {
  HOMOGRAPH: 'Uses look-alike characters to imitate a well-known site.',
  MIXED_SCRIPT: 'Mixes letters from different alphabets.',
  BRAND_IN_SUBDOMAIN: 'Puts a well-known brand name in front of an unrelated domain.',
  TYPOSQUAT: 'Is one character away from a well-known site.',
  DATASET_NOT_LOADED: 'The threat dataset is not loaded yet.',
  DATASET_STALE: 'The threat dataset is out of date.',
  LOOKUP_FAILED: 'The threat lookup failed.',
};

export const TRIGGER = {
  initial: 'First assessment',
  scan: 'Mailbox scan',
  breach_check: 'Breach check',
  remediation_update: 'You updated a recommendation',
  user_correction: 'You corrected an account',
  threat_update: 'Threat intelligence update',
  model_change: 'Scoring model update',
  connection_change: 'Mailbox connected or disconnected',
  verification_deadline: 'Verification window ended',
  manual: 'Recalculated',
};

export function formatDate(d, { time = false } = {}) {
  if (!d) return '—';
  const date = new Date(d);
  if (Number.isNaN(date.getTime())) return '—';
  return date.toLocaleString(undefined, time ? { dateStyle: 'medium', timeStyle: 'short' } : { dateStyle: 'medium' });
}

export function relative(d) {
  if (!d) return 'never';
  const ms = Date.now() - new Date(d).getTime();
  const m = Math.round(ms / 60e3);
  if (m < 1) return 'just now';
  if (m < 60) return `${m} min ago`;
  const h = Math.round(m / 60);
  if (h < 36) return `${h} h ago`;
  const days = Math.round(h / 24);
  if (days < 60) return `${days} days ago`;
  const months = Math.round(days / 30);
  if (months < 24) return `${months} months ago`;
  return `${Math.round(months / 12)} years ago`;
}
