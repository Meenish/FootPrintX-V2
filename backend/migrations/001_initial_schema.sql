-- FootprintX schema v1. Runs unchanged on PostgreSQL 16+ and PGlite.
-- Ownership: every user-owned table carries user_id with ON DELETE CASCADE so
-- account deletion removes the user's data in one statement. Audit events are
-- the deliberate exception (user_id is nulled, see docs/PRIVACY.md).

CREATE TABLE users (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL,
  password_hash text NOT NULL,
  display_name text,
  role text NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
  failed_login_count integer NOT NULL DEFAULT 0,
  locked_until timestamptz,
  password_changed_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_uq ON users (email);

-- Opaque session tokens; only a SHA-256 hash is stored.
CREATE TABLE sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  csrf_hash text,
  kind text NOT NULL CHECK (kind IN ('web', 'extension')),
  label text,
  extension_sync_enabled boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  idle_expires_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz
);
CREATE INDEX sessions_user_idx ON sessions (user_id);

CREATE TABLE password_reset_tokens (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  token_hash text NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX password_reset_user_idx ON password_reset_tokens (user_id);

-- Single-use OAuth state (CSRF protection for the OAuth redirect) + PKCE verifier.
CREATE TABLE oauth_states (
  state_hash text PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  pkce_verifier_enc jsonb NOT NULL,
  scope_mode text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE email_connections (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  provider text NOT NULL CHECK (provider IN ('gmail', 'synthetic')),
  email_hash text NOT NULL,
  email_enc jsonb NOT NULL,
  email_masked text NOT NULL,
  scope_mode text NOT NULL CHECK (scope_mode IN ('metadata', 'readonly', 'synthetic')),
  granted_scopes text,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'reauth_required', 'disconnected')),
  token_enc jsonb,
  is_synthetic boolean NOT NULL DEFAULT false,
  connected_at timestamptz NOT NULL DEFAULT now(),
  disconnected_at timestamptz,
  token_revoked_at timestamptz,
  token_revoke_result text,
  last_scan_at timestamptz,
  last_successful_scan_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, email_hash)
);

CREATE TABLE scan_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  connection_id uuid NOT NULL REFERENCES email_connections (id) ON DELETE CASCADE,
  trigger text NOT NULL CHECK (trigger IN ('manual', 'onboarding', 'scheduled', 'verification')),
  status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'running', 'partial', 'completed', 'failed', 'cancelled')),
  stage text,
  progress jsonb NOT NULL DEFAULT '{}'::jsonb,
  source_results jsonb NOT NULL DEFAULT '[]'::jsonb,
  summary jsonb,
  error_code text,
  error_message text,
  attempts integer NOT NULL DEFAULT 0,
  max_attempts integer NOT NULL DEFAULT 3,
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  cancel_requested boolean NOT NULL DEFAULT false,
  heartbeat_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  started_at timestamptz,
  finished_at timestamptz
);
CREATE INDEX scan_jobs_user_idx ON scan_jobs (user_id, created_at DESC);
CREATE INDEX scan_jobs_queue_idx ON scan_jobs (status, next_attempt_at);
-- At most one queued/running scan per mailbox: duplicate triggers are absorbed.
CREATE UNIQUE INDEX scan_jobs_one_active ON scan_jobs (connection_id) WHERE status IN ('queued', 'running');

CREATE TABLE discovered_accounts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  connection_id uuid REFERENCES email_connections (id) ON DELETE CASCADE,
  service_key text NOT NULL,
  service_name text NOT NULL,
  service_domain text,
  category text NOT NULL DEFAULT 'other',
  identifier_masked text,
  status text NOT NULL DEFAULT 'confirmed' CHECK (status IN ('confirmed', 'possible', 'dismissed')),
  discovery_source text NOT NULL CHECK (discovery_source IN ('mailbox_connection', 'gmail_metadata', 'gmail_search', 'synthetic', 'breach_record', 'manual')),
  confidence text NOT NULL CHECK (confidence IN ('high', 'medium', 'low')),
  manually_added boolean NOT NULL DEFAULT false,
  user_corrected boolean NOT NULL DEFAULT false,
  dismissed_reason text,
  weak_signal_count integer NOT NULL DEFAULT 0,
  first_observed_at timestamptz,
  last_observed_at timestamptz,
  last_checked_at timestamptz,
  mfa_status text NOT NULL DEFAULT 'unknown' CHECK (mfa_status IN ('enabled', 'disabled', 'unknown')),
  mfa_source text CHECK (mfa_source IN ('mailbox_evidence', 'user_reported')),
  mfa_observed_at timestamptz,
  exposure_status text NOT NULL DEFAULT 'unknown' CHECK (exposure_status IN ('confirmed_evidence', 'no_evidence_found', 'unknown')),
  exposure_checked_at timestamptz,
  account_state text NOT NULL DEFAULT 'unknown' CHECK (account_state IN ('unknown', 'closed_user_reported', 'closed_evidence')),
  risk_score integer,
  risk_upper integer,
  risk_level text,
  risk_factors jsonb NOT NULL DEFAULT '[]'::jsonb,
  risk_model_version text,
  risk_assessed_at timestamptz,
  is_synthetic boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE NULLS NOT DISTINCT (user_id, connection_id, service_key)
);
CREATE INDEX discovered_accounts_user_idx ON discovered_accounts (user_id, status);
CREATE INDEX discovered_accounts_domain_idx ON discovered_accounts (service_domain);

-- Provenance for each finding. Message subjects/bodies are never stored; the
-- Gmail message id is stored only as an HMAC for de-duplication.
CREATE TABLE account_evidence (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  account_id uuid NOT NULL REFERENCES discovered_accounts (id) ON DELETE CASCADE,
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  connection_id uuid REFERENCES email_connections (id) ON DELETE CASCADE,
  kind text NOT NULL,
  strength text NOT NULL CHECK (strength IN ('strong', 'weak')),
  source text NOT NULL,
  sender_domain text,
  sender_authenticated text CHECK (sender_authenticated IN ('pass', 'fail', 'unknown')),
  source_ref_hash text,
  observed_at timestamptz NOT NULL,
  recorded_at timestamptz NOT NULL DEFAULT now(),
  is_synthetic boolean NOT NULL DEFAULT false,
  UNIQUE (account_id, source_ref_hash)
);
CREATE INDEX account_evidence_account_idx ON account_evidence (account_id, observed_at DESC);

CREATE TABLE consents (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  kind text NOT NULL CHECK (kind IN ('breach_lookup')),
  provider text NOT NULL,
  policy_version text NOT NULL,
  granted_at timestamptz,
  revoked_at timestamptz,
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, kind)
);

CREATE TABLE breach_checks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  connection_id uuid NOT NULL REFERENCES email_connections (id) ON DELETE CASCADE,
  provider text NOT NULL,
  status text NOT NULL CHECK (status IN ('ok', 'unavailable', 'rate_limited', 'error')),
  result_count integer,
  error_code text,
  is_synthetic boolean NOT NULL DEFAULT false,
  checked_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX breach_checks_conn_idx ON breach_checks (connection_id, checked_at DESC);

CREATE TABLE breach_findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  connection_id uuid NOT NULL REFERENCES email_connections (id) ON DELETE CASCADE,
  account_id uuid REFERENCES discovered_accounts (id) ON DELETE SET NULL,
  provider text NOT NULL,
  breach_name text NOT NULL,
  breach_title text NOT NULL,
  breach_domain text,
  breach_date date,
  breach_date_precision text NOT NULL DEFAULT 'unknown' CHECK (breach_date_precision IN ('day', 'year', 'unknown')),
  data_classes jsonb NOT NULL DEFAULT '[]'::jsonb,
  password_exposed boolean NOT NULL DEFAULT false,
  provider_verified boolean,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  is_synthetic boolean NOT NULL DEFAULT false,
  UNIQUE (connection_id, provider, breach_name)
);
CREATE INDEX breach_findings_user_idx ON breach_findings (user_id);
CREATE INDEX breach_findings_account_idx ON breach_findings (account_id);

CREATE TABLE dasi_snapshots (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  model_version text NOT NULL,
  score integer,
  upper_bound integer,
  level text,
  confidence text NOT NULL,
  coverage jsonb NOT NULL,
  contributors jsonb NOT NULL,
  critical_findings jsonb NOT NULL DEFAULT '[]'::jsonb,
  trigger text NOT NULL,
  previous_score integer,
  delta integer,
  change_reasons jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX dasi_snapshots_user_idx ON dasi_snapshots (user_id, created_at DESC);

CREATE TABLE recommendations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  account_id uuid REFERENCES discovered_accounts (id) ON DELETE CASCADE,
  domain text,
  action_type text NOT NULL CHECK (action_type IN ('change_password', 'enable_mfa', 'review_sessions', 'review_connected_apps', 'update_recovery', 'close_account', 'review_activity', 'avoid_site')),
  severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
  priority integer NOT NULL,
  title text NOT NULL,
  explanation text NOT NULL,
  why_it_matters text NOT NULL,
  next_step text NOT NULL,
  evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
  official_url text,
  official_url_kind text NOT NULL DEFAULT 'none' CHECK (official_url_kind IN ('settings_page', 'help_page', 'none')),
  expected_effect text NOT NULL,
  status text NOT NULL DEFAULT 'recommended' CHECK (status IN ('recommended', 'in_progress', 'user_reported', 'verification_pending', 'verified', 'unable_to_verify', 'dismissed')),
  applicable boolean NOT NULL DEFAULT true,
  verification_method text NOT NULL DEFAULT 'none' CHECK (verification_method IN ('mailbox_security_notification', 'none')),
  verification_evidence jsonb,
  dismissed_reason text,
  reported_at timestamptz,
  verified_at timestamptz,
  verification_deadline timestamptz,
  status_changed_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE NULLS NOT DISTINCT (user_id, account_id, domain, action_type)
);
CREATE INDEX recommendations_user_idx ON recommendations (user_id, status);

CREATE TABLE remediation_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  recommendation_id uuid NOT NULL REFERENCES recommendations (id) ON DELETE CASCADE,
  from_status text,
  to_status text NOT NULL,
  actor text NOT NULL CHECK (actor IN ('user', 'system')),
  note text,
  evidence jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX remediation_events_user_idx ON remediation_events (user_id, created_at DESC);

CREATE TABLE alerts (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  kind text NOT NULL CHECK (kind IN ('account_security', 'breach', 'threat_intel', 'extension', 'remediation', 'scan', 'subscription')),
  severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  title text NOT NULL,
  body text NOT NULL,
  account_id uuid REFERENCES discovered_accounts (id) ON DELETE SET NULL,
  domain text,
  dedup_key text NOT NULL,
  status text NOT NULL DEFAULT 'unread' CHECK (status IN ('unread', 'read', 'dismissed')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, dedup_key)
);
CREATE INDEX alerts_user_idx ON alerts (user_id, created_at DESC);

CREATE TABLE notification_preferences (
  user_id uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
  security_alerts_email boolean NOT NULL DEFAULT true,
  remediation_reminders_email boolean NOT NULL DEFAULT false,
  periodic_summary_email boolean NOT NULL DEFAULT false,
  product_updates_email boolean NOT NULL DEFAULT false,
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Delivery log: category + status only, never message content.
CREATE TABLE notification_deliveries (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  category text NOT NULL,
  channel text NOT NULL DEFAULT 'email',
  dedup_key text NOT NULL,
  status text NOT NULL CHECK (status IN ('sent', 'failed', 'skipped')),
  reason text,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, channel, dedup_key)
);
CREATE INDEX notification_deliveries_user_idx ON notification_deliveries (user_id, created_at DESC);

CREATE TABLE subscriptions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL UNIQUE REFERENCES users (id) ON DELETE CASCADE,
  plan text NOT NULL CHECK (plan IN ('premium')),
  status text NOT NULL CHECK (status IN ('trialing', 'active', 'past_due', 'canceled', 'expired')),
  provider text NOT NULL CHECK (provider IN ('development', 'stripe', 'razorpay')),
  provider_ref text,
  current_period_start timestamptz NOT NULL,
  current_period_end timestamptz NOT NULL,
  cancel_at_period_end boolean NOT NULL DEFAULT false,
  canceled_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE extension_link_codes (
  code_hash text PRIMARY KEY,
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  expires_at timestamptz NOT NULL,
  used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE extension_events (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  session_id uuid REFERENCES sessions (id) ON DELETE SET NULL,
  client_event_id uuid NOT NULL,
  type text NOT NULL,
  domain text NOT NULL,
  status text NOT NULL,
  reason_codes jsonb NOT NULL DEFAULT '[]'::jsonb,
  dataset_version text,
  occurred_at timestamptz NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (user_id, client_event_id)
);
CREATE INDEX extension_events_user_idx ON extension_events (user_id, occurred_at DESC);

CREATE TABLE domain_checks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  domain text NOT NULL,
  status text NOT NULL,
  reasons jsonb NOT NULL DEFAULT '[]'::jsonb,
  dataset_version text,
  checked_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX domain_checks_user_idx ON domain_checks (user_id, checked_at DESC);

CREATE TABLE false_positive_reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid REFERENCES users (id) ON DELETE SET NULL,
  domain text NOT NULL,
  reported_status text NOT NULL,
  note text,
  review_status text NOT NULL DEFAULT 'open' CHECK (review_status IN ('open', 'accepted', 'rejected')),
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE threat_indicators (
  hostname text NOT NULL,
  source text NOT NULL,
  hash_full text NOT NULL,
  hash_prefix text NOT NULL,
  category text NOT NULL CHECK (category IN ('malicious')),
  threat_type text NOT NULL,
  active boolean NOT NULL DEFAULT true,
  first_seen_at timestamptz NOT NULL DEFAULT now(),
  last_seen_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (hostname, source)
);
CREATE INDEX threat_indicators_prefix_idx ON threat_indicators (hash_prefix) WHERE active;
CREATE INDEX threat_indicators_full_idx ON threat_indicators (hash_full) WHERE active;

CREATE TABLE threat_feed_runs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  source text NOT NULL,
  status text NOT NULL CHECK (status IN ('running', 'ok', 'failed')),
  fetched_count integer,
  accepted_count integer,
  rejected_count integer,
  added_count integer,
  deactivated_count integer,
  rejected_by_reason jsonb,
  error text,
  started_at timestamptz NOT NULL DEFAULT now(),
  finished_at timestamptz
);
CREATE INDEX threat_feed_runs_source_idx ON threat_feed_runs (source, started_at DESC);

CREATE TABLE audit_events (
  id bigserial PRIMARY KEY,
  user_id uuid REFERENCES users (id) ON DELETE SET NULL,
  session_id uuid,
  event text NOT NULL,
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  ip_hash text,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_events_user_idx ON audit_events (user_id, created_at DESC);
CREATE INDEX audit_events_created_idx ON audit_events (created_at);

CREATE TABLE privacy_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_ref_hash text NOT NULL,
  kind text NOT NULL CHECK (kind IN ('export', 'deletion')),
  status text NOT NULL CHECK (status IN ('completed', 'failed')),
  detail jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

-- Cross-process lock for periodic jobs (feed sync, monitoring, maintenance).
CREATE TABLE scheduled_tasks (
  name text PRIMARY KEY,
  last_started_at timestamptz,
  last_finished_at timestamptz,
  last_status text,
  locked_until timestamptz
);
