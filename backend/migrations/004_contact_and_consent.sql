CREATE TABLE contact_submissions (
  id uuid PRIMARY KEY,
  user_id uuid REFERENCES users(id) ON DELETE CASCADE,
  content_enc jsonb NOT NULL,
  status text NOT NULL CHECK (status IN ('pending','accepted','failed')),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX contact_submissions_created_idx ON contact_submissions(created_at);
-- New accounts must opt in to optional security email; preserve existing choices.
ALTER TABLE notification_preferences ALTER COLUMN security_alerts_email SET DEFAULT false;
