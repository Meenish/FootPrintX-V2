-- Development-only: messages injected into a *synthetic* mailbox (see
-- src/services/synthetic.js) to exercise verification flows. Only rows tied to
-- a synthetic connection can exist here; nothing reads this table for real
-- Gmail connections. The API that writes it is disabled unless
-- DEV_SYNTHETIC_DATA=true, which production configuration rejects.
CREATE TABLE synthetic_messages (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  connection_id uuid NOT NULL REFERENCES email_connections (id) ON DELETE CASCADE,
  from_header text NOT NULL,
  subject text NOT NULL,
  auth_results text,
  internal_date timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX synthetic_messages_conn_idx ON synthetic_messages (connection_id);
