CREATE TABLE cardflow_workflow_outbox (
  event_key text PRIMARY KEY CHECK (length(event_key) BETWEEN 1 AND 256),
  event_type text NOT NULL CHECK (event_type IN ('card_status_changed', 'declined_transaction')),
  entity_id text NOT NULL CHECK (length(entity_id) BETWEEN 1 AND 128),
  payload jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(payload) = 'object'),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'sent')),
  attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
  next_attempt_at timestamptz NOT NULL DEFAULT now(),
  lease_until timestamptz,
  sent_at timestamptz,
  last_error_code text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX cardflow_workflow_outbox_ready_idx
  ON cardflow_workflow_outbox (next_attempt_at, created_at)
  WHERE status <> 'sent';
