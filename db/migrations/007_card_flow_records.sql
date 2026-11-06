-- Flexible storage for the existing Card Flow records while preserving the
-- existing UI's JSON fields. Core login/roles, devices, ledger and PhotonPay
-- access tokens remain in their dedicated relational tables.
CREATE TABLE cardflow_records (
  entity text NOT NULL CHECK (entity IN (
    'AccountEntry', 'Card', 'Cardholder', 'CardholderApplication',
    'CardRequest', 'CardTransaction', 'Notification', 'PhotonPayLog',
    'ProgrammeSettings'
  )),
  id text NOT NULL CHECK (length(id) BETWEEN 1 AND 128),
  data jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(data) = 'object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (entity, id)
);

CREATE INDEX cardflow_records_entity_updated_idx
  ON cardflow_records (entity, updated_at DESC);
CREATE INDEX cardflow_records_data_gin_idx
  ON cardflow_records USING gin (data jsonb_path_ops);
CREATE INDEX cardflow_records_owner_idx
  ON cardflow_records (entity, lower((data->>'owner_email')))
  WHERE data ? 'owner_email';
CREATE UNIQUE INDEX cardflow_transactions_provider_id_unique
  ON cardflow_records ((data->>'photon_txn_id'))
  WHERE entity = 'CardTransaction' AND COALESCE(data->>'photon_txn_id', '') <> '';
CREATE UNIQUE INDEX cardflow_notifications_dedupe_unique
  ON cardflow_records (lower((data->>'owner_email')), (data->>'dedupe_key'))
  WHERE entity = 'Notification' AND COALESCE(data->>'dedupe_key', '') <> '';

-- Store the admin-edited card programme as a single record.
CREATE UNIQUE INDEX cardflow_programme_settings_singleton
  ON cardflow_records (entity) WHERE entity = 'ProgrammeSettings';
