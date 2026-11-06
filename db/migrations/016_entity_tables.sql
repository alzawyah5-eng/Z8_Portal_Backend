-- Replace the generic record bucket with one typed PostgreSQL table per Card Flow entity.
-- JSONB remains as a compatibility payload; generated columns expose/index the declared schema.
ALTER TABLE app_users ADD COLUMN created_date timestamptz GENERATED ALWAYS AS (created_at) STORED;
ALTER TABLE app_users ADD COLUMN updated_date timestamptz GENERATED ALWAYS AS (updated_at) STORED;
ALTER TABLE photonpay_tokens ADD COLUMN created_by_id text;
ALTER TABLE photonpay_tokens ADD COLUMN created_date timestamptz GENERATED ALWAYS AS (updated_at) STORED;
ALTER TABLE photonpay_tokens ADD COLUMN updated_date timestamptz GENERATED ALWAYS AS (updated_at) STORED;
CREATE TABLE account_entries (
  id text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
  data jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(data) = 'object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  created_by_id text,
  owner_email_hash char(64),
  cardholder_email_hash char(64),
  created_date timestamptz GENERATED ALWAYS AS (created_at) STORED,
  updated_date timestamptz GENERATED ALWAYS AS (updated_at) STORED,
  owner_email jsonb GENERATED ALWAYS AS (data->'owner_email') STORED,
  client_name jsonb GENERATED ALWAYS AS (data->'client_name') STORED,
  kind text GENERATED ALWAYS AS (data->>'kind') STORED,
  status text GENERATED ALWAYS AS (data->>'status') STORED,
  amount numeric GENERATED ALWAYS AS (NULLIF(data->>'amount', '')::numeric) STORED,
  currency text GENERATED ALWAYS AS (data->>'currency') STORED,
  method text GENERATED ALWAYS AS (data->>'method') STORED,
  reference jsonb GENERATED ALWAYS AS (data->'reference') STORED,
  note jsonb GENERATED ALWAYS AS (data->'note') STORED,
  admin_note jsonb GENERATED ALWAYS AS (data->'admin_note') STORED,
  reported_by jsonb GENERATED ALWAYS AS (data->'reported_by') STORED,
  reported_amount numeric GENERATED ALWAYS AS (NULLIF(data->>'reported_amount', '')::numeric) STORED,
  recorded_by jsonb GENERATED ALWAYS AS (data->'recorded_by') STORED,
  recorded_at text GENERATED ALWAYS AS (data->>'recorded_at') STORED,
  card_id text GENERATED ALWAYS AS (data->>'card_id') STORED,
  card_request_id text GENERATED ALWAYS AS (data->>'card_request_id') STORED,
  proof_file_uri jsonb GENERATED ALWAYS AS (data->'proof_file_uri') STORED,
  proof_type text GENERATED ALWAYS AS (data->>'proof_type') STORED,
  proof_name jsonb GENERATED ALWAYS AS (data->'proof_name') STORED
);
CREATE INDEX account_entries_created_idx ON account_entries (created_at DESC);
CREATE INDEX account_entries_creator_idx ON account_entries (created_by_id, created_at DESC) WHERE created_by_id IS NOT NULL;
CREATE INDEX account_entries_data_gin_idx ON account_entries USING gin (data jsonb_path_ops);
CREATE INDEX account_entries_owner_hash_idx ON account_entries (owner_email_hash, created_at DESC) WHERE owner_email_hash IS NOT NULL;
INSERT INTO account_entries (id, data, created_at, updated_at, owner_email_hash, cardholder_email_hash, created_by_id)
SELECT id, data, created_at, updated_at, owner_email_hash, cardholder_email_hash, created_by_id FROM cardflow_records WHERE entity = 'AccountEntry';
CREATE TABLE cards (
  id text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
  data jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(data) = 'object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  created_by_id text,
  owner_email_hash char(64),
  cardholder_email_hash char(64),
  created_date timestamptz GENERATED ALWAYS AS (created_at) STORED,
  updated_date timestamptz GENERATED ALWAYS AS (updated_at) STORED,
  nickname text GENERATED ALWAYS AS (data->>'nickname') STORED,
  tier text GENERATED ALWAYS AS (data->>'tier') STORED,
  purpose text GENERATED ALWAYS AS (data->>'purpose') STORED,
  purpose_detail jsonb GENERATED ALWAYS AS (data->'purpose_detail') STORED,
  masked_number text GENERATED ALWAYS AS (data->>'masked_number') STORED,
  last4 text GENERATED ALWAYS AS (data->>'last4') STORED,
  expiry text GENERATED ALWAYS AS (data->>'expiry') STORED,
  currency text GENERATED ALWAYS AS (data->>'currency') STORED,
  scheme text GENERATED ALWAYS AS (data->>'scheme') STORED,
  card_type text GENERATED ALWAYS AS (data->>'card_type') STORED,
  form_factor text GENERATED ALWAYS AS (data->>'form_factor') STORED,
  status text GENERATED ALWAYS AS (data->>'status') STORED,
  balance numeric GENERATED ALWAYS AS (NULLIF(data->>'balance', '')::numeric) STORED,
  monthly_spend numeric GENERATED ALWAYS AS (NULLIF(data->>'monthly_spend', '')::numeric) STORED,
  max_on_daily numeric GENERATED ALWAYS AS (NULLIF(data->>'max_on_daily', '')::numeric) STORED,
  max_on_monthly numeric GENERATED ALWAYS AS (NULLIF(data->>'max_on_monthly', '')::numeric) STORED,
  max_on_percent numeric GENERATED ALWAYS AS (NULLIF(data->>'max_on_percent', '')::numeric) STORED,
  transaction_limit_type text GENERATED ALWAYS AS (data->>'transaction_limit_type') STORED,
  cardholder_name jsonb GENERATED ALWAYS AS (data->'cardholder_name') STORED,
  cardholder_id text GENERATED ALWAYS AS (data->>'cardholder_id') STORED,
  photon_card_id text GENERATED ALWAYS AS (data->>'photon_card_id') STORED,
  photon_cardholder_id text GENERATED ALWAYS AS (data->>'photon_cardholder_id') STORED,
  request_id text GENERATED ALWAYS AS (data->>'request_id') STORED,
  bin text GENERATED ALWAYS AS (data->>'bin') STORED,
  notes jsonb GENERATED ALWAYS AS (data->'notes') STORED,
  owner_email jsonb GENERATED ALWAYS AS (data->'owner_email') STORED,
  funded_at text GENERATED ALWAYS AS (data->>'funded_at') STORED,
  auto_issued boolean GENERATED ALWAYS AS (NULLIF(data->>'auto_issued', '')::boolean) STORED,
  pending_topup_amount numeric GENERATED ALWAYS AS (NULLIF(data->>'pending_topup_amount', '')::numeric) STORED,
  pending_topup_request_id text GENERATED ALWAYS AS (data->>'pending_topup_request_id') STORED,
  available_transaction_limit numeric GENERATED ALWAYS AS (NULLIF(data->>'available_transaction_limit', '')::numeric) STORED
);
CREATE INDEX cards_created_idx ON cards (created_at DESC);
CREATE INDEX cards_creator_idx ON cards (created_by_id, created_at DESC) WHERE created_by_id IS NOT NULL;
CREATE INDEX cards_data_gin_idx ON cards USING gin (data jsonb_path_ops);
CREATE INDEX cards_owner_hash_idx ON cards (owner_email_hash, created_at DESC) WHERE owner_email_hash IS NOT NULL;
INSERT INTO cards (id, data, created_at, updated_at, owner_email_hash, cardholder_email_hash, created_by_id)
SELECT id, data, created_at, updated_at, owner_email_hash, cardholder_email_hash, created_by_id FROM cardflow_records WHERE entity = 'Card';
CREATE TABLE card_transactions (
  id text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
  data jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(data) = 'object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  created_by_id text,
  owner_email_hash char(64),
  cardholder_email_hash char(64),
  created_date timestamptz GENERATED ALWAYS AS (created_at) STORED,
  updated_date timestamptz GENERATED ALWAYS AS (updated_at) STORED,
  kind text GENERATED ALWAYS AS (data->>'kind') STORED,
  event text GENERATED ALWAYS AS (data->>'event') STORED,
  card_id text GENERATED ALWAYS AS (data->>'card_id') STORED,
  card_last4 text GENERATED ALWAYS AS (data->>'card_last4') STORED,
  card_nickname text GENERATED ALWAYS AS (data->>'card_nickname') STORED,
  merchant jsonb GENERATED ALWAYS AS (data->'merchant') STORED,
  amount numeric GENERATED ALWAYS AS (NULLIF(data->>'amount', '')::numeric) STORED,
  currency text GENERATED ALWAYS AS (data->>'currency') STORED,
  status text GENERATED ALWAYS AS (data->>'status') STORED,
  category text GENERATED ALWAYS AS (data->>'category') STORED,
  occurred_at text GENERATED ALWAYS AS (data->>'occurred_at') STORED,
  note jsonb GENERATED ALWAYS AS (data->'note') STORED,
  photon_txn_id text GENERATED ALWAYS AS (data->>'photon_txn_id') STORED,
  owner_email jsonb GENERATED ALWAYS AS (data->'owner_email') STORED
);
CREATE INDEX card_transactions_created_idx ON card_transactions (created_at DESC);
CREATE INDEX card_transactions_creator_idx ON card_transactions (created_by_id, created_at DESC) WHERE created_by_id IS NOT NULL;
CREATE INDEX card_transactions_data_gin_idx ON card_transactions USING gin (data jsonb_path_ops);
CREATE INDEX card_transactions_owner_hash_idx ON card_transactions (owner_email_hash, created_at DESC) WHERE owner_email_hash IS NOT NULL;
CREATE UNIQUE INDEX card_transactions_provider_id_unique ON card_transactions ((data->>'photon_txn_id')) WHERE COALESCE(data->>'photon_txn_id', '') <> '';
INSERT INTO card_transactions (id, data, created_at, updated_at, owner_email_hash, cardholder_email_hash, created_by_id)
SELECT id, data, created_at, updated_at, owner_email_hash, cardholder_email_hash, created_by_id FROM cardflow_records WHERE entity = 'CardTransaction';
CREATE TABLE cardholders (
  id text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
  data jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(data) = 'object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  created_by_id text,
  owner_email_hash char(64),
  cardholder_email_hash char(64),
  created_date timestamptz GENERATED ALWAYS AS (created_at) STORED,
  updated_date timestamptz GENERATED ALWAYS AS (updated_at) STORED,
  full_name jsonb GENERATED ALWAYS AS (data->'full_name') STORED,
  first_name jsonb GENERATED ALWAYS AS (data->'first_name') STORED,
  last_name jsonb GENERATED ALWAYS AS (data->'last_name') STORED,
  email jsonb GENERATED ALWAYS AS (data->'email') STORED,
  phone jsonb GENERATED ALWAYS AS (data->'phone') STORED,
  date_of_birth jsonb GENERATED ALWAYS AS (data->'date_of_birth') STORED,
  nationality jsonb GENERATED ALWAYS AS (data->'nationality') STORED,
  address_line jsonb GENERATED ALWAYS AS (data->'address_line') STORED,
  city jsonb GENERATED ALWAYS AS (data->'city') STORED,
  state jsonb GENERATED ALWAYS AS (data->'state') STORED,
  postal_code jsonb GENERATED ALWAYS AS (data->'postal_code') STORED,
  country jsonb GENERATED ALWAYS AS (data->'country') STORED,
  cert_type jsonb GENERATED ALWAYS AS (data->'cert_type') STORED,
  cert_id jsonb GENERATED ALWAYS AS (data->'cert_id') STORED,
  cert_country jsonb GENERATED ALWAYS AS (data->'cert_country') STORED,
  photon_cardholder_id text GENERATED ALWAYS AS (data->>'photon_cardholder_id') STORED,
  status text GENERATED ALWAYS AS (data->>'status') STORED,
  notes jsonb GENERATED ALWAYS AS (data->'notes') STORED,
  master_account_email jsonb GENERATED ALWAYS AS (data->'master_account_email') STORED,
  provider_status text GENERATED ALWAYS AS (data->>'provider_status') STORED,
  review_status text GENERATED ALWAYS AS (data->>'review_status') STORED,
  review_reason jsonb GENERATED ALWAYS AS (data->'review_reason') STORED,
  synced_at text GENERATED ALWAYS AS (data->>'synced_at') STORED,
  owner_email jsonb GENERATED ALWAYS AS (data->'owner_email') STORED,
  device_ip jsonb GENERATED ALWAYS AS (data->'device_ip') STORED,
  device_country jsonb GENERATED ALWAYS AS (data->'device_country') STORED,
  auto_issue_status text GENERATED ALWAYS AS (data->>'auto_issue_status') STORED,
  auto_issue_note jsonb GENERATED ALWAYS AS (data->'auto_issue_note') STORED,
  photon_created_at text GENERATED ALWAYS AS (data->>'photon_created_at') STORED,
  is_legal text GENERATED ALWAYS AS (data->>'is_legal') STORED,
  id_info_requirement text GENERATED ALWAYS AS (data->>'id_info_requirement') STORED
);
CREATE INDEX cardholders_created_idx ON cardholders (created_at DESC);
CREATE INDEX cardholders_creator_idx ON cardholders (created_by_id, created_at DESC) WHERE created_by_id IS NOT NULL;
CREATE INDEX cardholders_data_gin_idx ON cardholders USING gin (data jsonb_path_ops);
CREATE INDEX cardholders_owner_hash_idx ON cardholders (owner_email_hash, created_at DESC) WHERE owner_email_hash IS NOT NULL;
CREATE INDEX cardholders_email_hash_idx ON cardholders (cardholder_email_hash, created_at DESC) WHERE cardholder_email_hash IS NOT NULL;
INSERT INTO cardholders (id, data, created_at, updated_at, owner_email_hash, cardholder_email_hash, created_by_id)
SELECT id, data, created_at, updated_at, owner_email_hash, cardholder_email_hash, created_by_id FROM cardflow_records WHERE entity = 'Cardholder';
CREATE TABLE cardholder_applications (
  id text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
  data jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(data) = 'object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  created_by_id text,
  owner_email_hash char(64),
  cardholder_email_hash char(64),
  created_date timestamptz GENERATED ALWAYS AS (created_at) STORED,
  updated_date timestamptz GENERATED ALWAYS AS (updated_at) STORED,
  owner_email jsonb GENERATED ALWAYS AS (data->'owner_email') STORED,
  status text GENERATED ALWAYS AS (data->>'status') STORED,
  first_name jsonb GENERATED ALWAYS AS (data->'first_name') STORED,
  last_name jsonb GENERATED ALWAYS AS (data->'last_name') STORED,
  date_of_birth jsonb GENERATED ALWAYS AS (data->'date_of_birth') STORED,
  nationality jsonb GENERATED ALWAYS AS (data->'nationality') STORED,
  email jsonb GENERATED ALWAYS AS (data->'email') STORED,
  mobile_prefix jsonb GENERATED ALWAYS AS (data->'mobile_prefix') STORED,
  mobile jsonb GENERATED ALWAYS AS (data->'mobile') STORED,
  address_line jsonb GENERATED ALWAYS AS (data->'address_line') STORED,
  city jsonb GENERATED ALWAYS AS (data->'city') STORED,
  state jsonb GENERATED ALWAYS AS (data->'state') STORED,
  postal_code jsonb GENERATED ALWAYS AS (data->'postal_code') STORED,
  country jsonb GENERATED ALWAYS AS (data->'country') STORED,
  cert_type jsonb GENERATED ALWAYS AS (data->'cert_type') STORED,
  cert_id jsonb GENERATED ALWAYS AS (data->'cert_id') STORED,
  cert_country jsonb GENERATED ALWAYS AS (data->'cert_country') STORED,
  front_file_uri text GENERATED ALWAYS AS (data->>'front_file_uri') STORED,
  back_file_uri text GENERATED ALWAYS AS (data->>'back_file_uri') STORED,
  submitted_at text GENERATED ALWAYS AS (data->>'submitted_at') STORED,
  reviewed_by jsonb GENERATED ALWAYS AS (data->'reviewed_by') STORED,
  reviewed_at text GENERATED ALWAYS AS (data->>'reviewed_at') STORED,
  review_note jsonb GENERATED ALWAYS AS (data->'review_note') STORED,
  last_error jsonb GENERATED ALWAYS AS (data->'last_error') STORED,
  photon_cardholder_id text GENERATED ALWAYS AS (data->>'photon_cardholder_id') STORED,
  cardholder_record_id text GENERATED ALWAYS AS (data->>'cardholder_record_id') STORED,
  device_ip jsonb GENERATED ALWAYS AS (data->'device_ip') STORED,
  device_country jsonb GENERATED ALWAYS AS (data->'device_country') STORED
);
CREATE INDEX cardholder_applications_created_idx ON cardholder_applications (created_at DESC);
CREATE INDEX cardholder_applications_creator_idx ON cardholder_applications (created_by_id, created_at DESC) WHERE created_by_id IS NOT NULL;
CREATE INDEX cardholder_applications_data_gin_idx ON cardholder_applications USING gin (data jsonb_path_ops);
CREATE INDEX cardholder_applications_owner_hash_idx ON cardholder_applications (owner_email_hash, created_at DESC) WHERE owner_email_hash IS NOT NULL;
INSERT INTO cardholder_applications (id, data, created_at, updated_at, owner_email_hash, cardholder_email_hash, created_by_id)
SELECT id, data, created_at, updated_at, owner_email_hash, cardholder_email_hash, created_by_id FROM cardflow_records WHERE entity = 'CardholderApplication';
CREATE TABLE card_requests (
  id text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
  data jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(data) = 'object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  created_by_id text,
  owner_email_hash char(64),
  cardholder_email_hash char(64),
  created_date timestamptz GENERATED ALWAYS AS (created_at) STORED,
  updated_date timestamptz GENERATED ALWAYS AS (updated_at) STORED,
  status text GENERATED ALWAYS AS (data->>'status') STORED,
  owner_email jsonb GENERATED ALWAYS AS (data->'owner_email') STORED,
  cardholder_record_id text GENERATED ALWAYS AS (data->>'cardholder_record_id') STORED,
  photon_cardholder_id text GENERATED ALWAYS AS (data->>'photon_cardholder_id') STORED,
  client_name jsonb GENERATED ALWAYS AS (data->'client_name') STORED,
  amount numeric GENERATED ALWAYS AS (NULLIF(data->>'amount', '')::numeric) STORED,
  approved_amount numeric GENERATED ALWAYS AS (NULLIF(data->>'approved_amount', '')::numeric) STORED,
  currency text GENERATED ALWAYS AS (data->>'currency') STORED,
  client_note jsonb GENERATED ALWAYS AS (data->'client_note') STORED,
  tier text GENERATED ALWAYS AS (data->>'tier') STORED,
  purpose text GENERATED ALWAYS AS (data->>'purpose') STORED,
  purpose_detail text GENERATED ALWAYS AS (data->>'purpose_detail') STORED,
  requested_at text GENERATED ALWAYS AS (data->>'requested_at') STORED,
  reviewed_by jsonb GENERATED ALWAYS AS (data->'reviewed_by') STORED,
  reviewed_at text GENERATED ALWAYS AS (data->>'reviewed_at') STORED,
  review_note jsonb GENERATED ALWAYS AS (data->'review_note') STORED,
  last_error jsonb GENERATED ALWAYS AS (data->'last_error') STORED,
  card_record_id text GENERATED ALWAYS AS (data->>'card_record_id') STORED,
  provider_request_id text GENERATED ALWAYS AS (data->>'provider_request_id') STORED
);
CREATE INDEX card_requests_created_idx ON card_requests (created_at DESC);
CREATE INDEX card_requests_creator_idx ON card_requests (created_by_id, created_at DESC) WHERE created_by_id IS NOT NULL;
CREATE INDEX card_requests_data_gin_idx ON card_requests USING gin (data jsonb_path_ops);
CREATE INDEX card_requests_owner_hash_idx ON card_requests (owner_email_hash, created_at DESC) WHERE owner_email_hash IS NOT NULL;
INSERT INTO card_requests (id, data, created_at, updated_at, owner_email_hash, cardholder_email_hash, created_by_id)
SELECT id, data, created_at, updated_at, owner_email_hash, cardholder_email_hash, created_by_id FROM cardflow_records WHERE entity = 'CardRequest';
CREATE TABLE notifications (
  id text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
  data jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(data) = 'object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  created_by_id text,
  owner_email_hash char(64),
  cardholder_email_hash char(64),
  created_date timestamptz GENERATED ALWAYS AS (created_at) STORED,
  updated_date timestamptz GENERATED ALWAYS AS (updated_at) STORED,
  owner_email jsonb GENERATED ALWAYS AS (data->'owner_email') STORED,
  kind text GENERATED ALWAYS AS (data->>'kind') STORED,
  tone text GENERATED ALWAYS AS (data->>'tone') STORED,
  title jsonb GENERATED ALWAYS AS (data->'title') STORED,
  body jsonb GENERATED ALWAYS AS (data->'body') STORED,
  link text GENERATED ALWAYS AS (data->>'link') STORED,
  read boolean GENERATED ALWAYS AS (NULLIF(data->>'read', '')::boolean) STORED,
  read_at text GENERATED ALWAYS AS (data->>'read_at') STORED,
  dedupe_key text GENERATED ALWAYS AS (data->>'dedupe_key') STORED
);
CREATE INDEX notifications_created_idx ON notifications (created_at DESC);
CREATE INDEX notifications_creator_idx ON notifications (created_by_id, created_at DESC) WHERE created_by_id IS NOT NULL;
CREATE INDEX notifications_data_gin_idx ON notifications USING gin (data jsonb_path_ops);
CREATE INDEX notifications_owner_hash_idx ON notifications (owner_email_hash, created_at DESC) WHERE owner_email_hash IS NOT NULL;
CREATE UNIQUE INDEX notifications_dedupe_unique ON notifications (owner_email_hash, (data->>'dedupe_key')) WHERE owner_email_hash IS NOT NULL AND COALESCE(data->>'dedupe_key', '') <> '';
INSERT INTO notifications (id, data, created_at, updated_at, owner_email_hash, cardholder_email_hash, created_by_id)
SELECT id, data, created_at, updated_at, owner_email_hash, cardholder_email_hash, created_by_id FROM cardflow_records WHERE entity = 'Notification';
CREATE TABLE photonpay_logs (
  id text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
  data jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(data) = 'object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  created_by_id text,
  owner_email_hash char(64),
  cardholder_email_hash char(64),
  created_date timestamptz GENERATED ALWAYS AS (created_at) STORED,
  updated_date timestamptz GENERATED ALWAYS AS (updated_at) STORED,
  kind text GENERATED ALWAYS AS (data->>'kind') STORED,
  source text GENERATED ALWAYS AS (data->>'source') STORED,
  environment text GENERATED ALWAYS AS (data->>'environment') STORED,
  method text GENERATED ALWAYS AS (data->>'method') STORED,
  host text GENERATED ALWAYS AS (data->>'host') STORED,
  path text GENERATED ALWAYS AS (data->>'path') STORED,
  request_headers text GENERATED ALWAYS AS (data->>'request_headers') STORED,
  request_body text GENERATED ALWAYS AS (data->>'request_body') STORED,
  started_at text GENERATED ALWAYS AS (data->>'started_at') STORED,
  http_status integer GENERATED ALWAYS AS (NULLIF(data->>'http_status', '')::integer) STORED,
  provider_code text GENERATED ALWAYS AS (data->>'provider_code') STORED,
  response_headers text GENERATED ALWAYS AS (data->>'response_headers') STORED,
  response_body text GENERATED ALWAYS AS (data->>'response_body') STORED,
  finished_at text GENERATED ALWAYS AS (data->>'finished_at') STORED,
  duration_ms integer GENERATED ALWAYS AS (NULLIF(data->>'duration_ms', '')::integer) STORED,
  error text GENERATED ALWAYS AS (data->>'error') STORED
);
CREATE INDEX photonpay_logs_created_idx ON photonpay_logs (created_at DESC);
CREATE INDEX photonpay_logs_creator_idx ON photonpay_logs (created_by_id, created_at DESC) WHERE created_by_id IS NOT NULL;
CREATE INDEX photonpay_logs_data_gin_idx ON photonpay_logs USING gin (data jsonb_path_ops);
INSERT INTO photonpay_logs (id, data, created_at, updated_at, owner_email_hash, cardholder_email_hash, created_by_id)
SELECT id, data, created_at, updated_at, owner_email_hash, cardholder_email_hash, created_by_id FROM cardflow_records WHERE entity = 'PhotonPayLog';
CREATE TABLE programme_settings (
  id text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 128),
  data jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(data) = 'object'),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  created_by_id text,
  owner_email_hash char(64),
  cardholder_email_hash char(64),
  created_date timestamptz GENERATED ALWAYS AS (created_at) STORED,
  updated_date timestamptz GENERATED ALWAYS AS (updated_at) STORED,
  client_requests_enabled boolean GENERATED ALWAYS AS (NULLIF(data->>'client_requests_enabled', '')::boolean) STORED,
  client_topups_enabled boolean GENERATED ALWAYS AS (NULLIF(data->>'client_topups_enabled', '')::boolean) STORED,
  max_cards_per_client integer GENERATED ALWAYS AS (NULLIF(data->>'max_cards_per_client', '')::integer) STORED,
  default_max_on_daily numeric GENERATED ALWAYS AS (NULLIF(data->>'default_max_on_daily', '')::numeric) STORED,
  default_max_on_monthly numeric GENERATED ALWAYS AS (NULLIF(data->>'default_max_on_monthly', '')::numeric) STORED,
  default_max_on_percent numeric GENERATED ALWAYS AS (NULLIF(data->>'default_max_on_percent', '')::numeric) STORED,
  tier_emerald_enabled boolean GENERATED ALWAYS AS (NULLIF(data->>'tier_emerald_enabled', '')::boolean) STORED,
  tier_plum_enabled boolean GENERATED ALWAYS AS (NULLIF(data->>'tier_plum_enabled', '')::boolean) STORED,
  tier_crimson_enabled boolean GENERATED ALWAYS AS (NULLIF(data->>'tier_crimson_enabled', '')::boolean) STORED,
  tier_start_amount numeric GENERATED ALWAYS AS (NULLIF(data->>'tier_start_amount', '')::numeric) STORED,
  tier_plum_from numeric GENERATED ALWAYS AS (NULLIF(data->>'tier_plum_from', '')::numeric) STORED,
  tier_crimson_from numeric GENERATED ALWAYS AS (NULLIF(data->>'tier_crimson_from', '')::numeric) STORED,
  funding_instructions text GENERATED ALWAYS AS (data->>'funding_instructions') STORED,
  min_opening_amount numeric GENERATED ALWAYS AS (NULLIF(data->>'min_opening_amount', '')::numeric) STORED
);
CREATE INDEX programme_settings_created_idx ON programme_settings (created_at DESC);
CREATE INDEX programme_settings_creator_idx ON programme_settings (created_by_id, created_at DESC) WHERE created_by_id IS NOT NULL;
CREATE INDEX programme_settings_data_gin_idx ON programme_settings USING gin (data jsonb_path_ops);
CREATE UNIQUE INDEX programme_settings_singleton_idx ON programme_settings ((true));
INSERT INTO programme_settings (id, data, created_at, updated_at, owner_email_hash, cardholder_email_hash, created_by_id)
SELECT id, data, created_at, updated_at, owner_email_hash, cardholder_email_hash, created_by_id FROM cardflow_records WHERE entity = 'ProgrammeSettings';
DROP TABLE cardflow_records;

