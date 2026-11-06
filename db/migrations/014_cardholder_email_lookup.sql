ALTER TABLE cardflow_records ADD COLUMN cardholder_email_hash char(64);

CREATE INDEX cardflow_records_cardholder_email_hash_idx
  ON cardflow_records (cardholder_email_hash, updated_at DESC)
  WHERE entity = 'Cardholder' AND cardholder_email_hash IS NOT NULL;
