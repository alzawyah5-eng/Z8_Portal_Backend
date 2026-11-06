ALTER TABLE cardflow_records ADD COLUMN owner_email_hash char(64);

DROP INDEX IF EXISTS cardflow_records_owner_idx;
DROP INDEX IF EXISTS cardflow_notifications_dedupe_unique;
CREATE UNIQUE INDEX cardflow_notifications_dedupe_unique
  ON cardflow_records (owner_email_hash, (data->>'dedupe_key'))
  WHERE entity = 'Notification' AND owner_email_hash IS NOT NULL
    AND COALESCE(data->>'dedupe_key', '') <> '';

CREATE INDEX cardflow_records_entity_owner_hash_idx
  ON cardflow_records (entity, owner_email_hash, updated_at DESC)
  WHERE owner_email_hash IS NOT NULL;
