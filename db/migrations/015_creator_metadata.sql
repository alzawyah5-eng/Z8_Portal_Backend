ALTER TABLE cardflow_records ADD COLUMN created_by_id text;
ALTER TABLE app_users ADD COLUMN created_by_id text;

CREATE INDEX cardflow_records_creator_idx
  ON cardflow_records (created_by_id, created_at DESC)
  WHERE created_by_id IS NOT NULL;
