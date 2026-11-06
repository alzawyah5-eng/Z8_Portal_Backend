ALTER TABLE app_users
  ADD COLUMN full_name text GENERATED ALWAYS AS (display_name) STORED;

CREATE INDEX app_users_full_name_idx
  ON app_users (full_name)
  WHERE deleted_at IS NULL AND full_name IS NOT NULL;
