ALTER TABLE app_users ADD COLUMN deleted_at timestamptz;
CREATE INDEX app_users_active_email_idx ON app_users (lower(email)) WHERE deleted_at IS NULL AND email IS NOT NULL;
