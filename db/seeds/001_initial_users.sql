-- Initial seed data for development
-- Executed automatically on backend start.
-- Safe to re-run anytime because of ON CONFLICT.

INSERT INTO app_users (email, email_verified, display_name, role)
VALUES 
  ('uaebenflis@gmail.com', true, 'Haroon', 'admin')
ON CONFLICT (lower(email)) WHERE email IS NOT NULL DO UPDATE
SET role = 'admin',
    display_name = COALESCE(NULLIF(BTRIM(app_users.display_name), ''), EXCLUDED.display_name),
    updated_at = now();

