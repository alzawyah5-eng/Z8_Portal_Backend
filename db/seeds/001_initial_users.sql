-- Initial seed data for development
-- Executed automatically on backend start.
-- Safe to re-run anytime because of ON CONFLICT.

INSERT INTO app_users (email, email_verified, display_name, role)
VALUES 
  ('admin@z8portal.com', true, 'System Admin', 'admin')
ON CONFLICT (lower(email)) WHERE email IS NOT NULL DO UPDATE
SET role = 'admin', updated_at = now();

