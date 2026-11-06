-- PostgreSQL is the account directory for the mobile application. A row with
-- no Firebase UID is an invitation; only an invited email may claim it.
ALTER TABLE app_users
  ALTER COLUMN firebase_uid DROP NOT NULL,
  ADD COLUMN role text NOT NULL DEFAULT 'user'
    CHECK (role IN ('user', 'admin'));

