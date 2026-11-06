import { getApps, initializeApp, applicationDefault, cert } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import * as argon2 from 'argon2';
import pg from 'pg';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import 'dotenv/config';

const { Pool } = pg;

/**
 * Seeds the admin user: creates/updates the Firebase account and sets the
 * password hash in app_users so they can log in with email + password.
 *
 * Safe to run on every startup — idempotent.
 */
export async function runSeedAdmin(connectionString = process.env.DATABASE_URL) {
  const email = process.env.ADMIN_SEED_EMAIL?.trim().toLowerCase();
  const password = process.env.Z8_ADMIN_SEED_PASSWORD;

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    console.warn('[SeedAdmin] Skipped: ADMIN_SEED_EMAIL is not set or invalid.');
    return;
  }
  if (!password || password.length < 8) {
    console.warn('[SeedAdmin] Skipped: Z8_ADMIN_SEED_PASSWORD is not set or too short (min 8 chars).');
    return;
  }
  if (!connectionString) {
    console.warn('[SeedAdmin] Skipped: DATABASE_URL is not set.');
    return;
  }

  const projectId = process.env.FIREBASE_PROJECT_ID;
  if (!projectId) {
    console.warn('[SeedAdmin] Skipped: FIREBASE_PROJECT_ID is not set.');
    return;
  }

  const db = new Pool({ connectionString });
  try {
    const envCred = process.env.GOOGLE_APPLICATION_CREDENTIALS;
    const candidatePaths = [
      envCred ? (path.isAbsolute(envCred) ? envCred : path.resolve(process.cwd(), envCred)) : null,
      path.resolve(process.cwd(), 'secrets/firebase-service-account.json'),
      path.resolve(process.cwd(), 'secrets/firebase-service-account.json.json'),
    ].filter((p) => p && fs.existsSync(p));

    const credential = candidatePaths.length > 0 ? cert(candidatePaths[0]) : applicationDefault();
    const app = getApps()[0] ?? initializeApp({ credential, projectId });
    const auth = getAuth(app);

    let firebaseUser;
    try {
      const current = await auth.getUserByEmail(email);
      firebaseUser = await auth.updateUser(current.uid, { emailVerified: true, disabled: false });
      console.log(`[SeedAdmin] Firebase account verified for ${email}.`);
    } catch (error) {
      const code = error && typeof error === 'object' && 'code' in error ? error.code : undefined;
      if (code !== 'auth/user-not-found') throw error;
      firebaseUser = await auth.createUser({ email, emailVerified: true, disabled: false });
      console.log(`[SeedAdmin] Created Firebase account for ${email}.`);
    }

    const firebaseUid = firebaseUser.uid;
    const passwordHash = await argon2.hash(password, { type: argon2.argon2id });

    const client = await db.connect();
    try {
      await client.query('BEGIN');
      const existing = await client.query(
        'SELECT id, firebase_uid FROM app_users WHERE lower(email) = $1 FOR UPDATE',
        [email],
      );

      if (existing.rowCount) {
        await client.query(
          `UPDATE app_users
             SET role = 'admin',
                 password_hash = $3,
                 firebase_uid  = COALESCE(firebase_uid, $2),
                 email_verified = true,
                 updated_at    = now()
           WHERE id = $1`,
          [existing.rows[0].id, firebaseUid, passwordHash],
        );
      } else {
        await client.query(
          `INSERT INTO app_users (email, firebase_uid, email_verified, role, password_hash)
           VALUES ($1, $2, true, 'admin', $3)`,
          [email, firebaseUid, passwordHash],
        );
      }

      await client.query('COMMIT');
      console.log(`[SeedAdmin] Admin seeded in DB: ${email} (uid: ${firebaseUid})`);
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  } catch (error) {
    console.error(`[SeedAdmin] Error: ${error.message}`);
  } finally {
    await db.end();
  }
}

// Allow running directly: node scripts/seed-admin.mjs [email]
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  // Override email from CLI argument if provided
  if (process.argv[2]) process.env.ADMIN_SEED_EMAIL = process.argv[2];
  await runSeedAdmin();
}
