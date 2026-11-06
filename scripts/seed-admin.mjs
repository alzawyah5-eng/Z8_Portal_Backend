import { getApps, initializeApp, applicationDefault, cert } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import * as argon2 from 'argon2';
import pg from 'pg';
import fs from 'node:fs';
import path from 'node:path';
import 'dotenv/config';

const email = (process.argv[2] || process.env.ADMIN_SEED_EMAIL)?.trim().toLowerCase();
const password = process.env.Z8_ADMIN_SEED_PASSWORD;
if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
  throw new Error('Set ADMIN_SEED_EMAIL in Backend_z8-card-flow/.env or pass an email argument.');
}
if (!password || password.length < 8) {
  throw new Error('Set Z8_ADMIN_SEED_PASSWORD to a password of at least 8 characters for this command.');
}

const { Pool } = pg;
const db = new Pool({ connectionString: process.env.DATABASE_URL });
let verifiedFirebaseUser;

try {
  if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL must be set in Backend_z8-card-flow/.env.');
  const projectId = process.env.FIREBASE_PROJECT_ID;
  if (!projectId) throw new Error('FIREBASE_PROJECT_ID must be set in Backend_z8-card-flow/.env.');

  const envCred = process.env.GOOGLE_APPLICATION_CREDENTIALS;
  const candidatePaths = [
    envCred ? (path.isAbsolute(envCred) ? envCred : path.resolve(process.cwd(), envCred)) : null,
    path.resolve(process.cwd(), 'secrets/firebase-service-account.json'),
    path.resolve(process.cwd(), 'secrets/firebase-service-account.json.json'),
  ].filter((p) => p && fs.existsSync(p));

  const credential = candidatePaths.length > 0 ? cert(candidatePaths[0]) : applicationDefault();
  const app = getApps()[0] ?? initializeApp({ credential, projectId });
  const auth = getAuth(app);
  try {
    const current = await auth.getUserByEmail(email);
    verifiedFirebaseUser = await auth.updateUser(current.uid, {
      emailVerified: true,
      disabled: false,
    });
    console.log('Updated the Firebase admin credential and verified email status.');
  } catch (error) {
    const code = error && typeof error === 'object' && 'code' in error ? error.code : undefined;
    if (code !== 'auth/user-not-found') throw error;
    verifiedFirebaseUser = await auth.createUser({
      email,
      emailVerified: true,
      disabled: false,
    });
    console.log('Created the Firebase admin credential.');
  }
  const firebaseUid = verifiedFirebaseUser.uid;
  const passwordHash = await argon2.hash(password, { type: argon2.argon2id });

  const client = await db.connect();
  try {
    await client.query('BEGIN');
    const existing = await client.query(
      'SELECT id, firebase_uid FROM app_users WHERE lower(email) = $1 FOR UPDATE',
      [email],
    );
    if (
      existing.rowCount && existing.rows[0].firebase_uid &&
      existing.rows[0].firebase_uid !== firebaseUid
    ) {
      throw new Error('This email is already linked to a different Firebase account.');
    }
    if (existing.rowCount) {
      const linkedUid = await client.query(
        'SELECT 1 FROM app_users WHERE firebase_uid = $1 AND id <> $2',
        [firebaseUid, existing.rows[0].id],
      );
      if (linkedUid.rowCount) throw new Error('This Firebase account is linked to a different database email.');
    }

    const result = existing.rowCount
      ? await client.query(
          `UPDATE app_users SET role = 'admin', password_hash = $3,
             firebase_uid = COALESCE(firebase_uid, $2),
             email_verified = true,
             updated_at = now()
           WHERE id = $1 RETURNING id, email, firebase_uid, role`,
          [existing.rows[0].id, firebaseUid, passwordHash],
        )
      : await client.query(
          `INSERT INTO app_users (email, firebase_uid, email_verified, role, password_hash)
           VALUES ($1, $2, true, 'admin', $3) RETURNING id, email, firebase_uid, role`,
          [email, firebaseUid, passwordHash],
        );
    await client.query('COMMIT');
    console.log(`Seeded PostgreSQL admin ${result.rows[0].email} (${result.rows[0].firebase_uid}).`);
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
} finally {
  await db.end();
}
