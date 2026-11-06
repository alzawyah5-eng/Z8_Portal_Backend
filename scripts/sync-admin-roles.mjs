import { getApps, initializeApp, applicationDefault } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import pg from 'pg';
import 'dotenv/config';

const { Pool } = pg;
const projectId = process.env.FIREBASE_PROJECT_ID;
if (!projectId || !process.env.DATABASE_URL) {
  throw new Error('FIREBASE_PROJECT_ID and DATABASE_URL must be set in Backend_z8-card-flow/.env.');
}

const app = getApps()[0] ?? initializeApp({ credential: applicationDefault(), projectId });
const auth = getAuth(app);
const db = new Pool({ connectionString: process.env.DATABASE_URL });
let synchronized = 0;

try {
  const { rows } = await db.query(
    'SELECT firebase_uid, role FROM app_users WHERE firebase_uid IS NOT NULL ORDER BY id',
  );
  for (const row of rows) {
    try {
      const user = await auth.getUser(row.firebase_uid);
      const claims = {
        ...user.customClaims,
        admin: row.role === 'admin',
        role: row.role,
      };
      if (user.customClaims?.admin !== claims.admin || user.customClaims?.role !== claims.role) {
        await auth.setCustomUserClaims(user.uid, claims);
        synchronized += 1;
      }
    } catch (error) {
      const code = error && typeof error === 'object' && 'code' in error ? error.code : undefined;
      if (code !== 'auth/user-not-found') throw error;
    }
  }
  console.log(`Synchronized PostgreSQL roles for ${synchronized} Firebase account(s).`);
} finally {
  await db.end();
}
