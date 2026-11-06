import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import 'dotenv/config';

const { Pool } = pg;
const here = path.dirname(fileURLToPath(import.meta.url));
const seedDir = path.resolve(here, '../db/seeds');

export async function runSeeds(connectionString = process.env.DATABASE_URL) {
  if (!connectionString) {
    console.warn('[Seed] Skipped: DATABASE_URL is not set.');
    return;
  }
  const pool = new Pool({ connectionString });
  let client;

  try {
    client = await pool.connect();

    // 1. Run all .sql seed files from Backend/db/seeds
    try {
      const files = (await readdir(seedDir)).filter((name) => name.endsWith('.sql')).sort();
      for (const name of files) {
        const sql = await readFile(path.join(seedDir, name), 'utf8');
        await client.query('BEGIN');
        await client.query(sql);
        await client.query('COMMIT');
        console.log(`[Seed] Applied seed file: ${name}`);
      }
    } catch (err) {
      if (err.code !== 'ENOENT') {
        if (client) await client.query('ROLLBACK').catch(() => {});
        console.error(`[Seed Warning] Failed running seed files: ${err.message}`);
      }
    }

    // 2. Ensure any custom admin emails from .env are seeded as admin
    const configuredAdminEmail = process.env.ADMIN_SEED_EMAIL?.trim().toLowerCase();
    const adminEmails = configuredAdminEmail && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(configuredAdminEmail)
      ? [configuredAdminEmail]
      : [];
    for (const email of adminEmails) {
      await client.query(
        `INSERT INTO app_users (email, email_verified, display_name, role)
         VALUES ($1, true, 'Admin', 'admin')
         ON CONFLICT (lower(email)) WHERE email IS NOT NULL DO UPDATE
         SET role = 'admin', updated_at = now()`,
        [email],
      );
      console.log(`[Seed] Seeded admin email from .env: ${email}`);
    }

    const { rows } = await client.query('SELECT count(*)::int as count FROM app_users');
    console.log(`[Seed] Database ready. Active users in app_users: ${rows[0]?.count ?? 0}`);
  } catch (error) {
    console.error(`[Seed Error] Could not complete seeding: ${error.message}`);
  } finally {
    if (client) client.release();
    await pool.end();
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await runSeeds();
}

