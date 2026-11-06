import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import 'dotenv/config';
import { runSeeds } from './seed.mjs';
import { protectExistingRecords } from './protect-existing-records.mjs';

const { Pool } = pg;
const here = path.dirname(fileURLToPath(import.meta.url));
const migrationDir = path.resolve(here, '../db/migrations');

export async function runMigrations(connectionString = process.env.DATABASE_URL) {
  if (!connectionString) {
    console.warn('[Migration] Skipped: DATABASE_URL is not set.');
    return;
  }
  const pool = new Pool({ connectionString });

  try {
    await pool.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
      name text PRIMARY KEY,
      applied_at timestamptz NOT NULL DEFAULT now()
    )`);

    const files = (await readdir(migrationDir)).filter((name) => name.endsWith('.sql')).sort();
    let appliedCount = 0;
    for (const name of files) {
      const { rowCount } = await pool.query('SELECT 1 FROM schema_migrations WHERE name = $1', [name]);
      if (rowCount) continue;

      const sql = await readFile(path.join(migrationDir, name), 'utf8');
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations(name) VALUES ($1)', [name]);
        await client.query('COMMIT');
        console.log(`[Migration] Applied new table/schema: ${name}`);
        appliedCount++;
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
    }
    if (appliedCount === 0) {
      console.log('[Migration] All tables are up to date.');
    }
  } finally {
    await pool.end();
  }

  // Existing imported/older local rows are encrypted before API startup.
  await protectExistingRecords(connectionString);

  // After migrations (new tables created), automatically run seeds!
  await runSeeds(connectionString);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await runMigrations();
}

