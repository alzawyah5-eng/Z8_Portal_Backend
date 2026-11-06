import 'dotenv/config';
import pg from 'pg';
import { cardholderEmailLookupHash, decryptSensitiveRecordFields, ownerEmailLookupHash, parseRecordPiiKey, SENSITIVE_RECORD_FIELDS } from '../src/card-flow/record-pii-crypto.mjs';

if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL must be configured.');
const piiKey = parseRecordPiiKey(process.env.RECORD_PII_ENCRYPTION_KEY || '');
const lookupKey = parseRecordPiiKey(process.env.RECORD_LOOKUP_HMAC_KEY || '');
const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 1 });
try {
  const migrations = await pool.query('SELECT name FROM schema_migrations ORDER BY name');
  const users = await pool.query(
    `SELECT role, count(*)::int AS count,
       count(*) FILTER (WHERE role = 'admin' AND password_hash LIKE '$argon2id$%')::int AS argon2_admins
     FROM app_users WHERE deleted_at IS NULL GROUP BY role ORDER BY role`,
  );
  const recordCounts = new Map();
  const plaintextPii = [];
  const invalidOwnerHashes = [];
  let cardFlowRecordCount = 0;
  const entityTables = {
    AccountEntry: 'account_entries', Card: 'cards', Cardholder: 'cardholders',
    CardholderApplication: 'cardholder_applications', CardRequest: 'card_requests',
    CardTransaction: 'card_transactions', Notification: 'notifications',
    PhotonPayLog: 'photonpay_logs', ProgrammeSettings: 'programme_settings',
  };
  for (const [entity, table] of Object.entries(entityTables)) {
    const page = await pool.query(`SELECT id, data, owner_email_hash, cardholder_email_hash FROM ${table}`);
    for (const row of page.rows) {
      cardFlowRecordCount++;
      recordCounts.set(entity, (recordCounts.get(entity) ?? 0) + 1);
      for (const field of SENSITIVE_RECORD_FIELDS[entity] ?? []) {
        const value = row.data[field];
        if (value !== undefined && value !== null && value !== ''
          && (typeof value !== 'object' || Array.isArray(value)
            || value.__z8_encrypted_field !== 'aes-256-gcm:v1' || typeof value.data !== 'string')) {
          plaintextPii.push(entity + '.' + field + ':invalid-envelope');
        }
      }
      const clear = decryptSensitiveRecordFields(entity, row.data, piiKey);
      const expectedOwnerHash = ownerEmailLookupHash(
        typeof clear.owner_email === 'string' ? clear.owner_email : undefined,
        lookupKey,
      );
      if (expectedOwnerHash !== row.owner_email_hash) invalidOwnerHashes.push(entity + ':owner-hash');
      const expectedCardholderHash = entity === 'Cardholder'
        ? cardholderEmailLookupHash(typeof clear.email === 'string' ? clear.email : undefined, lookupKey)
        : null;
      if (expectedCardholderHash !== row.cardholder_email_hash) invalidOwnerHashes.push(entity + ':cardholder-email-hash');
    }
  }
  const schema = await pool.query(
    `SELECT EXISTS (SELECT 1 FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name = 'app_users' AND column_name = 'password') AS plaintext_password_column`,
  );
  const adminCount = users.rows.reduce((count, row) => count + Number(row.argon2_admins), 0);
  const result = {
    databaseConnected: true,
    migrationCount: migrations.rowCount,
    migrations: migrations.rows.map((row) => row.name),
    users: users.rows.map(({ role, count }) => ({ role, count })),
    argon2AdminCount: adminCount,
    cardFlowRecords: Object.fromEntries(recordCounts),
    cardFlowRecordCount,
    plaintextPasswordColumn: schema.rows[0].plaintext_password_column,
    recordPiiEncryptionKeyBytes: piiKey.length,
    recordLookupHmacKeyBytes: lookupKey.length,
    unencryptedSensitiveFields: [...new Set(plaintextPii)],
    invalidOwnerEmailHashes: [...new Set(invalidOwnerHashes)],
  };
  console.log(JSON.stringify(result, null, 2));
  if (result.plaintextPasswordColumn || result.argon2AdminCount < 1 || plaintextPii.length || invalidOwnerHashes.length) process.exitCode = 1;
} finally {
  await pool.end();
}
