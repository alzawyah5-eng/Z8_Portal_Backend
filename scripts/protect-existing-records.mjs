import 'dotenv/config';
import pg from 'pg';
import {
  decryptSensitiveRecordFields,
  cardholderEmailLookupHash,
  encryptSensitiveRecordFields,
  ownerEmailLookupHash,
  parseRecordPiiKey,
  SENSITIVE_RECORD_FIELDS,
} from '../src/card-flow/record-pii-crypto.mjs';

const MARKER = 'data_protection_v2';

export async function protectExistingRecords(connectionString = process.env.DATABASE_URL) {
  if (!connectionString) throw new Error('DATABASE_URL must be configured.');
  const piiKey = parseRecordPiiKey(process.env.RECORD_PII_ENCRYPTION_KEY || '');
  const lookupKey = parseRecordPiiKey(process.env.RECORD_LOOKUP_HMAC_KEY || '');
  const pool = new pg.Pool({ connectionString, max: 1 });
  try {
    const marked = await pool.query('SELECT 1 FROM schema_migrations WHERE name = $1', [MARKER]);
    if (marked.rowCount) return;

    const entityTables = {
      AccountEntry: 'account_entries', Card: 'cards', Cardholder: 'cardholders',
      CardholderApplication: 'cardholder_applications', CardRequest: 'card_requests',
      CardTransaction: 'card_transactions', Notification: 'notifications',
      PhotonPayLog: 'photonpay_logs', ProgrammeSettings: 'programme_settings',
    };
    for (const [entity, table] of Object.entries(entityTables)) {
      const page = await pool.query(`SELECT id, data, owner_email_hash, cardholder_email_hash FROM ${table}`);
      if (!page.rowCount) continue;
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        for (const row of page.rows) {
          const data = row.data;
          const fields = SENSITIVE_RECORD_FIELDS[entity] ?? new Set();
          const clearValues = {};
          for (const field of fields) {
            if (typeof data[field] === 'string' && data[field] !== '') clearValues[field] = data[field];
          }
          const next = { ...data, ...encryptSensitiveRecordFields(entity, clearValues, piiKey) };
          const clearRecord = decryptSensitiveRecordFields(entity, next, piiKey);
          const ownerHash = ownerEmailLookupHash(
            typeof clearRecord.owner_email === 'string' ? clearRecord.owner_email : undefined,
            lookupKey,
          );
          const cardholderHash = entity === 'Cardholder'
            ? cardholderEmailLookupHash(typeof clearRecord.email === 'string' ? clearRecord.email : undefined, lookupKey)
            : null;
          if (JSON.stringify(next) !== JSON.stringify(data) || ownerHash !== row.owner_email_hash
            || cardholderHash !== row.cardholder_email_hash) {
            await client.query(
              `UPDATE ${table} SET data = $2::jsonb, owner_email_hash = $3,
                 cardholder_email_hash = $4, updated_at = now()
               WHERE id = $1`,
              [row.id, JSON.stringify(next), ownerHash, cardholderHash],
            );
          }
        }
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK').catch(() => undefined);
        throw error;
      } finally {
        client.release();
      }
    }
    await pool.query('INSERT INTO schema_migrations(name) VALUES ($1) ON CONFLICT DO NOTHING', [MARKER]);
  } finally {
    await pool.end();
  }
}

if (process.argv[1] && new URL(import.meta.url).pathname.toLowerCase().endsWith(process.argv[1].replaceAll('\\', '/').toLowerCase())) {
  await protectExistingRecords();
  console.log('Existing Card Flow records are encrypted and owner lookups are keyed.');
}
