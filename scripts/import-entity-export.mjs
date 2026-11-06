import 'dotenv/config';
import { cardholderEmailLookupHash, encryptSensitiveRecordFields, ownerEmailLookupHash, parseRecordPiiKey, SENSITIVE_RECORD_FIELDS } from '../src/card-flow/record-pii-crypto.mjs';
import { readFile } from 'node:fs/promises';
import pg from 'pg';

const allowedEntities = new Set([
  'AccountEntry', 'Card', 'Cardholder', 'CardholderApplication', 'CardRequest',
  'CardTransaction', 'Notification', 'PhotonPayLog', 'ProgrammeSettings',
  'User',
]);
const entityTables = {
  AccountEntry: 'account_entries', Card: 'cards', Cardholder: 'cardholders',
  CardholderApplication: 'cardholder_applications', CardRequest: 'card_requests',
  CardTransaction: 'card_transactions', Notification: 'notifications',
  PhotonPayLog: 'photonpay_logs', ProgrammeSettings: 'programme_settings',
};
// Keep this aligned with CardFlowEntitiesService's field allowlists. Imported
// Export JSON bypasses normal API sanitization, so unknown fields must never
// be copied into records that will later be returned by the API.
const entityFields = {
  AccountEntry: new Set('owner_email client_name kind status amount currency method reference note admin_note reported_by reported_amount recorded_by recorded_at card_id card_request_id proof_file_uri proof_type proof_name'.split(' ')),
  Card: new Set('nickname tier purpose purpose_detail masked_number last4 expiry currency scheme card_type form_factor status balance monthly_spend max_on_daily max_on_monthly max_on_percent transaction_limit_type cardholder_name cardholder_id photon_card_id photon_cardholder_id request_id bin notes owner_email funded_at auto_issued pending_topup_amount pending_topup_request_id available_transaction_limit'.split(' ')),
  Cardholder: new Set('full_name first_name last_name email phone date_of_birth nationality address_line city state postal_code country cert_type cert_id cert_country photon_cardholder_id status notes master_account_email provider_status review_status review_reason synced_at owner_email device_ip device_country auto_issue_status auto_issue_note photon_created_at is_legal id_info_requirement'.split(' ')),
  CardholderApplication: new Set('owner_email status first_name last_name date_of_birth nationality email mobile_prefix mobile address_line city state postal_code country cert_type cert_id cert_country front_file_uri back_file_uri submitted_at reviewed_by reviewed_at review_note last_error photon_cardholder_id cardholder_record_id device_ip device_country'.split(' ')),
  CardRequest: new Set('status owner_email cardholder_record_id photon_cardholder_id client_name amount approved_amount currency client_note tier purpose purpose_detail requested_at reviewed_by reviewed_at review_note last_error card_record_id provider_request_id'.split(' ')),
  CardTransaction: new Set('kind event card_id card_last4 card_nickname merchant amount currency status category occurred_at note photon_txn_id owner_email'.split(' ')),
  Notification: new Set('owner_email kind tone title body link read read_at dedupe_key'.split(' ')),
  PhotonPayLog: new Set('kind source environment method host path request_headers request_body started_at http_status provider_code response_headers response_body finished_at duration_ms error'.split(' ')),
  ProgrammeSettings: new Set('client_requests_enabled client_topups_enabled max_cards_per_client default_max_on_daily default_max_on_monthly default_max_on_percent tier_emerald_enabled tier_plum_enabled tier_crimson_enabled tier_start_amount tier_plum_from tier_crimson_from funding_instructions min_opening_amount'.split(' ')),
};
const FILE_URI = /^mp\/private\/([a-f0-9]{24})\/([A-Za-z0-9][A-Za-z0-9._-]{0,140}\.(?:jpe?g|png|pdf))$/i;
const args = process.argv.slice(2);
const apply = args.includes('--apply');
const fileMapFlag = args.indexOf('--file-map');
const fileMapPath = fileMapFlag >= 0 ? args[fileMapFlag + 1] : null;
const positional = args.filter((arg, index) => arg !== '--apply' && arg !== '--file-map' && (fileMapFlag < 0 || index !== fileMapFlag + 1));
const filename = positional[0];
if (!filename) {
  console.error('Usage: node scripts/import-entity-export.mjs <export.json> [--file-map <uri-map.json>] [--apply]');
  process.exit(2);
}
if (fileMapFlag >= 0 && (!fileMapPath || fileMapPath.startsWith('--'))) {
  throw new Error('--file-map requires a JSON map file.');
}
if (positional.length !== 1 || args.filter((arg) => arg === '--apply').length > 1 || fileMapFlag !== args.lastIndexOf('--file-map')) {
  throw new Error('Use one export path, optional --file-map <uri-map.json>, and optional --apply.');
}

const fileUriMap = new Map();
if (fileMapPath) {
  const rawMap = JSON.parse(await readFile(fileMapPath, 'utf8'));
  const map = rawMap.files ?? rawMap;
  if (!map || typeof map !== 'object' || Array.isArray(map)) throw new Error('File URI map must be a JSON object.');
  for (const [oldUri, newUri] of Object.entries(map)) {
    if (!oldUri.trim() || typeof newUri !== 'string' || !FILE_URI.test(newUri)) throw new Error('File URI map contains an invalid source or local private-file URI.');
    fileUriMap.set(oldUri, newUri);
  }
}

const parsed = JSON.parse(await readFile(filename, 'utf8'));
const entries = Array.isArray(parsed)
  ? parsed
  : Object.entries(parsed).map(([entity, records]) => ({ entity, records }));
const batches = new Map();
for (const entry of entries) {
  const entity = entry.entity ?? entry.name;
  if (!allowedEntities.has(entity)) continue;
  const records = entry.records ?? entry.items ?? entry.data ?? [];
  if (!Array.isArray(records)) throw new Error(`Expected an array for ${entity}.`);
  batches.set(entity, [...(batches.get(entity) ?? []), ...records]);
}
const counts = Object.fromEntries([...batches].map(([entity, rows]) => [entity, rows.length]));
const droppedFieldCounts = {};
function sanitizeRecord(entity, record) {
  const clean = {};
  const allowed = entityFields[entity];
  for (const [key, value] of Object.entries(record)) {
    if (key === 'id' || key === 'created_date' || key === 'updated_date' || key === 'created_by_id') continue;
    if (allowed.has(key)) clean[key] = value;
    else droppedFieldCounts[entity] = (droppedFieldCounts[entity] ?? 0) + 1;
  }
  return clean;
}
const importedEmails = new Set();
const configuredAdminEmail = String(process.env.ADMIN_SEED_EMAIL ?? '').trim().toLowerCase();
const userInvitations = (batches.get('User') ?? []).map((record, index) => {
  if (!record || typeof record !== 'object' || Array.isArray(record)) {
    throw new Error(`User record ${index + 1} is not a JSON object.`);
  }
  const email = String(record.email ?? '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    throw new Error(`User record ${index + 1} has no valid email; fix or remove it from the export before import.`);
  }
  if (importedEmails.has(email)) throw new Error(`User record ${index + 1} duplicates an email in the export.`);
  importedEmails.add(email);
  const sourceRole = record.role === undefined ? 'user' : record.role;
  if (sourceRole !== 'admin' && sourceRole !== 'user') throw new Error(`User record ${index + 1} has an unsupported role.`);
  const role = email === configuredAdminEmail ? 'admin' : sourceRole;
  const displayName = String(record.display_name ?? record.full_name ?? record.name ?? '').trim().slice(0, 200) || null;
  const createdById = String(record.created_by_id ?? '').trim() || null;
  if (createdById && createdById.length > 128) throw new Error(`User record ${index + 1} has an invalid creator ID.`);
  return { email, role, displayName, createdById };
});
const fileReferences = new Set();
const unresolvedFileReferences = new Set();
const normalizedBatches = new Map();
function rewriteFileUris(value) {
  if (Array.isArray(value)) return value.map(rewriteFileUris);
  if (!value || typeof value !== 'object') return value;
  const result = {};
  for (const [key, item] of Object.entries(value)) {
    if (/_file_uri$/i.test(key) && typeof item === 'string' && item.trim()) {
      const sourceUri = item.trim();
      fileReferences.add(sourceUri);
      if (FILE_URI.test(sourceUri)) result[key] = sourceUri;
      else if (fileUriMap.has(sourceUri)) result[key] = fileUriMap.get(sourceUri);
      else {
        unresolvedFileReferences.add(sourceUri);
        result[key] = item;
      }
    } else {
      result[key] = rewriteFileUris(item);
    }
  }
  return result;
}
for (const [entity, records] of batches) {
  if (entity === 'User') continue;
  const normalized = [];
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    if (!record || typeof record !== 'object' || Array.isArray(record)) throw new Error(`${entity} record ${index + 1} is not a JSON object.`);
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(String(record.id ?? ''))) throw new Error(`${entity} record ${index + 1} has an invalid or missing ID.`);
    normalized.push(rewriteFileUris(sanitizeRecord(entity, record)));
  }
  normalizedBatches.set(entity, normalized);
}
console.log(`${apply ? 'Importing' : 'Dry run'} entity export counts: ${JSON.stringify(counts)}`);
console.log(`Validated ${userInvitations.length} user invitations. User emails, display names, and roles become passwordless local invitations. Passwords, Firebase identities/tokens, and PhotonPay access tokens are deliberately excluded.`);
console.log(`Unsupported fields excluded by the local record allowlist: ${JSON.stringify(droppedFieldCounts)}.`);
console.log(`Private-file URIs found=${fileReferences.size}; unresolved=${unresolvedFileReferences.size}.`);
if (!apply) {
  console.log('Review the counts and records, then rerun with --apply. No database changes were made.');
  process.exit(0);
}
if (unresolvedFileReferences.size) {
  throw new Error('Cannot apply import: every private-file URI must be exported, re-encrypted, and mapped with --file-map first.');
}
if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL must be configured.');
let recordPiiKey;
let ownerLookupKey;
const hasSensitiveValues = [...normalizedBatches].some(([entity, records]) =>
  records.some((record) => [...(SENSITIVE_RECORD_FIELDS[entity] ?? [])].some((field) => typeof record[field] === 'string' && record[field] !== '')),
);
if (hasSensitiveValues) recordPiiKey = parseRecordPiiKey(process.env.RECORD_PII_ENCRYPTION_KEY || '');
if ([...normalizedBatches].some(([, records]) => records.some((record) => typeof record.owner_email === 'string' && record.owner_email.trim()))) {
  ownerLookupKey = parseRecordPiiKey(process.env.RECORD_LOOKUP_HMAC_KEY || '');
}

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 1 });
const client = await pool.connect();
try {
  await client.query('BEGIN');
  for (const [entity, records] of batches) {
    if (entity === 'User') {
      for (const invitation of userInvitations) {
        await client.query(
          `INSERT INTO app_users (email, email_verified, display_name, role, created_by_id)
           VALUES ($1, false, $2, $3, $4)
           ON CONFLICT (lower(email)) WHERE email IS NOT NULL
           DO UPDATE SET role = EXCLUDED.role,
             display_name = COALESCE(app_users.display_name, EXCLUDED.display_name),
             created_by_id = COALESCE(app_users.created_by_id, EXCLUDED.created_by_id),
             updated_at = now()`,
          [invitation.email, invitation.displayName, invitation.role, invitation.createdById],
        );
      }
      continue;
    }
    for (let recordIndex = 0; recordIndex < records.length; recordIndex += 1) {
      const record = records[recordIndex];
      const id = String(record.id ?? '');
      const createdById = String(record.created_by_id ?? '').trim() || null;
      if (createdById && createdById.length > 128) throw new Error(`${entity} record ${recordIndex + 1} has an invalid creator ID.`);
      const clearRecord = normalizedBatches.get(entity)[recordIndex];
      const ownerEmailHash = ownerEmailLookupHash(typeof clearRecord.owner_email === 'string' ? clearRecord.owner_email : undefined, ownerLookupKey);
      const cardholderEmailHash = entity === 'Cardholder'
        ? cardholderEmailLookupHash(typeof clearRecord.email === 'string' ? clearRecord.email : undefined, ownerLookupKey)
        : null;
      const data = encryptSensitiveRecordFields(entity, clearRecord, recordPiiKey);
      if (entity === 'PhotonPayLog') {
        // Provider logs can contain credentials, cardholder details, or
        // identity data in free-form request/response/error fields. Preserve
        // operational audit metadata only; never import those payloads.
        const safeFields = [
          'kind', 'source', 'environment', 'method', 'host', 'path',
          'started_at', 'http_status', 'provider_code', 'finished_at', 'duration_ms',
        ];
        const safeLog = Object.fromEntries(
          safeFields.filter((key) => data[key] !== undefined).map((key) => [key, data[key]]),
        );
        if (typeof safeLog.path === 'string') safeLog.path = safeLog.path.split('?')[0];
        Object.keys(data).forEach((key) => delete data[key]);
        Object.assign(data, safeLog);
      }
      const table = entityTables[entity];
      await client.query(
        `INSERT INTO ${table} (id, data, created_at, updated_at, owner_email_hash, cardholder_email_hash, created_by_id)
         VALUES ($1, $2::jsonb, COALESCE($3::timestamptz, now()), COALESCE($4::timestamptz, now()), $5, $6, $7)
         ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data,
           owner_email_hash = EXCLUDED.owner_email_hash,
           cardholder_email_hash = EXCLUDED.cardholder_email_hash,
           created_by_id = COALESCE(${table}.created_by_id, EXCLUDED.created_by_id), updated_at = now()`,
        [id, JSON.stringify(data), record.created_date ?? null, record.updated_date ?? null, ownerEmailHash, cardholderEmailHash, createdById],
      );
    }
  }
  await client.query('COMMIT');
  console.log('Import committed. The import is an idempotent merge: records absent from the export are left unchanged.');
} catch (error) {
  await client.query('ROLLBACK');
  throw error;
} finally {
  client.release();
  await pool.end();
}

