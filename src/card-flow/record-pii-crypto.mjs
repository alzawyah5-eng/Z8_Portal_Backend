import { createCipheriv, createDecipheriv, createHmac, randomBytes } from 'node:crypto';

export const SENSITIVE_RECORD_FIELDS = {
  AccountEntry: new Set(['owner_email', 'client_name', 'reported_by', 'recorded_by']),
  Card: new Set(['owner_email', 'cardholder_name']),
  Cardholder: new Set(['owner_email', 'full_name', 'first_name', 'last_name', 'email', 'phone', 'date_of_birth', 'nationality', 'address_line', 'city', 'state', 'postal_code', 'country', 'cert_type', 'cert_id', 'cert_country', 'notes', 'master_account_email', 'review_reason', 'device_ip', 'device_country', 'auto_issue_note']),
  CardholderApplication: new Set(['owner_email', 'first_name', 'last_name', 'date_of_birth', 'nationality', 'email', 'mobile_prefix', 'mobile', 'address_line', 'city', 'state', 'postal_code', 'country', 'cert_type', 'cert_id', 'cert_country', 'reviewed_by', 'review_note', 'last_error', 'device_ip', 'device_country']),
  CardRequest: new Set(['owner_email', 'client_name', 'client_note', 'reviewed_by', 'review_note', 'last_error']),
  CardTransaction: new Set(['owner_email', 'merchant', 'note']),
  Notification: new Set(['owner_email', 'title', 'body']),
};

export function parseRecordPiiKey(encoded) {
  const value = String(encoded ?? '').trim();
  const key = Buffer.from(value, 'base64');
  if (key.length !== 32 || key.toString('base64') !== value) {
    throw new Error('RECORD_PII_ENCRYPTION_KEY must be a valid base64-encoded 32-byte key.');
  }
  return key;
}

export function ownerEmailLookupHash(email, key) {
  const normalizedEmail = String(email ?? '').trim().toLowerCase();
  if (!normalizedEmail) return null;
  return createHmac('sha256', key).update(`z8-owner-email:v1:${normalizedEmail}`).digest('hex');
}

export function cardholderEmailLookupHash(email, key) {
  const normalizedEmail = String(email ?? '').trim().toLowerCase();
  if (!normalizedEmail) return null;
  return createHmac('sha256', key).update(`z8-cardholder-email:v1:${normalizedEmail}`).digest('hex');
}

export function encryptSensitiveRecordFields(entity, data, key) {
  const fields = SENSITIVE_RECORD_FIELDS[entity];
  if (!fields) return data;
  const output = { ...data };
  for (const field of fields) {
    const value = output[field];
    if (value === undefined || value === null || value === '') continue;
    if (typeof value !== 'string') throw new Error(`${entity} contains an invalid value for a protected field.`);
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(Buffer.from(`z8-card-flow:${entity}:${field}:v1`));
    const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
    output[field] = {
      __z8_encrypted_field: 'aes-256-gcm:v1',
      data: Buffer.concat([iv, cipher.getAuthTag(), ciphertext]).toString('base64'),
    };
  }
  return output;
}

export function decryptSensitiveRecordFields(entity, data, key) {
  const fields = SENSITIVE_RECORD_FIELDS[entity];
  if (!fields) return data;
  const output = { ...data };
  for (const field of fields) {
    const value = output[field];
    if (value === undefined || value === null || value === '') continue;
    if (typeof value !== 'object' || Array.isArray(value)
      || value.__z8_encrypted_field !== 'aes-256-gcm:v1' || typeof value.data !== 'string') {
      throw new Error('A protected cardholder record has an invalid encrypted value.');
    }
    const payload = Buffer.from(value.data, 'base64');
    if (payload.length < 28) throw new Error('A protected cardholder record could not be decrypted.');
    const decipher = createDecipheriv('aes-256-gcm', key, payload.subarray(0, 12));
    decipher.setAAD(Buffer.from(`z8-card-flow:${entity}:${field}:v1`));
    decipher.setAuthTag(payload.subarray(12, 28));
    output[field] = Buffer.concat([decipher.update(payload.subarray(28)), decipher.final()]).toString('utf8');
  }
  return output;
}
