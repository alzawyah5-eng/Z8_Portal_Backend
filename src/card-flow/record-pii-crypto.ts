import { BadRequestException, ServiceUnavailableException } from '@nestjs/common';
import { cardholderEmailLookupHash as cardholderHashShared, decryptSensitiveRecordFields as decryptShared, encryptSensitiveRecordFields as encryptShared, ownerEmailLookupHash as ownerHashShared, parseRecordPiiKey as parseShared, SENSITIVE_RECORD_FIELDS } from './record-pii-crypto.mjs';

export { SENSITIVE_RECORD_FIELDS };

export function parseRecordPiiKey(encoded: string): Buffer {
  try { return parseShared(encoded); }
  catch { throw new ServiceUnavailableException('Sensitive record encryption is not configured.'); }
}

export function ownerEmailLookupHash(email: string | undefined, key: Buffer): string | null {
  return ownerHashShared(email, key);
}

export function cardholderEmailLookupHash(email: string | undefined, key: Buffer): string | null {
  return cardholderHashShared(email, key);
}

export function encryptSensitiveRecordFields(entity: string, data: Record<string, unknown>, key: Buffer): Record<string, unknown> {
  try { return encryptShared(entity, data, key); }
  catch { throw new BadRequestException({ code: 'invalid_entity_data' }); }
}

export function decryptSensitiveRecordFields(entity: string, data: Record<string, unknown>, key: Buffer): Record<string, unknown> {
  try { return decryptShared(entity, data, key); }
  catch { throw new ServiceUnavailableException('A protected cardholder record could not be decrypted. Check the stable RECORD_PII_ENCRYPTION_KEY configuration.'); }
}
