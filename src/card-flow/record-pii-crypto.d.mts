export const SENSITIVE_RECORD_FIELDS: Record<string, Set<string>>;
export function parseRecordPiiKey(encoded: string): Buffer;
export function ownerEmailLookupHash(email: string | undefined, key: Buffer): string | null;
export function cardholderEmailLookupHash(email: string | undefined, key: Buffer): string | null;
export function encryptSensitiveRecordFields(entity: string, data: Record<string, unknown>, key: Buffer): Record<string, unknown>;
export function decryptSensitiveRecordFields(entity: string, data: Record<string, unknown>, key: Buffer): Record<string, unknown>;
