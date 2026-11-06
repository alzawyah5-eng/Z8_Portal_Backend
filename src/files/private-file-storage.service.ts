import { BadRequestException, Injectable, ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createCipheriv, createDecipheriv, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname, resolve, sep } from 'node:path';

const FILE_URI = /^mp\/private\/([a-f0-9]{24})\/([A-Za-z0-9][A-Za-z0-9._-]{0,140}\.(?:jpe?g|png|pdf))$/i;
const MAX_FILE_SIZE = 10 * 1024 * 1024;
const FORMAT = Buffer.from('Z8F1');

@Injectable()
export class PrivateFileStorageService {
  constructor(private readonly config: ConfigService) {}

  async uploadPrivateFile(file: File): Promise<{ file_uri: string }> {
    if (!(file instanceof File) || file.size < 1 || file.size > MAX_FILE_SIZE) {
      throw new BadRequestException({ code: 'invalid_file_size', message: 'The file must be smaller than 10 MB.' });
    }
    const bytes = Buffer.from(await file.arrayBuffer());
    const detected = this.detectType(bytes);
    if (!detected) throw new BadRequestException({ code: 'invalid_file_type', message: 'Upload a JPG, PNG, or PDF file.' });
    const id = randomBytes(12).toString('hex');
    const extension = detected === 'image/jpeg' ? 'jpg' : detected === 'image/png' ? 'png' : 'pdf';
    const baseName = file.name.replace(/[^A-Za-z0-9._-]/g, '_').slice(0, 120).replace(/\.[^.]*$/, '');
    const name = `${baseName || 'upload'}.${extension}`;
    const uri = `mp/private/${id}/${name}`;
    const target = this.filePath(id, name);
    const temporary = `${target}.${randomBytes(8).toString('hex')}.tmp`;
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.encryptionKey(), iv);
    const encrypted = Buffer.concat([cipher.update(bytes), cipher.final()]);
    const output = Buffer.concat([FORMAT, iv, cipher.getAuthTag(), encrypted]);
    await mkdir(dirname(target), { recursive: true, mode: 0o700 });
    await writeFile(temporary, output, { flag: 'wx', mode: 0o600 });
    await rename(temporary, target);
    return { file_uri: uri };
  }

  createSignedUrl(fileUri: string, expiresInSeconds: number): { signed_url: string } {
    const match = FILE_URI.exec(fileUri);
    if (!match) throw new BadRequestException({ code: 'invalid_private_file' });
    const expires = Math.floor(Date.now() / 1000) + Math.max(30, Math.min(600, Math.floor(expiresInSeconds)));
    const signature = this.sign(`${fileUri}|${expires}`);
    const base = this.config.get<string>('API_PUBLIC_URL', '').trim().replace(/\/+$/, '') || `http://127.0.0.1:${this.config.get<string>('PORT', '3001')}/v1`;
    return { signed_url: `${base}/files/private/${match[1]}/${encodeURIComponent(match[2])}?expires=${expires}&signature=${signature}` };
  }

  async readSigned(fileId: string, fileName: string, expires: string, signature: string) {
    const uri = `mp/private/${fileId}/${fileName}`;
    const expiresAt = Number(expires);
    if (!FILE_URI.test(uri) || !Number.isInteger(expiresAt) || expiresAt < Math.floor(Date.now() / 1000) || expiresAt > Math.floor(Date.now() / 1000) + 600) {
      throw new BadRequestException({ code: 'private_file_link_expired' });
    }
    const expected = Buffer.from(this.sign(`${uri}|${expiresAt}`));
    const supplied = Buffer.from(String(signature || ''));
    if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) {
      throw new BadRequestException({ code: 'private_file_link_invalid' });
    }
    let stored: Buffer;
    try { stored = await readFile(this.filePath(fileId, fileName)); }
    catch { throw new BadRequestException({ code: 'private_file_not_found' }); }
    if (stored.length < 32 || !stored.subarray(0, 4).equals(FORMAT)) throw new ServiceUnavailableException('The private file could not be decrypted.');
    const decipher = createDecipheriv('aes-256-gcm', this.encryptionKey(), stored.subarray(4, 16));
    decipher.setAuthTag(stored.subarray(16, 32));
    const bytes = Buffer.concat([decipher.update(stored.subarray(32)), decipher.final()]);
    return { bytes, contentType: this.detectType(bytes) || 'application/octet-stream' };
  }

  private filePath(id: string, name: string): string {
    if (!/^[a-f0-9]{24}$/i.test(id) || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,140}\.(?:jpe?g|png|pdf)$/i.test(name)) {
      throw new BadRequestException({ code: 'invalid_private_file' });
    }
    const root = resolve(this.config.get<string>('PRIVATE_FILES_PATH', './storage/private'));
    const target = resolve(root, id, name);
    if (!target.startsWith(`${root}${sep}`)) throw new BadRequestException({ code: 'invalid_private_file' });
    return target;
  }

  private encryptionKey(): Buffer {
    const value = this.config.get<string>('PRIVATE_FILE_ENCRYPTION_KEY', '').trim();
    const key = Buffer.from(value, 'base64');
    if (key.length !== 32) throw new ServiceUnavailableException('Private file encryption is not configured.');
    return key;
  }

  private sign(value: string): string {
    const secret = this.config.get<string>('PRIVATE_FILE_SIGNING_KEY', '').trim();
    if (Buffer.byteLength(secret) < 32) throw new ServiceUnavailableException('Private file links are not configured.');
    return createHmac('sha256', secret).update(value).digest('base64url');
  }

  private detectType(bytes: Buffer): string {
    if (bytes[0] === 0xff && bytes[1] === 0xd8) return 'image/jpeg';
    if (bytes.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return 'image/png';
    if (bytes.subarray(0, 5).toString('ascii') === '%PDF-') return 'application/pdf';
    return '';
  }
}
