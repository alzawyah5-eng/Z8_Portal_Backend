import { BadRequestException, Injectable, ServiceUnavailableException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Inject } from '@nestjs/common';
import { createCipheriv, createDecipheriv, createSign, createPrivateKey, randomBytes, KeyObject } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { Pool } from 'pg';

type PhotonPayEnvironment = 'sandbox' | 'prod';
type PhotonPayJson = Record<string, any>;

const API_HOSTS: Record<PhotonPayEnvironment, string> = {
  sandbox: 'https://x-api.sandbox.photontech.cc',
  prod: 'https://x-api.photonpay.com',
};
const ALLOWED_RELAY_TARGETS = new Set(Object.values(API_HOSTS).map((host) => new URL(host).hostname));
const TOKEN_REFRESH_MARGIN_MS = 5 * 60 * 1000;

@Injectable()
export class PhotonPayService {
  constructor(
    private readonly config: ConfigService,
    @Inject('PG_POOL') private readonly db: Pool,
  ) {}

  private get appId(): string {
    return this.config.get<string>('PHOTONPAY_APP_ID', '').trim();
  }

  private get appSecret(): string {
    return this.config.get<string>('PHOTONPAY_APP_SECRET', '').trim();
  }

  private get environment(): PhotonPayEnvironment {
    const value = this.config.get<string>('PHOTONPAY_ENV', 'sandbox').trim().toLowerCase();
    if (value === 'production' || value === 'live') return 'prod';
    if (value === 'sandbox' || value === 'prod') return value;
    throw new ServiceUnavailableException('PHOTONPAY_ENV must be sandbox or prod.');
  }

  private get relay(): { url: string; secret: string } | null {
    const rawUrl = this.config.get<string>('PHOTONPAY_RELAY_URL', '').trim().replace(/\/+$/, '');
    const secret = this.config.get<string>('PHOTONPAY_RELAY_SECRET', '').trim();
    if (!rawUrl && !secret) return null;
    try {
      const url = new URL(rawUrl);
      if (url.protocol !== 'https:' || url.pathname !== '/' || url.search || url.hash || !secret) {
        throw new Error();
      }
      return { url: rawUrl, secret };
    } catch {
      throw new ServiceUnavailableException('PhotonPay relay configuration is incomplete or invalid.');
    }
  }

  private get signingKeyPem(): string {
    const inline = this.config.get<string>('PHOTONPAY_RSA_PRIVATE_KEY', '').trim();
    if (inline) return inline.replace(/\\n/g, '\n');
    const configuredPath = this.config.get<string>('PHOTONPAY_RSA_PRIVATE_KEY_PATH', '').trim();
    if (!configuredPath) return '';
    try {
      const absolutePath = path.isAbsolute(configuredPath)
        ? configuredPath
        : path.resolve(process.cwd(), configuredPath);
      return readFileSync(absolutePath, 'utf8').trim();
    } catch {
      return '';
    }
  }

  private assertConfigured(): void {
    if (!this.appId || !this.appSecret) {
      throw new ServiceUnavailableException('PhotonPay App ID and App Secret are not configured.');
    }
  }

  private tokenEncryptionKey(): Buffer {
    const raw = this.config.get<string>('PHOTONPAY_TOKEN_ENCRYPTION_KEY', '').trim();
    const key = Buffer.from(raw, 'base64');
    if (!raw || key.length !== 32) {
      throw new ServiceUnavailableException('PHOTONPAY_TOKEN_ENCRYPTION_KEY must be a base64-encoded 32-byte key.');
    }
    return key;
  }

  private encryptToken(token: string): { ciphertext: Buffer; iv: Buffer; tag: Buffer } {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.tokenEncryptionKey(), iv);
    const ciphertext = Buffer.concat([cipher.update(token, 'utf8'), cipher.final()]);
    return { ciphertext, iv, tag: cipher.getAuthTag() };
  }

  private decryptToken(ciphertext: Buffer, iv: Buffer, tag: Buffer): string {
    try {
      const decipher = createDecipheriv('aes-256-gcm', this.tokenEncryptionKey(), iv);
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString('utf8');
    } catch {
      throw new ServiceUnavailableException('The saved PhotonPay token cannot be decrypted; check the token encryption key.');
    }
  }

  async connectionStatus(): Promise<Record<string, unknown>> {
    this.assertConfigured();
    const env = this.environment;
    await this.getAccessToken(env);
    return {
      configured: true,
      connected: true,
      environment: env,
      master_account_email: this.config.get<string>('PHOTONPAY_MASTER_ACCOUNT_EMAIL', '').trim().toLowerCase(),
      signing_key_configured: Boolean(this.signingKeyPem),
      webhook_key_configured: Boolean(this.config.get<string>('PHOTONPAY_PUBLIC_KEY', '').trim()),
      relay_configured: Boolean(this.relay),
    };
  }

  async getUsdBalance(): Promise<Record<string, unknown>> {
    const response = await this.request('/wallet/openApi/v4/account/single', {
      query: { currency: 'USD', accountType: 'FT10001' },
    });
    const account = response.data ?? {};
    return {
      currency: 'USD',
      account: String(account.accountNo ?? '').slice(0, 64),
      available: Number(account.realTimeBalance ?? 0),
      as_of: String(account.returnedAt ?? '').slice(0, 40),
      environment: this.environment,
    };
  }

  async listVirtualCards(options: {
    pageIndex?: number;
    pageSize?: number;
    status?: string;
    nickname?: string;
  }): Promise<Record<string, unknown>> {
    const pageIndex = options.pageIndex ?? 1;
    const pageSize = options.pageSize ?? 20;
    if (!Number.isInteger(pageIndex) || pageIndex < 1 || !Number.isInteger(pageSize) || pageSize < 1 || pageSize > 100) {
      throw new BadRequestException('Card pageIndex must be positive and pageSize must be between 1 and 100.');
    }
    const response = await this.request('/vcc/openApi/v4/pagingVccCard', {
      query: {
        cardFormFactor: 'virtual_card',
        pageIndex,
        pageSize,
        cardStatus: options.status?.trim().slice(0, 30),
        nickname: options.nickname?.trim().slice(0, 50),
      },
    });
    const data = response.data ?? {};
    const candidate: unknown = Array.isArray(data) ? data : data.list ?? data.rows ?? [];
    if (!Array.isArray(candidate)) throw new ServiceUnavailableException('PhotonPay returned an invalid card list response.');
    const rows: unknown[] = candidate;
    return {
      total: Number(data.total ?? rows.length),
      cards: rows.map((value) => {
        if (!value || typeof value !== 'object' || Array.isArray(value)) {
          throw new ServiceUnavailableException('PhotonPay returned an invalid card record.');
        }
        return this.maskCard(value as PhotonPayJson);
      }),
    };
  }

  private maskCard(card: PhotonPayJson): Record<string, unknown> {
    const digits = String(card.cardNo ?? '').replace(/\D/g, '');
    return {
      photon_card_id: String(card.cardId ?? '').slice(0, 80),
      last4: digits.slice(-4),
      masked_number: digits.length >= 10 ? `•••• •••• •••• ${digits.slice(-4)}` : '',
      nickname: String(card.nickname ?? '').slice(0, 100),
      currency: String(card.cardCurrency ?? '').slice(0, 3),
      status: String(card.cardStatus ?? '').slice(0, 30),
      card_type: String(card.cardType ?? '').slice(0, 30),
      form_factor: String(card.cardFormFactor ?? '').slice(0, 30),
      balance: Number.isFinite(Number(card.cardBalance)) ? Number(card.cardBalance) : null,
    };
  }

  private async request(
    path: string,
    options: { method?: 'GET' | 'POST'; query?: Record<string, string | number | undefined>; body?: PhotonPayJson } = {},
  ): Promise<PhotonPayJson> {
    this.assertConfigured();
    const env = this.environment;
    const method = options.method ?? 'GET';
    const token = await this.getAccessToken(env);
    const url = new URL(path, API_HOSTS[env]);
    if (url.origin !== API_HOSTS[env]) throw new ServiceUnavailableException('Invalid PhotonPay API path.');
    for (const [key, value] of Object.entries(options.query ?? {})) {
      if (value !== undefined && value !== '') url.searchParams.set(key, String(value));
    }

    const headers: Record<string, string> = { 'content-type': 'application/json', 'X-PD-TOKEN': token };
    const body = method === 'POST' && options.body ? JSON.stringify(options.body) : undefined;
    if (body !== undefined) headers['X-PD-SIGN'] = this.signBody(body);
    let response = await this.fetchProvider(url, { method, headers, body, signal: AbortSignal.timeout(20_000) });
    let json = await this.readJson(response);

    if (this.isRejectedToken(json)) {
      const retryToken = await this.getAccessToken(env, token);
      headers['X-PD-TOKEN'] = retryToken;
      response = await this.fetchProvider(url, { method, headers, body, signal: AbortSignal.timeout(20_000) });
      json = await this.readJson(response);
    }

    if (!response.ok || (json.code && json.code !== '0000')) {
      const message = String(json.msg ?? `PhotonPay request failed (HTTP ${response.status})`).slice(0, 400);
      throw new ServiceUnavailableException({
        message,
        provider_code: String(json.code ?? '').slice(0, 40),
        http_status: response.status,
      });
    }
    return json;
  }

  private async getAccessToken(env: PhotonPayEnvironment, rejectedToken = ''): Promise<string> {
    this.assertConfigured();
    const key = `${env}:${this.appId}`;
    const client = await this.db.connect();
    try {
      await client.query('BEGIN');
      await client.query('SELECT pg_advisory_xact_lock(hashtext($1))', [key]);
      const current = await client.query<{
        access_token_ciphertext: Buffer;
        access_token_iv: Buffer;
        access_token_tag: Buffer;
        expires_at: Date;
      }>(
        'SELECT access_token_ciphertext, access_token_iv, access_token_tag, expires_at FROM photonpay_tokens WHERE token_key = $1 FOR UPDATE',
        [key],
      );
      const saved = current.rows[0];
      let savedToken = '';
      if (saved) {
        try {
          savedToken = this.decryptToken(saved.access_token_ciphertext, saved.access_token_iv, saved.access_token_tag);
        } catch {
          // If the encryption key was rotated, discard the cached token and
          // replace it with a fresh one rather than blocking future requests.
        }
      }
      if (saved && savedToken !== rejectedToken && saved.expires_at.getTime() > Date.now() + TOKEN_REFRESH_MARGIN_MS) {
        await client.query('COMMIT');
        return savedToken;
      }

      const host = API_HOSTS[env];
      const auth = Buffer.from(`${this.appId}/${this.appSecret}`, 'utf8').toString('base64');
      const response = await this.fetchProvider(new URL('/oauth2/token/accessToken', host), {
        method: 'POST',
        headers: { 'content-type': 'application/json', Authorization: `basic ${auth}` },
        signal: AbortSignal.timeout(15_000),
      });
      const json = await this.readJson(response);
      const token = String(json.data?.token ?? '');
      if (!response.ok || !token) {
        throw new ServiceUnavailableException({
          message: String(json.msg ?? `PhotonPay authentication failed (HTTP ${response.status})`).slice(0, 400),
          provider_code: String(json.code ?? '').slice(0, 40),
          http_status: response.status,
        });
      }
      const expiryValue = Number(json.data?.expiresIn);
      const expiresAt = expiryValue > 1e12
        ? new Date(expiryValue)
        : expiryValue > 1e9
          ? new Date(expiryValue * 1000)
          : new Date(Date.now() + (expiryValue > 0 ? expiryValue : 7200) * 1000);
      const encrypted = this.encryptToken(token);
      await client.query(
        `INSERT INTO photonpay_tokens
           (token_key, environment, app_id, access_token_ciphertext, access_token_iv, access_token_tag, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (token_key) DO UPDATE SET
           environment = EXCLUDED.environment,
           app_id = EXCLUDED.app_id,
           access_token_ciphertext = EXCLUDED.access_token_ciphertext,
           access_token_iv = EXCLUDED.access_token_iv,
           access_token_tag = EXCLUDED.access_token_tag,
           expires_at = EXCLUDED.expires_at,
           updated_at = now()`,
        [key, env, this.appId, encrypted.ciphertext, encrypted.iv, encrypted.tag, expiresAt],
      );
      await client.query('COMMIT');
      return token;
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  private signBody(body: string): string {
    const pem = this.signingKeyPem;
    if (!pem) throw new ServiceUnavailableException('PHOTONPAY_RSA_PRIVATE_KEY is required for PhotonPay write requests.');
    let key: KeyObject;
    try {
      key = createPrivateKey(pem);
    } catch {
      throw new ServiceUnavailableException('PHOTONPAY_RSA_PRIVATE_KEY is not a readable PEM private key.');
    }
    if (key.asymmetricKeyType !== 'rsa') {
      throw new ServiceUnavailableException('PhotonPay requires an RSA signing key.');
    }
    // PhotonPay's current Open API signing contract specifies MD5withRSA.
    const signer = createSign('RSA-MD5');
    signer.update(body, 'utf8');
    signer.end();
    return signer.sign(key, 'base64');
  }

  private isRejectedToken(json: PhotonPayJson): boolean {
    const code = String(json.code ?? '0000');
    return code !== '0000' && (code === '1002' || /token/i.test(String(json.msg ?? '')));
  }

  private async readJson(response: Response): Promise<PhotonPayJson> {
    try {
      const value: unknown = await response.json();
      return value && typeof value === 'object' ? value as PhotonPayJson : {};
    } catch {
      return {};
    }
  }

  private async fetchProvider(url: URL, init: RequestInit): Promise<Response> {
    const relay = this.relay;
    if (!relay) return fetch(url, init);
    if (!ALLOWED_RELAY_TARGETS.has(url.hostname)) {
      throw new ServiceUnavailableException('The PhotonPay relay only permits approved PhotonPay hosts.');
    }
    const body = typeof init.body === 'string' ? init.body : null;
    const response = await fetch(`${relay.url}/forward`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-relay-secret': relay.secret },
      body: JSON.stringify({ url: url.toString(), method: init.method ?? 'GET', headers: init.headers ?? {}, body }),
      signal: AbortSignal.timeout(30_000),
    });
    const forwarded = await response.json().catch(() => null) as {
      status?: number;
      body?: string;
      headers?: Record<string, string>;
      error?: string;
    } | null;
    if (!response.ok || !forwarded) {
      throw new ServiceUnavailableException(String(forwarded?.error ?? 'PhotonPay relay request failed').slice(0, 300));
    }
    const status = Number(forwarded.status);
    return new Response(forwarded.body ?? null, {
      status: status >= 200 && status <= 599 ? status : 502,
      headers: forwarded.headers ?? {},
    });
  }
}
