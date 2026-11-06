import { BadRequestException, ForbiddenException, Injectable, NotFoundException, Inject, ServiceUnavailableException } from '@nestjs/common';
import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'node:crypto';
import { Pool } from 'pg';
import { ConfigService } from '@nestjs/config';
import { NotificationsService } from '../notifications/notifications.service';
import { FirebasePrincipal } from '../auth/firebase-principal';
import { cardholderEmailLookupHash, decryptSensitiveRecordFields, encryptSensitiveRecordFields, ownerEmailLookupHash, parseRecordPiiKey, SENSITIVE_RECORD_FIELDS } from './record-pii-crypto';
import { redactBody, redactHeaders } from './legacy/photonpay';

const ENTITY_NAMES = new Set([
  'AccountEntry', 'Card', 'Cardholder', 'CardholderApplication', 'CardRequest',
  'CardTransaction', 'Notification', 'PhotonPayLog', 'ProgrammeSettings', 'User',
]);
const ENTITY_TABLES: Record<string, string> = {
  AccountEntry: 'account_entries', Card: 'cards', Cardholder: 'cardholders',
  CardholderApplication: 'cardholder_applications', CardRequest: 'card_requests',
  CardTransaction: 'card_transactions', Notification: 'notifications',
  PhotonPayLog: 'photonpay_logs', ProgrammeSettings: 'programme_settings',
};
const ENTITY_FIELDS: Record<string, Set<string>> = {
  AccountEntry: new Set('owner_email client_name kind status amount currency method reference note admin_note reported_by reported_amount recorded_by recorded_at card_id card_request_id proof_file_uri proof_type proof_name'.split(' ')),
  Card: new Set('nickname tier purpose purpose_detail masked_number last4 expiry currency scheme card_type form_factor status balance monthly_spend max_on_daily max_on_monthly max_on_percent transaction_limit_type cardholder_name cardholder_id photon_card_id photon_cardholder_id request_id bin notes owner_email funded_at auto_issued pending_topup_amount pending_topup_request_id available_transaction_limit'.split(' ')),
  Cardholder: new Set('full_name first_name last_name email phone date_of_birth nationality address_line city state postal_code country cert_type cert_id cert_country photon_cardholder_id status notes master_account_email provider_status review_status review_reason synced_at owner_email device_ip device_country auto_issue_status auto_issue_note photon_created_at is_legal id_info_requirement'.split(' ')),
  CardholderApplication: new Set('owner_email status first_name last_name date_of_birth nationality email mobile_prefix mobile address_line city state postal_code country cert_type cert_id cert_country front_file_uri back_file_uri submitted_at reviewed_by reviewed_at review_note last_error photon_cardholder_id cardholder_record_id device_ip device_country'.split(' ')),
  CardRequest: new Set('status owner_email cardholder_record_id photon_cardholder_id client_name amount approved_amount currency client_note tier purpose purpose_detail requested_at reviewed_by reviewed_at review_note last_error card_record_id provider_request_id'.split(' ')),
  CardTransaction: new Set('kind event card_id card_last4 card_nickname merchant amount currency status category occurred_at note photon_txn_id owner_email'.split(' ')),
  Notification: new Set('owner_email kind tone title body link read read_at dedupe_key'.split(' ')),
  PhotonPayLog: new Set('kind source environment method host path request_headers request_body started_at http_status provider_code response_headers response_body finished_at duration_ms error'.split(' ')),
  ProgrammeSettings: new Set('client_requests_enabled client_topups_enabled max_cards_per_client default_max_on_daily default_max_on_monthly default_max_on_percent tier_emerald_enabled tier_plum_enabled tier_crimson_enabled tier_start_amount tier_plum_from tier_crimson_from funding_instructions min_opening_amount'.split(' ')),
  User: new Set(['email', 'display_name', 'role']),
};
const SAFE_ID = /^[A-Za-z0-9_-]{1,128}$/;

type EntityOptions = { sort?: string; limit?: number; cursor?: string };

@Injectable()
export class CardFlowEntitiesService {
  constructor(
    @Inject('PG_POOL') private readonly db: Pool,
    private readonly notifications: NotificationsService,
    private readonly config: ConfigService,
  ) {}

  async getPhotonPayToken(key: string) {
    const result = await this.db.query(
      `SELECT token_key, access_token_ciphertext, access_token_iv, access_token_tag, expires_at, updated_at
       FROM photonpay_tokens WHERE token_key = $1`, [key],
    );
    const row = result.rows[0];
    if (!row) return null;
    try {
      const decipher = createDecipheriv('aes-256-gcm', this.photonPayKey(), row.access_token_iv);
      decipher.setAuthTag(row.access_token_tag);
      const token = Buffer.concat([decipher.update(row.access_token_ciphertext), decipher.final()]).toString('utf8');
      return { id: row.token_key, key: row.token_key, token, expires_at: new Date(row.expires_at).getTime(), issued_at: row.updated_at.toISOString() };
    } catch {
      return null;
    }
  }

  async savePhotonPayToken(data: { key: string; token: string; expires_at: number | string }) {
    const separator = data.key.indexOf(':');
    const environment = data.key.slice(0, separator);
    const appId = data.key.slice(separator + 1);
    if (!['sandbox', 'prod'].includes(environment) || !appId || !data.token) {
      throw new BadRequestException({ code: 'invalid_photonpay_token' });
    }
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.photonPayKey(), iv);
    const ciphertext = Buffer.concat([cipher.update(data.token, 'utf8'), cipher.final()]);
    const expiresAt = new Date(Number(data.expires_at));
    if (Number.isNaN(expiresAt.getTime())) throw new BadRequestException({ code: 'invalid_photonpay_token_expiry' });
    await this.db.query(
      `INSERT INTO photonpay_tokens
         (token_key, environment, app_id, access_token_ciphertext, access_token_iv, access_token_tag, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (token_key) DO UPDATE SET environment = EXCLUDED.environment,
         app_id = EXCLUDED.app_id, access_token_ciphertext = EXCLUDED.access_token_ciphertext,
         access_token_iv = EXCLUDED.access_token_iv, access_token_tag = EXCLUDED.access_token_tag,
         expires_at = EXCLUDED.expires_at, updated_at = now()`,
      [data.key, environment, appId, ciphertext, iv, cipher.getAuthTag(), expiresAt],
    );
    return { id: data.key, ...data, issued_at: new Date().toISOString() };
  }

  assertEntity(entity: string): void {
    if (!ENTITY_NAMES.has(entity)) throw new NotFoundException({ code: 'entity_not_found' });
  }

  private tableFor(entity: string): string {
    this.assertEntity(entity);
    const table = ENTITY_TABLES[entity];
    if (!table) throw new NotFoundException({ code: 'entity_not_found' });
    return table;
  }

  async filter(entity: string, filter: Record<string, unknown> = {}, options: EntityOptions = {}, principal?: FirebasePrincipal, internal = false) {
    this.assertEntity(entity);
    if (!internal) this.authorize(entity, 'read', principal);
    if (entity === 'User') return this.filterUsers(filter, options, principal, internal);

    const protectedFilters = Object.entries(filter ?? {}).filter(([field]) => SENSITIVE_RECORD_FIELDS[entity]?.has(field));
    if (protectedFilters.length) {
      if (!internal || protectedFilters.some(([, value]) => value === null || typeof value === 'object')) {
        throw new BadRequestException({ code: 'invalid_filter' });
      }
      const safeFilter = Object.fromEntries(Object.entries(filter).filter(([field]) => !SENSITIVE_RECORD_FIELDS[entity]?.has(field)));
    const params: unknown[] = [];
    const clauses = this.filterClauses(entity, safeFilter, params);
      const supportedHashes = protectedFilters.every(([field, value]) =>
        typeof value === 'string' && value.trim() !== ''
          && (field === 'owner_email' || (entity === 'Cardholder' && field === 'email')),
      );
      if (supportedHashes) {
        for (const [field, value] of protectedFilters) {
          params.push(field === 'owner_email'
            ? this.ownerEmailHash(String(value))
            : this.cardholderEmailHash(String(value)));
          clauses.push(`${field === 'owner_email' ? 'owner_email_hash' : 'cardholder_email_hash'} = $${params.length}`);
        }
        const sort = this.parseSort(options.sort);
        if (SENSITIVE_RECORD_FIELDS[entity]?.has(sort.field)) throw new BadRequestException({ code: 'invalid_sort' });
        const cursorField = sort.field === 'created_date' ? 'created_at' : `data->>'${sort.field}'`;
        const limit = this.parseLimit(options.limit);
        const cursor = this.decodeCursor(options.cursor);
        if (cursor) {
          const direction = sort.direction === 'DESC' ? '<' : '>';
          params.push(cursor.value, cursor.id);
          clauses.push(`((${cursorField} ${direction} $${params.length - 1}) OR (${cursorField} = $${params.length - 1} AND id ${direction} $${params.length}))`);
        }
        params.push(limit + 1);
        const result = await this.db.query(
          `SELECT id, data, created_by_id, created_at, updated_at FROM ${this.tableFor(entity)}
           WHERE ${clauses.length ? clauses.join(' AND ') : 'TRUE'} ORDER BY ${sort.sql}, id ${sort.direction} LIMIT $${params.length}`,
          params,
        );
        const hasMore = result.rows.length > limit;
        const rows = result.rows.slice(0, limit).map((row) => this.format(row, entity));
        const last = rows.at(-1);
        return {
          items: rows,
          has_more: hasMore,
          next_cursor: hasMore && last
            ? Buffer.from(JSON.stringify({ value: (last as Record<string, any>)[sort.field] ?? '', id: last.id })).toString('base64url')
            : null,
        };
      }
      const sort = this.parseSort(options.sort);
      if (SENSITIVE_RECORD_FIELDS[entity]?.has(sort.field)) throw new BadRequestException({ code: 'invalid_sort' });
      const result = await this.db.query(
        `SELECT id, data, created_by_id, created_at, updated_at FROM ${this.tableFor(entity)}
         WHERE ${clauses.length ? clauses.join(' AND ') : 'TRUE'} ORDER BY ${sort.sql}, id ${sort.direction} LIMIT 10000`,
        params,
      );
      let rows = result.rows.map((row) => this.format(row, entity) as Record<string, any>);
      rows = rows.filter((row) => protectedFilters.every(([field, value]) => row[field] === value));
      const cursor = this.decodeCursor(options.cursor);
      if (cursor) {
        const direction = sort.direction === 'DESC' ? -1 : 1;
        rows = rows.filter((row) => {
          const value = String(row[sort.field] ?? '');
          return (value.localeCompare(cursor.value) * direction) > 0
            || (value === cursor.value && row.id.localeCompare(cursor.id) * direction > 0);
        });
      }
      const limit = this.parseLimit(options.limit);
      const hasMore = rows.length > limit;
      const items = rows.slice(0, limit);
      const last = items.at(-1);
      return {
        items,
        has_more: hasMore,
        next_cursor: hasMore && last
          ? Buffer.from(JSON.stringify({ value: String(last[sort.field] ?? ''), id: last.id })).toString('base64url')
          : null,
      };
    }

    const params: unknown[] = [];
    const clauses = this.filterClauses(entity, filter, params);
    if (!internal && principal?.role !== 'admin') {
      if (!principal?.email) throw new ForbiddenException('Verified account access is required.');
      params.push(this.ownerEmailHash(principal.email));
      clauses.push(`owner_email_hash = $${params.length}`);
    }
    const sort = this.parseSort(options.sort);
    if (SENSITIVE_RECORD_FIELDS[entity]?.has(sort.field)) throw new BadRequestException({ code: 'invalid_sort' });
    const cursorField = sort.field === 'created_date' ? 'created_at' : `data->>'${sort.field}'`;
    const limit = this.parseLimit(options.limit);
    const cursor = this.decodeCursor(options.cursor);
    if (cursor) {
      const direction = sort.direction === 'DESC' ? '<' : '>';
      params.push(cursor.value, cursor.id);
      clauses.push(`((${cursorField} ${direction} $${params.length - 1}) OR (${cursorField} = $${params.length - 1} AND id ${direction} $${params.length}))`);
    }
    params.push(limit + 1);
    const result = await this.db.query(
      `SELECT id, data, created_by_id, created_at, updated_at FROM ${this.tableFor(entity)}
       WHERE ${clauses.length ? clauses.join(' AND ') : 'TRUE'} ORDER BY ${sort.sql}, id ${sort.direction} LIMIT $${params.length}`,
      params,
    );
    const hasMore = result.rows.length > limit;
    const rows = result.rows.slice(0, limit).map((row) => this.format(row, entity));
    const last = rows.at(-1);
    return {
      items: rows,
      has_more: hasMore,
      next_cursor: hasMore && last ? Buffer.from(JSON.stringify({ value: (last as Record<string, any>)[sort.field] ?? '', id: last.id })).toString('base64url') : null,
    };
  }

  async list(entity: string, options: EntityOptions = {}, principal?: FirebasePrincipal, internal = false) {
    return this.filter(entity, {}, options, principal, internal);
  }

  async count(entity: string, filter: Record<string, unknown> = {}, principal?: FirebasePrincipal, internal = false): Promise<number> {
    this.assertEntity(entity);
    if (!internal) this.authorize(entity, 'read', principal);
    if (entity === 'User') {
      const rows = await this.filterUsers(filter, { limit: 500 }, principal, internal);
      return rows.length;
    }
    const params: unknown[] = [];
    const clauses = this.filterClauses(entity, filter, params);
    if (!internal && principal?.role !== 'admin') {
      params.push(this.ownerEmailHash(principal?.email));
      clauses.push(`owner_email_hash = $${params.length}`);
    }
    const result = await this.db.query(`SELECT count(*)::int AS count FROM ${this.tableFor(entity)} ${clauses.length ? `WHERE ${clauses.join(' AND ')}` : ''}`, params);
    return result.rows[0].count;
  }

  async get(entity: string, id: string, principal?: FirebasePrincipal, internal = false) {
    this.assertEntity(entity);
    if (!SAFE_ID.test(id)) throw new BadRequestException({ code: 'invalid_record_id' });
    if (!internal) this.authorize(entity, 'read', principal);
    if (entity === 'User') {
      const users = await this.filterUsers({ id }, { limit: 1 }, principal, internal);
      if (!users[0]) throw new NotFoundException({ code: 'record_not_found' });
      return users[0];
    }
    const params: unknown[] = [id];
    let scope = '';
    if (!internal && principal?.role !== 'admin') {
      params.push(this.ownerEmailHash(principal?.email));
      scope = ` AND owner_email_hash = $${params.length}`;
    }
    const result = await this.db.query(
      `SELECT id, data, created_by_id, created_at, updated_at FROM ${this.tableFor(entity)} WHERE id = $1${scope}`,
      params,
    );
    if (!result.rowCount) throw new NotFoundException({ code: 'record_not_found' });
    return this.format(result.rows[0], entity);
  }

  async create(entity: string, input: Record<string, unknown>, principal?: FirebasePrincipal, internal = false) {
    this.assertEntity(entity);
    if (!internal) this.authorize(entity, 'create', principal);
    const clearData = this.sanitize(entity, input, false);
    if (!internal && principal?.role !== 'admin' && entity === 'CardholderApplication') {
      clearData.owner_email = principal?.email?.toLowerCase();
    }
    if (!internal && principal?.role !== 'admin' && entity === 'Notification') {
      clearData.owner_email = principal?.email?.toLowerCase();
      clearData.read = false;
    }
    const data = this.encryptSensitiveFields(entity, clearData);
    const ownerHash = this.ownerEmailHash(typeof clearData.owner_email === 'string' ? clearData.owner_email : undefined);
    const cardholderHash = entity === 'Cardholder'
      ? this.cardholderEmailHash(typeof clearData.email === 'string' ? clearData.email : undefined)
      : null;
    const createdById = principal?.uid ?? null;
    const id = entity === 'ProgrammeSettings' ? 'programme-settings' : randomUUID();
    try {
      const result = await this.db.query(
        `WITH inserted AS (
           INSERT INTO ${this.tableFor(entity)} (id, data, owner_email_hash, cardholder_email_hash, created_by_id)
           VALUES ($2, $3::jsonb, $4, $5, $6)
           ON CONFLICT DO NOTHING
           RETURNING id, data, created_by_id, created_at, updated_at
         ), queued AS (
           INSERT INTO cardflow_workflow_outbox (event_key, event_type, entity_id)
           SELECT 'declined-transaction:' || inserted.id, 'declined_transaction', inserted.id
           FROM inserted
           WHERE $1 = 'CardTransaction' AND lower(COALESCE(inserted.data->>'status', '')) = 'declined'
           ON CONFLICT (event_key) DO NOTHING
           RETURNING event_key
         )
         SELECT id, data, created_by_id, created_at, updated_at FROM inserted`,
          [entity, id, JSON.stringify(data), ownerHash, cardholderHash, createdById],
      );
      if (!result.rowCount && entity === 'CardTransaction' && data.photon_txn_id) {
        const prior = await this.db.query(
          `SELECT id, data, created_by_id, created_at, updated_at FROM card_transactions
           WHERE data->>'photon_txn_id' = $1`,
          [data.photon_txn_id],
        );
        if (prior.rowCount) return this.format(prior.rows[0], entity);
      }
      if (!result.rowCount && entity === 'Notification' && data.dedupe_key) {
        const prior = await this.db.query(
          `SELECT id, data, created_by_id, created_at, updated_at FROM notifications
           WHERE owner_email_hash = $1 AND data->>'dedupe_key' = $2`,
          [ownerHash, data.dedupe_key],
        );
        if (prior.rowCount) return this.format(prior.rows[0], entity);
      }
      if (!result.rowCount) throw new BadRequestException({ code: 'duplicate_record' });
      if (entity === 'Notification' && clearData.owner_email && clearData.title) {
        void this.notifications.sendToEmail(
          String(clearData.owner_email),
          String(clearData.title),
          String(clearData.body ?? ''),
          { type: String(clearData.kind ?? 'notification'), ...(clearData.link ? { link: String(clearData.link) } : {}) },
        ).catch(() => undefined);
      }
      return this.format(result.rows[0], entity);
    } catch (error) {
      if ((error as { code?: string })?.code === '23505') throw new BadRequestException({ code: 'duplicate_record' });
      throw error;
    }
  }

  async update(entity: string, id: string, patch: Record<string, unknown>, principal?: FirebasePrincipal, internal = false) {
    this.assertEntity(entity);
    if (!SAFE_ID.test(id)) throw new BadRequestException({ code: 'invalid_record_id' });
    if (!internal) this.authorize(entity, 'update', principal);
    const clearChanges = this.sanitize(entity, patch, false);
    const changes = this.encryptSensitiveFields(entity, clearChanges);
    if (!internal && principal?.role !== 'admin') {
      if (entity !== 'Notification') throw new ForbiddenException('This record cannot be changed by this account.');
      const keys = Object.keys(changes);
      if (keys.some((key) => !['read', 'read_at'].includes(key))) throw new ForbiddenException('Only notification read state can be changed.');
    }
    if (entity === 'User') {
      if (!internal && principal?.role !== 'admin') throw new ForbiddenException();
      const result = await this.db.query(
        `UPDATE app_users SET role = COALESCE($3, role), display_name = COALESCE($4, display_name), updated_at = now()
         WHERE id::text = $1 OR firebase_uid = $2
           RETURNING id::text AS id, email, display_name, role, created_by_id, created_at, updated_at`,
        [id, id, changes.role ?? null, changes.display_name ?? null],
      );
      if (!result.rowCount) throw new NotFoundException({ code: 'record_not_found' });
      return result.rows[0];
    }
    const params: unknown[] = [id, JSON.stringify(changes)];
    const hasOwnerEmailChange = Object.prototype.hasOwnProperty.call(clearChanges, 'owner_email');
    params.push(hasOwnerEmailChange, hasOwnerEmailChange && typeof clearChanges.owner_email === 'string'
      ? this.ownerEmailHash(clearChanges.owner_email)
      : null);
    const hasCardholderEmailChange = entity === 'Cardholder' && Object.prototype.hasOwnProperty.call(clearChanges, 'email');
    params.push(hasCardholderEmailChange, hasCardholderEmailChange && typeof clearChanges.email === 'string'
      ? this.cardholderEmailHash(clearChanges.email)
      : null);
    let scope = '';
    if (!internal && principal?.role !== 'admin') {
      params.push(this.ownerEmailHash(principal?.email));
      scope = ` AND owner_email_hash = $${params.length}`;
    }
    try {
      const result = await this.db.query(
        `WITH previous AS MATERIALIZED (
           SELECT id, data FROM ${this.tableFor(entity)}
           WHERE id = $1${scope}
           FOR UPDATE
         ), updated AS (
           UPDATE ${this.tableFor(entity)} AS record
           SET data = record.data || $2::jsonb,
               owner_email_hash = CASE WHEN $3::boolean THEN $4::text ELSE record.owner_email_hash END,
               cardholder_email_hash = CASE WHEN $5::boolean THEN $6::text ELSE record.cardholder_email_hash END,
               updated_at = now()
           FROM previous
           WHERE record.id = $1
           RETURNING record.id, record.data, record.created_by_id, record.created_at, record.updated_at, previous.data AS previous_data
         ), queued AS (
           INSERT INTO cardflow_workflow_outbox (event_key, event_type, entity_id, payload)
           SELECT 'card-status:' || updated.id || ':' || to_char(updated.updated_at AT TIME ZONE 'UTC', 'YYYYMMDDHH24MISSUS'),
             'card_status_changed', updated.id,
             jsonb_build_object('previous_status', updated.previous_data->>'status', 'new_status', updated.data->>'status')
           FROM updated
           WHERE '${entity}' = 'Card'
             AND COALESCE(updated.previous_data->>'status', '') IS DISTINCT FROM COALESCE(updated.data->>'status', '')
           ON CONFLICT (event_key) DO NOTHING
           RETURNING event_key
         )
         SELECT id, data, created_by_id, created_at, updated_at FROM updated`,
        params,
      );
      if (!result.rowCount) throw new NotFoundException({ code: 'record_not_found' });
      return this.format(result.rows[0], entity);
    } catch (error) {
      if ((error as { code?: string })?.code === '23505') throw new BadRequestException({ code: 'duplicate_record' });
      throw error;
    }
  }

  async updateMany(entity: string, filter: Record<string, unknown>, update: Record<string, unknown>, principal?: FirebasePrincipal, internal = false) {
    this.assertEntity(entity);
    if (!internal) this.authorize(entity, 'update', principal);
    const query = this.sanitize(entity, filter, true);
    const protectedFilters = Object.entries(query).filter(([field]) => SENSITIVE_RECORD_FIELDS[entity]?.has(field));
    if (protectedFilters.length && (!internal || !protectedFilters.every(([field, value]) =>
      typeof value === 'string' && value.trim() !== ''
        && (field === 'owner_email' || (entity === 'Cardholder' && field === 'email')),
    ))) throw new BadRequestException({ code: 'invalid_filter' });
    const safeQuery = Object.fromEntries(Object.entries(query).filter(([field]) => !SENSITIVE_RECORD_FIELDS[entity]?.has(field)));
    const clearChanges = this.sanitize(entity, (update as any).$set ?? update, false);
    const changes = this.encryptSensitiveFields(entity, clearChanges);
    const params: unknown[] = [JSON.stringify(safeQuery), JSON.stringify(changes)];
    const protectedClauses: string[] = [];
    for (const [field, value] of protectedFilters) {
      params.push(field === 'owner_email'
        ? this.ownerEmailHash(String(value))
        : this.cardholderEmailHash(String(value)));
      protectedClauses.push(`${field === 'owner_email' ? 'owner_email_hash' : 'cardholder_email_hash'} = $${params.length}`);
    }
    let ownerScope = '';
    if (!internal && principal?.role !== 'admin') {
      if (entity !== 'Notification' || Object.keys(changes).some((key) => !['read', 'read_at'].includes(key))) {
        throw new ForbiddenException('This account cannot perform that operation.');
      }
      params.push(this.ownerEmailHash(principal?.email));
      ownerScope = ` AND owner_email_hash = $${params.length}`;
    }
    params.push(Object.prototype.hasOwnProperty.call(clearChanges, 'owner_email'));
    params.push(Object.prototype.hasOwnProperty.call(clearChanges, 'owner_email') && typeof clearChanges.owner_email === 'string'
      ? this.ownerEmailHash(clearChanges.owner_email)
      : null);
    const hasCardholderEmailChange = entity === 'Cardholder' && Object.prototype.hasOwnProperty.call(clearChanges, 'email');
    params.push(hasCardholderEmailChange);
    params.push(hasCardholderEmailChange && typeof clearChanges.email === 'string'
      ? this.cardholderEmailHash(clearChanges.email)
      : null);
    const ownerHashFlagIndex = params.length - 3;
    const ownerHashIndex = params.length - 2;
    const cardholderHashFlagIndex = params.length - 1;
    const cardholderHashIndex = params.length;
    const result = await this.db.query(
      `UPDATE ${this.tableFor(entity)} SET data = data || $2::jsonb,
       owner_email_hash = CASE WHEN $${ownerHashFlagIndex}::boolean THEN $${ownerHashIndex}::text ELSE owner_email_hash END,
       cardholder_email_hash = CASE WHEN $${cardholderHashFlagIndex}::boolean THEN $${cardholderHashIndex}::text ELSE cardholder_email_hash END,
       updated_at = now()
       WHERE data @> $1::jsonb${protectedClauses.length ? ` AND ${protectedClauses.join(' AND ')}` : ''}${ownerScope} RETURNING id`,
      params,
    );
    return { count: result.rowCount };
  }

  async remove(entity: string, id: string, principal?: FirebasePrincipal, internal = false) {
    this.assertEntity(entity);
    if (!SAFE_ID.test(id)) throw new BadRequestException({ code: 'invalid_record_id' });
    if (!internal) this.authorize(entity, 'delete', principal);
    if (entity === 'User') {
      const client = await this.db.connect();
      try {
        await client.query('BEGIN');
        const found = await client.query('SELECT id, firebase_uid FROM app_users WHERE id::text = $1 OR firebase_uid = $1 FOR UPDATE', [id]);
        if (!found.rowCount) throw new NotFoundException({ code: 'record_not_found' });
        const accountId = found.rows[0].id;
        const uid = found.rows[0].firebase_uid;
        await client.query('DELETE FROM user_devices WHERE user_id = $1', [accountId]);
        await client.query(
          `UPDATE app_users SET deleted_at = now(), firebase_uid = 'deleted:' || id::text,
             email = NULL, email_verified = false, display_name = NULL, password_hash = NULL,
             role = 'user', updated_at = now() WHERE id = $1`, [accountId],
        );
        await client.query('COMMIT');
        return { deleted: true, firebaseUid: uid };
      } catch (error) {
        try { await client.query('ROLLBACK'); } catch { /* transaction already ended */ }
        throw error;
      } finally { client.release(); }
    }
    const params: unknown[] = [id];
    let scope = '';
    if (!internal && principal?.role !== 'admin') {
      params.push(this.ownerEmailHash(principal?.email));
      scope = ` AND owner_email_hash = $${params.length}`;
    }
    const result = await this.db.query(`DELETE FROM ${this.tableFor(entity)} WHERE id = $1${scope} RETURNING id`, params);
    if (!result.rowCount) throw new NotFoundException({ code: 'record_not_found' });
    return { deleted: true };
  }

  private async filterUsers(filter: Record<string, unknown>, options: EntityOptions, principal?: FirebasePrincipal, internal = false) {
    if (!internal && principal?.role !== 'admin') {
      if (principal?.uid) {
        const result = await this.db.query(
          `SELECT id::text AS id, firebase_uid, email, email_verified, display_name, display_name AS full_name, role,
                  created_by_id, created_at, created_at AS created_date, updated_at
           FROM app_users WHERE firebase_uid = $1`, [principal.uid],
        );
        return result.rows;
      }
      throw new ForbiddenException();
    }
    const clauses: string[] = [];
    const params: unknown[] = [];
    for (const [key, value] of Object.entries(filter ?? {})) {
      if (!['id', 'email', 'role', 'firebase_uid', 'created_by_id'].includes(key)) throw new BadRequestException({ code: 'invalid_filter' });
      params.push(String(value));
      clauses.push(`${key === 'id' ? 'id::text' : key} = $${params.length}`);
    }
    const sort = this.parseSort(options.sort, true);
    params.push(this.parseLimit(options.limit));
    const result = await this.db.query(
      `SELECT id::text AS id, firebase_uid, email, email_verified, display_name, display_name AS full_name, role,
              created_by_id, created_at, created_at AS created_date, updated_at
       FROM app_users WHERE deleted_at IS NULL ${clauses.length ? `AND ${clauses.join(' AND ')}` : ''}
       ORDER BY ${sort.sql} LIMIT $${params.length}`,
      params,
    );
    return result.rows;
  }

  private sanitize(entity: string, value: Record<string, unknown> = {}, filter: boolean) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new BadRequestException({ code: 'invalid_entity_data' });
    const allowed = ENTITY_FIELDS[entity];
    const output: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) {
      if (!allowed.has(key)) {
        if (filter) throw new BadRequestException({ code: 'invalid_filter' });
        continue;
      }
      if (typeof item === 'function' || typeof item === 'undefined') continue;
      output[key] = item;
    }
    if (!filter && entity === 'PhotonPayLog') return this.sanitizePhotonPayLog(output);
    return output;
  }

  private sanitizePhotonPayLog(data: Record<string, unknown>): Record<string, unknown> {
    const output = { ...data };
    for (const field of ['request_headers', 'response_headers']) {
      if (typeof output[field] !== 'string') {
        delete output[field];
        continue;
      }
      try {
        output[field] = redactHeaders(JSON.parse(output[field] as string));
      } catch {
        output[field] = '{}';
      }
    }
    for (const field of ['request_body', 'response_body']) {
      if (output[field] !== undefined && output[field] !== null) output[field] = redactBody(String(output[field]));
    }
    if (typeof output.path === 'string') {
      try { output.path = new URL(output.path, 'https://z8.local').pathname.slice(0, 500); }
      catch { output.path = ''; }
    }
    if (typeof output.error === 'string') output.error = redactBody(JSON.stringify({ error: output.error }));
    return output;
  }

  private authorize(entity: string, operation: string, principal?: FirebasePrincipal): void {
    if (!principal?.uid) throw new ForbiddenException('A signed-in account is required.');
    if (principal.role === 'admin') return;
    const userRead = ['Card', 'CardTransaction', 'CardholderApplication', 'Notification'].includes(entity) && operation === 'read';
    const notificationUpdate = entity === 'Notification' && operation === 'update';
    if (principal.role === 'user' && (userRead || notificationUpdate)) return;
    throw new ForbiddenException('This account cannot perform that operation.');
  }

  private parseSort(value?: string, user = false): { field: string; direction: 'ASC' | 'DESC'; sql: string } {
    const raw = String(value || '-created_date');
    const descending = raw.startsWith('-');
    const field = raw.replace(/^-/, '');
    if (!/^[a-z][a-z0-9_]{0,63}$/.test(field)) throw new BadRequestException({ code: 'invalid_sort' });
    const column = user ? ({ created_date: 'created_at', email: 'email', role: 'role', created_by_id: 'created_by_id' } as Record<string, string>)[field] : null;
    if (user && !column) throw new BadRequestException({ code: 'invalid_sort' });
    const direction = descending ? 'DESC' : 'ASC';
    return { field, direction, sql: user ? `${column} ${direction}` : `${field === 'created_date' ? 'created_at' : `data->>'${field}'`} ${direction} NULLS LAST` };
  }

  private filterClauses(entity: string, filter: Record<string, unknown>, params: unknown[]): string[] {
    if (!filter || typeof filter !== 'object' || Array.isArray(filter)) throw new BadRequestException({ code: 'invalid_filter' });
    const clauses: string[] = [];
    for (const [field, condition] of Object.entries(filter)) {
      if (!ENTITY_FIELDS[entity].has(field)) throw new BadRequestException({ code: 'invalid_filter' });
      if (SENSITIVE_RECORD_FIELDS[entity]?.has(field)) throw new BadRequestException({ code: 'invalid_filter' });
      const sqlField = `data->>'${field}'`;
      if (condition && typeof condition === 'object' && !Array.isArray(condition)) {
        for (const [operator, value] of Object.entries(condition)) {
          params.push(value);
          const param = `$${params.length}`;
          if (operator === '$lt' || operator === '$lte' || operator === '$gt' || operator === '$gte') {
            clauses.push(`${sqlField} ${({ $lt: '<', $lte: '<=', $gt: '>', $gte: '>=' } as Record<string, string>)[operator]} ${param}`);
          } else if (operator === '$regex') {
            const pattern = String(value);
            if (pattern.length > 128 || /[()[\]{}+*?|]/.test(pattern.replace(/\\[()[\]{}+*?|]/g, ''))) throw new BadRequestException({ code: 'invalid_filter' });
            const literal = pattern.replace(/\\([.*+?^${}()|[\]\\])/g, '$1').replace(/[%_]/g, '\\$&');
            params[params.length - 1] = `%${literal}%`;
            clauses.push(`${sqlField} ILIKE ${param} ESCAPE '\\'`);
          } else if (operator === '$in' && Array.isArray(value) && value.length <= 100) {
            params[params.length - 1] = value.map(String);
            clauses.push(`${sqlField} = ANY(${param}::text[])`);
          } else {
            throw new BadRequestException({ code: 'invalid_filter' });
          }
        }
      } else {
        params.push(condition);
        clauses.push(`${sqlField} = $${params.length}`);
      }
    }
    return clauses;
  }

  private decodeCursor(cursor?: string): { value: string; id: string } | null {
    if (!cursor) return null;
    try {
      if (cursor.length > 1024) throw new Error();
      const parsed = JSON.parse(Buffer.from(cursor, 'base64url').toString('utf8'));
      if (typeof parsed.value !== 'string' || typeof parsed.id !== 'string' || !SAFE_ID.test(parsed.id)) throw new Error();
      return parsed;
    } catch {
      throw new BadRequestException({ code: 'invalid_cursor' });
    }
  }

  private parseLimit(value?: number): number {
    const limit = value === undefined ? 100 : Number(value);
    if (!Number.isInteger(limit) || limit < 1) throw new BadRequestException({ code: 'invalid_limit' });
    return Math.min(limit, 500);
  }

  private format(row: { id: string; data: Record<string, unknown>; created_by_id?: string | null; created_at: Date | string; updated_at: Date | string }, entity: string) {
    return {
      ...this.decryptSensitiveFields(entity, row.data),
      id: row.id,
      created_by_id: row.created_by_id ?? null,
      created_date: new Date(row.created_at).toISOString(),
      updated_date: new Date(row.updated_at).toISOString(),
    };
  }

  private encryptSensitiveFields(entity: string, data: Record<string, unknown>): Record<string, unknown> {
    const fields = SENSITIVE_RECORD_FIELDS[entity];
    if (!fields) return data;
    if (![...fields].some((field) => data[field] !== undefined && data[field] !== null && data[field] !== '')) return data;
    return encryptSensitiveRecordFields(entity, data, this.recordPiiKey());
  }

  private decryptSensitiveFields(entity: string, data: Record<string, unknown>): Record<string, unknown> {
    return decryptSensitiveRecordFields(entity, data, this.recordPiiKey());
  }

  private recordPiiKey(): Buffer {
    return parseRecordPiiKey(this.config.get<string>('RECORD_PII_ENCRYPTION_KEY', ''));
  }

  private ownerEmailHash(email?: string): string | null {
    const key = parseRecordPiiKey(this.config.get<string>('RECORD_LOOKUP_HMAC_KEY', ''));
    return ownerEmailLookupHash(email, key);
  }

  private cardholderEmailHash(email?: string): string | null {
    const key = parseRecordPiiKey(this.config.get<string>('RECORD_LOOKUP_HMAC_KEY', ''));
    return cardholderEmailLookupHash(email, key);
  }

  private photonPayKey(): Buffer {
    const raw = this.config.get<string>('PHOTONPAY_TOKEN_ENCRYPTION_KEY', '').trim();
    const key = Buffer.from(raw, 'base64');
    if (key.length !== 32) throw new ServiceUnavailableException('PhotonPay token encryption is not configured.');
    return key;
  }
}
