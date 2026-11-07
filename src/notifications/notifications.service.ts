import { Inject, Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Messaging } from 'firebase-admin/messaging';
import { Pool } from 'pg';
import { randomUUID } from 'node:crypto';
import {
  encryptSensitiveRecordFields,
  ownerEmailLookupHash,
  parseRecordPiiKey,
} from '../card-flow/record-pii-crypto';

@Injectable()
export class NotificationsService {
  private readonly logger = new Logger(NotificationsService.name);

  constructor(
    @Inject('PG_POOL') private readonly db: Pool,
    @Inject('FIREBASE_MESSAGING') private readonly messaging: Messaging,
    private readonly config: ConfigService,
  ) {}

  async notifyAdminsOfNewAccount(userId: string) {
    try {
      const key = parseRecordPiiKey(
        this.config.get<string>('RECORD_PII_ENCRYPTION_KEY', ''),
      );
      const admins = await this.db.query(
        `SELECT email FROM app_users
         WHERE role = 'admin' AND deleted_at IS NULL AND email IS NOT NULL
         ORDER BY created_at`,
      );
      for (const row of admins.rows) {
        const email = String(row.email).trim().toLowerCase();
        if (!email) continue;
        try {
          const dedupeKey = `admin-new-account:${userId}:${email}`;
          const data = encryptSensitiveRecordFields('Notification', {
            owner_email: email,
            kind: 'account',
            tone: 'info',
            title: 'New client account created',
            body: 'A new client completed sign-up and can now submit identity verification.',
            link: '/cardholders',
            dedupe_key: dedupeKey,
            read: false,
          }, key);
          const inserted = await this.db.query(
            `INSERT INTO notifications (id, data, owner_email_hash)
             VALUES ($1, $2::jsonb, $3)
             ON CONFLICT DO NOTHING
             RETURNING id`,
            [randomUUID(), JSON.stringify(data), ownerEmailLookupHash(email, key)],
          );
          if (inserted.rowCount) {
            await this.sendToEmail(
              email,
              'New client account created',
              'A new client completed sign-up and can now submit identity verification.',
              { type: 'account', link: '/cardholders' },
            );
          }
        } catch (error) {
          this.logger.warn(
            `New-account notification failed for one administrator; code=${this.errorCode(error)}.`,
          );
        }
      }
    } catch (error) {
      this.logger.warn(
        `New-account admin notification was not delivered; code=${this.errorCode(error)}.`,
      );
    }
  }

  async sendToEmail(email: string, title: string, body: string, data: Record<string, string> = {}) {
    const result = await this.db.query(
      'SELECT firebase_uid FROM app_users WHERE lower(email) = lower($1)', [email],
    );
    const uid = result.rows[0]?.firebase_uid;
    if (!uid) return { deviceCount: 0, sent: 0 };
    return this.sendToUser(uid, title, body, data);
  }

  async sendToUser(firebaseUid: string, title: string, body: string, data: Record<string, string> = {}) {
    const result = await this.db.query(
      `SELECT d.firebase_token FROM user_devices d
       JOIN app_users u ON u.id = d.user_id WHERE u.firebase_uid = $1`,
      [firebaseUid],
    );
    const tokens: string[] = result.rows.map((row) => row.firebase_token);
    let sent = 0;
    for (let offset = 0; offset < tokens.length; offset += 500) {
      const chunk = tokens.slice(offset, offset + 500);
      const response = await this.messaging.sendEachForMulticast({
        tokens: chunk,
        notification: { title, body },
        data,
        android: { priority: 'high', notification: { channelId: 'z8_alerts' } },
        apns: { payload: { aps: { sound: 'default' } } },
        webpush: {
          headers: { Urgency: 'high' },
          notification: { icon: '/favicon.ico', tag: data.type ?? 'z8-notification' },
          fcmOptions: { link: data.link ? `https://portal.z8card.com${data.link}` : 'https://portal.z8card.com/' },
        },
      });
      sent += response.successCount;
      const invalidTokens = response.responses.flatMap((item, index) =>
        !item.success && [
          'messaging/registration-token-not-registered',
          'messaging/invalid-registration-token',
        ].includes(item.error?.code ?? '') ? [chunk[index]] : [],
      );
      if (invalidTokens.length) {
        await this.db.query('DELETE FROM user_devices WHERE firebase_token = ANY($1::text[])', [invalidTokens]);
      }
      if (response.failureCount) this.logger.warn(`FCM delivery failures: ${response.failureCount}`);
    }
    return { deviceCount: tokens.length, sent };
  }

  private errorCode(error: unknown): string {
    return error && typeof error === 'object' && 'code' in error
      ? String((error as { code: unknown }).code).slice(0, 80)
      : 'notification_failed';
  }
}
