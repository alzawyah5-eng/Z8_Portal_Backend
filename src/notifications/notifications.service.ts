import { Inject, Injectable, Logger, NotFoundException } from '@nestjs/common';
import { Messaging } from 'firebase-admin/messaging';
import { Pool } from 'pg';

@Injectable()
export class NotificationsService {
  private readonly logger = new Logger(NotificationsService.name);

  constructor(
    @Inject('PG_POOL') private readonly db: Pool,
    @Inject('FIREBASE_MESSAGING') private readonly messaging: Messaging,
  ) {}

  async sendTestToUser(firebaseUid: string) {
    const user = await this.db.query(
      'SELECT 1 FROM app_users WHERE firebase_uid = $1',
      [firebaseUid],
    );
    if (!user.rowCount) throw new NotFoundException({ code: 'user_not_registered' });
    this.logger.log('User requested a push test; sending immediately.');
    const result = await this.sendToUser(
      firebaseUid,
      'Z8 notifications are connected',
      'Your device can receive Z8 alerts.',
      { type: 'notification_test' },
    );
    this.logger.log(
      `Push test finished; registeredDevices=${result.deviceCount}, acceptedByFcm=${result.sent}.`,
    );
    return result;
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
}
