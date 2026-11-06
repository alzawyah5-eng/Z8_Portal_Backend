import { Inject, Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Pool } from 'pg';
import nodemailer from 'nodemailer';
import { decryptSensitiveRecordFields, parseRecordPiiKey } from './record-pii-crypto';

type WorkflowEvent = {
  event_key: string;
  event_type: 'card_status_changed' | 'declined_transaction';
  entity_id: string;
  payload: Record<string, string | null>;
  attempts: number;
};

@Injectable()
export class WorkflowAutomationService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(WorkflowAutomationService.name);
  private timer?: NodeJS.Timeout;
  private draining = false;

  constructor(
    @Inject('PG_POOL') private readonly db: Pool,
    private readonly config: ConfigService,
  ) {}

  onModuleInit() {
    this.timer = setInterval(() => void this.drain(), 5_000);
    this.timer.unref();
    void this.drain();
  }

  onModuleDestroy() {
    if (this.timer) clearInterval(this.timer);
  }

  private async drain(): Promise<void> {
    if (this.draining) return;
    this.draining = true;
    try {
      const client = await this.db.connect();
      let events: WorkflowEvent[] = [];
      try {
        await client.query('BEGIN');
        const claimed = await client.query(
          `WITH ready AS (
             SELECT event_key FROM cardflow_workflow_outbox
             WHERE (status = 'pending' AND next_attempt_at <= now())
                OR (status = 'processing' AND lease_until < now())
             ORDER BY created_at
             FOR UPDATE SKIP LOCKED
             LIMIT 20
           )
           UPDATE cardflow_workflow_outbox AS outbox
           SET status = 'processing', attempts = outbox.attempts + 1,
               lease_until = now() + interval '5 minutes', updated_at = now()
           FROM ready
           WHERE outbox.event_key = ready.event_key
           RETURNING outbox.event_key, outbox.event_type, outbox.entity_id,
                     outbox.payload, outbox.attempts`,
        );
        events = claimed.rows;
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK').catch(() => undefined);
        throw error;
      } finally {
        client.release();
      }

      for (const event of events) {
        try {
          await this.deliver(event);
          await this.db.query(
            `UPDATE cardflow_workflow_outbox
             SET status = 'sent', sent_at = now(), lease_until = NULL,
                 last_error_code = NULL, updated_at = now()
             WHERE event_key = $1 AND status = 'processing'`,
            [event.event_key],
          );
        } catch (error) {
          const delayMinutes = Math.min(360, 2 ** Math.min(event.attempts, 8));
          await this.db.query(
            `UPDATE cardflow_workflow_outbox
             SET status = 'pending', next_attempt_at = now() + ($2 * interval '1 minute'),
                 lease_until = NULL, last_error_code = $3, updated_at = now()
             WHERE event_key = $1 AND status = 'processing'`,
            [event.event_key, delayMinutes, this.errorCode(error)],
          );
          this.logger.warn(`Workflow email delivery deferred; event=${event.event_key}; retry_minutes=${delayMinutes}`);
        }
      }
    } catch (error) {
      this.logger.error(`Workflow outbox poll failed; code=${this.errorCode(error)}`);
    } finally {
      this.draining = false;
    }
  }

  private async deliver(event: WorkflowEvent): Promise<void> {
    const entity = event.event_type === 'card_status_changed' ? 'Card' : 'CardTransaction';
    const result = await this.db.query(
      `SELECT data FROM ${entity === 'Card' ? 'cards' : 'card_transactions'} WHERE id = $1`,
      [event.entity_id],
    );
    if (!result.rowCount) return;
    const admins = await this.db.query(
      `SELECT email FROM app_users WHERE role = 'admin' AND deleted_at IS NULL
       AND email IS NOT NULL ORDER BY created_at LIMIT 10`,
    );
    const recipients: string[] = admins.rows.map((row) => String(row.email)).filter(Boolean);
    if (!recipients.length) return;

    const encryptedRecord = result.rows[0].data as Record<string, unknown>;
    const record = decryptSensitiveRecordFields(entity, encryptedRecord, parseRecordPiiKey(
      this.config.get<string>('RECORD_PII_ENCRYPTION_KEY', ''),
    ));
    const variables = event.event_type === 'card_status_changed'
      ? {
          card_name: String(record.nickname || 'Z8 card'),
          last4: String(record.last4 || ''),
          cardholder: String(record.cardholder_name || 'Not assigned'),
          previous_status: String(event.payload.previous_status || 'unknown'),
          new_status: String(record.status || event.payload.new_status || 'unknown'),
          card_url: `https://portal.z8card.com/cards/${encodeURIComponent(event.entity_id)}`,
        }
      : {
          merchant: String(record.merchant || 'Unknown merchant'),
          amount: Number.isFinite(Number(record.amount)) ? Number(record.amount).toFixed(2) : '0.00',
          currency: String(record.currency || 'USD'),
          card_name: String(record.card_nickname || 'Z8 card'),
          last4: String(record.card_last4 || ''),
          category: String(record.category || 'Uncategorised'),
          occurred_at: this.formatWhen(record.occurred_at),
          card_url: record.card_id
            ? `https://portal.z8card.com/cards/${encodeURIComponent(String(record.card_id))}`
            : 'https://portal.z8card.com/activity',
        };

    const host = this.config.get<string>('SMTP_HOST', '').trim();
    const user = this.config.get<string>('SMTP_USER', '').trim();
    const pass = this.config.get<string>('SMTP_PASSWORD', '');
    if (!host || !user || !pass) throw new Error('smtp_unavailable');
    const port = Number(this.config.get('SMTP_PORT', 587));
    const transport = nodemailer.createTransport({
      host,
      port,
      secure: this.config.get('SMTP_SECURE', 'false') === 'true' || port === 465,
      auth: { user, pass },
    });
    const subject = event.event_type === 'card_status_changed'
      ? 'Z8 Portal: Card Status Alert'
      : 'Z8 Portal: Declined Transaction';
    const text = event.event_type === 'card_status_changed'
      ? `A card status changed.\n\nCard: ${variables.card_name}\nLast four: ${variables.last4}\nCardholder: ${variables.cardholder}\nPrevious status: ${variables.previous_status}\nNew status: ${variables.new_status}\n\n${variables.card_url}`
      : `A card transaction was declined.\n\nMerchant: ${variables.merchant}\nAmount: ${variables.amount} ${variables.currency}\nCard: ${variables.card_name}\nLast four: ${variables.last4}\nCategory: ${variables.category}\nOccurred: ${variables.occurred_at}\n\n${variables.card_url}`;
    await transport.sendMail({
      from: this.config.get<string>('SMTP_FROM', user),
      to: recipients,
      subject,
      text,
    });
  }

  private formatWhen(value: unknown): string {
    const date = new Date(String(value ?? ''));
    return Number.isNaN(date.getTime()) ? 'Just now' : `${date.toISOString().slice(0, 16).replace('T', ' ')} UTC`;
  }

  private errorCode(error: unknown): string {
    if (error && typeof error === 'object' && 'code' in error) {
      return String((error as { code: unknown }).code).slice(0, 80);
    }
    return error instanceof Error && error.message === 'smtp_unavailable' ? 'smtp_unavailable' : 'delivery_failed';
  }
}
