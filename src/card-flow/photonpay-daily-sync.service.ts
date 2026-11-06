import { Inject, Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Pool } from 'pg';
import { FirebasePrincipal } from '../auth/firebase-principal';
import { LocalWorkflowContextFactory } from './workflow-context.factory';
import photonpaySync from './legacy/photonpay-sync';

const DAILY_SYNC_LOCK_CLASS = 800_217;
const DAILY_SYNC_LOCK_ID = 1;

@Injectable()
export class PhotonPayDailySyncService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(PhotonPayDailySyncService.name);
  private timer?: NodeJS.Timeout;

  constructor(
    @Inject('PG_POOL') private readonly db: Pool,
    private readonly config: ConfigService,
    private readonly contextFactory: LocalWorkflowContextFactory,
  ) {}

  onModuleInit() {
    if (this.config.get<string>('PHOTONPAY_DAILY_SYNC_ENABLED', 'true').toLowerCase() === 'false') {
      this.logger.log('Daily PhotonPay transaction sync is disabled by configuration.');
      return;
    }
    this.scheduleNext();
  }

  onModuleDestroy() {
    if (this.timer) clearTimeout(this.timer);
  }

  private scheduleNext() {
    const now = new Date();
    const next = new Date(now);
    next.setUTCHours(2, 17, 0, 0);
    if (next.getTime() <= now.getTime()) next.setUTCDate(next.getUTCDate() + 1);
    const delay = Math.max(1_000, next.getTime() - now.getTime());
    this.timer = setTimeout(() => {
      void this.run().finally(() => this.scheduleNext());
    }, delay);
    this.timer.unref();
    this.logger.log(`Daily PhotonPay transaction sync scheduled for ${next.toISOString()}.`);
  }

  private async run(): Promise<void> {
    const client = await this.db.connect();
    let locked = false;
    try {
      const lock = await client.query<{ acquired: boolean }>(
        'SELECT pg_try_advisory_lock($1, $2) AS acquired',
        [DAILY_SYNC_LOCK_CLASS, DAILY_SYNC_LOCK_ID],
      );
      locked = lock.rows[0]?.acquired === true;
      if (!locked) {
        this.logger.log('Daily PhotonPay sync skipped because another backend instance owns the job lock.');
        return;
      }

      const systemAdmin: FirebasePrincipal = {
        uid: 'z8-scheduled-workflow',
        email: 'scheduled-workflow@z8.local',
        email_verified: true,
        name: 'Z8 Scheduled Workflow',
        admin: true,
        role: 'admin',
      };
      const request = new Request('https://z8.local/v1/functions/photonpayTransactionSync', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{}',
      });
      const response = await photonpaySync(request, this.contextFactory.create(systemAdmin));
      const summary = await response.json().catch(() => null);
      if (!response.ok) {
        this.logger.error(`Scheduled PhotonPay sync failed; http_status=${response.status}.`);
        return;
      }
      this.logger.log(`Scheduled PhotonPay sync completed; ${JSON.stringify(summary)}`);
    } catch (error) {
      this.logger.error(`Scheduled PhotonPay sync failed; code=${this.errorCode(error)}.`);
    } finally {
      if (locked) {
        await client.query('SELECT pg_advisory_unlock($1, $2)', [DAILY_SYNC_LOCK_CLASS, DAILY_SYNC_LOCK_ID]).catch(() => undefined);
      }
      client.release();
    }
  }

  private errorCode(error: unknown): string {
    if (error && typeof error === 'object' && 'code' in error) {
      return String((error as { code: unknown }).code).slice(0, 80);
    }
    return 'sync_failed';
  }
}
