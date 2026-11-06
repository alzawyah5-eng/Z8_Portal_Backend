import { Module, OnApplicationShutdown } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Pool } from 'pg';

class DatabaseLifecycle implements OnApplicationShutdown {
  constructor(private readonly pool: Pool) {}
  async onApplicationShutdown(): Promise<void> {
    await this.pool.end();
  }
}

@Module({
  providers: [
    {
      provide: 'PG_POOL',
      inject: [ConfigService],
      useFactory: (config: ConfigService) =>
        new Pool({
          connectionString: config.getOrThrow<string>('DATABASE_URL'),
          max: 10,
          idleTimeoutMillis: 30_000,
          connectionTimeoutMillis: 5_000,
          application_name: 'z8-backend',
          options: '-c statement_timeout=5000 -c lock_timeout=2000 -c idle_in_transaction_session_timeout=10000',
          ssl: config.get<string>('DATABASE_SSL') === 'true' ? { rejectUnauthorized: true } : undefined,
        }),
    },
    {
      provide: DatabaseLifecycle,
      inject: ['PG_POOL'],
      useFactory: (pool: Pool) => new DatabaseLifecycle(pool),
    },
  ],
  exports: ['PG_POOL'],
})
export class DatabaseModule {}
