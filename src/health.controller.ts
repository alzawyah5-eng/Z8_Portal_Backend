import { Controller, Get } from '@nestjs/common';
import { Inject } from '@nestjs/common';
import { Pool } from 'pg';

@Controller('health')
export class HealthController {
  constructor(@Inject('PG_POOL') private readonly db: Pool) {}

  @Get()
  async health(): Promise<{ status: string; database: string }> {
    await this.db.query('SELECT 1');
    return { status: 'ok', database: 'ok' };
  }
}
