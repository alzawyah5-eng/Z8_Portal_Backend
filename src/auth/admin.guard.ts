import { CanActivate, ExecutionContext, ForbiddenException, Inject, Injectable } from '@nestjs/common';
import { Request } from 'express';
import { FirebasePrincipal } from './firebase-principal';
import { Pool } from 'pg';

@Injectable()
export class AdminGuard implements CanActivate {
  constructor(@Inject('PG_POOL') private readonly db: Pool) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request & { user?: FirebasePrincipal }>();
    const uid = request.user?.uid;
    if (!uid) {
      throw new ForbiddenException('Administrator access is required.');
    }
    const result = await this.db.query(
      `SELECT 1 FROM app_users WHERE firebase_uid = $1 AND role = 'admin'`,
      [uid],
    );
    if (!result.rowCount) throw new ForbiddenException('Administrator access is required.');
    return true;
  }
}
