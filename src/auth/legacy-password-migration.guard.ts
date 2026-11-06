import { CanActivate, ExecutionContext, Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { Auth } from 'firebase-admin/auth';
import { Request } from 'express';
import { Pool } from 'pg';
import { FirebasePrincipal } from './firebase-principal';

@Injectable()
export class LegacyPasswordMigrationGuard implements CanActivate {
  constructor(
    @Inject('FIREBASE_AUTH') private readonly auth: Auth,
    @Inject('PG_POOL') private readonly db: Pool,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request & { user?: FirebasePrincipal }>();
    const authorization = request.headers.authorization;
    if (!authorization?.startsWith('Bearer ')) {
      throw new UnauthorizedException('A legacy sign-in token is required.');
    }
    try {
      const decoded = await this.auth.verifyIdToken(authorization.slice('Bearer '.length), true);
      if (decoded.firebase?.sign_in_provider !== 'password') {
        throw new UnauthorizedException('A legacy password sign-in is required.');
      }
      if (decoded.email_verified !== true) {
        throw new UnauthorizedException('Verify your email before migrating this account.');
      }
      const eligible = await this.db.query(
        `SELECT 1 FROM app_users WHERE firebase_uid = $1
           AND password_hash IS NULL`,
        [decoded.uid],
      );
      if (!eligible.rowCount) throw new UnauthorizedException('This account does not need password migration.');
      request.user = {
        uid: decoded.uid,
        email: decoded.email,
        email_verified: decoded.email_verified,
        name: decoded.name,
        admin: decoded.admin,
        sign_in_provider: decoded.firebase?.sign_in_provider,
      };
      return true;
    } catch {
      throw new UnauthorizedException('The legacy password session is invalid or no longer eligible.');
    }
  }
}
