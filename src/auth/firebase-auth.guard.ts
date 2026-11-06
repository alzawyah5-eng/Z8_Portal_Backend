import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Auth } from 'firebase-admin/auth';
import { Request } from 'express';
import { FirebasePrincipal } from './firebase-principal';
import { Pool } from 'pg';

@Injectable()
export class FirebaseAuthGuard implements CanActivate {
  constructor(
    @Inject('FIREBASE_AUTH') private readonly auth: Auth,
    @Inject('PG_POOL') private readonly db: Pool,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request & { user?: FirebasePrincipal }>();
    const authorization = request.headers.authorization;
    if (!authorization?.startsWith('Bearer ')) {
      throw new UnauthorizedException('A Firebase ID token is required.');
    }

    let decoded;
    try {
      decoded = await this.auth.verifyIdToken(authorization.slice('Bearer '.length), true);
      if (decoded.firebase?.sign_in_provider === 'password') {
        throw new UnauthorizedException('Sign in with the Z8 password service.');
      }
    } catch {
      throw new UnauthorizedException('The Firebase ID token is invalid, expired, or revoked.');
    }
    const account = await this.db.query('SELECT role FROM app_users WHERE firebase_uid = $1', [decoded.uid]);
    request.user = {
      uid: decoded.uid,
      email: decoded.email,
      email_verified: decoded.email_verified,
      name: decoded.name,
      admin: decoded.admin,
      role: account.rows[0]?.role ?? null,
      sign_in_provider: decoded.firebase?.sign_in_provider,
    };
    return true;
  }
}
