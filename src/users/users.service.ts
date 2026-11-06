import { ConflictException, ForbiddenException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import { Pool } from 'pg';
import { FirebasePrincipal } from '../auth/firebase-principal';
import { Auth } from 'firebase-admin/auth';

@Injectable()
export class UsersService {
  constructor(
    @Inject('PG_POOL') private readonly db: Pool,
    @Inject('FIREBASE_AUTH') private readonly auth: Auth,
  ) {}

  async getFromFirebase(principal: FirebasePrincipal) {
    const result = await this.db.query(
      `SELECT id::text AS id, firebase_uid, email, email_verified, display_name, display_name AS full_name, role, created_at
       FROM app_users WHERE firebase_uid = $1`,
      [principal.uid],
    );
    if (!result.rowCount) throw new NotFoundException({ code: 'user_not_registered' });
    await this.syncAdminClaim(principal.uid, result.rows[0].role);
    return result.rows[0];
  }

  async registerFromFirebase(principal: FirebasePrincipal) {
    if (!principal.email) throw new ForbiddenException('A verified email is required.');
    const client = await this.db.connect();
    try {
      await client.query('BEGIN');
      const current = await client.query(
        `SELECT id::text AS id, firebase_uid, email, email_verified, display_name, display_name AS full_name, role, created_at
         FROM app_users WHERE lower(email) = lower($1) FOR UPDATE`,
        [principal.email],
      );
      let user = current.rows[0];
      if (user && user.firebase_uid && user.firebase_uid !== principal.uid) {
        throw new ConflictException('This email is already linked to another account.');
      }
      if (user?.role === 'admin') {
        throw new ConflictException({
          code: 'admin_account_exists',
          message: 'This email is already registered as an administrator. Please sign in via Admin sign-in.',
        });
      }
      if (user) {
        const updated = await client.query(
          `UPDATE app_users SET firebase_uid = $2, email_verified = $3,
             display_name = COALESCE($4, display_name), last_seen_at = now(), updated_at = now()
           WHERE id = $1
           RETURNING id::text AS id, firebase_uid, email, email_verified, display_name, display_name AS full_name, role, created_at`,
          [user.id, principal.uid, principal.email_verified ?? false, principal.name ?? null],
        );
        user = updated.rows[0];
      } else {
        if (principal.sign_in_provider !== 'password') {
          throw new ForbiddenException({ code: 'user_not_registered' });
        }
        const inserted = await client.query(
          `INSERT INTO app_users (firebase_uid, email, email_verified, display_name, role)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id::text AS id, firebase_uid, email, email_verified, display_name, display_name AS full_name, role, created_at`,
          [principal.uid, principal.email, principal.email_verified ?? false, principal.name ?? null, 'user'],
        );
        user = inserted.rows[0];
      }
      await client.query('COMMIT');
      await this.syncAdminClaim(principal.uid, user.role);
      return user;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  private async syncAdminClaim(uid: string, role: string): Promise<void> {
    const user = await this.auth.getUser(uid);
    const customClaims = { ...user.customClaims, admin: role === 'admin' };
    if (user.customClaims?.admin !== customClaims.admin) {
      await this.auth.setCustomUserClaims(uid, customClaims);
    }
  }

  async registerDevice(principal: FirebasePrincipal, token: string, platform: 'android' | 'ios' | 'web') {
    const user = await this.db.query(
      'SELECT id FROM app_users WHERE firebase_uid = $1',
      [principal.uid],
    );
    if (!user.rowCount) throw new NotFoundException({ code: 'user_not_registered' });
    await this.db.query(
      `INSERT INTO user_devices (user_id, firebase_token, platform, last_seen_at)
       VALUES ($1, $2, $3, now())
       ON CONFLICT (firebase_token) DO UPDATE SET user_id = EXCLUDED.user_id,
         platform = EXCLUDED.platform, last_seen_at = now()`,
      [user.rows[0].id, token, platform],
    );
    return { registered: true };
  }

  async removeDevice(principal: FirebasePrincipal, token: string) {
    await this.db.query(
      `DELETE FROM user_devices d USING app_users u
       WHERE d.user_id = u.id AND u.firebase_uid = $1 AND d.firebase_token = $2`,
      [principal.uid, token],
    );
    return { removed: true };
  }
}
