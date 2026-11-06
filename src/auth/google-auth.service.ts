import { ConflictException, ForbiddenException, Inject, Injectable, Logger, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Auth } from 'firebase-admin/auth';
import { OAuth2Client } from 'google-auth-library';
import { Pool } from 'pg';
import { FirebasePrincipal } from './firebase-principal';

@Injectable()
export class GoogleAuthService {
  private readonly logger = new Logger(GoogleAuthService.name);
  private readonly googleClient: OAuth2Client;
  private readonly allowedAudiences: string[];

  constructor(
    @Inject('PG_POOL') private readonly db: Pool,
    @Inject('FIREBASE_AUTH') private readonly firebaseAuth: Auth,
    config: ConfigService,
  ) {
    const serverClientId = config.getOrThrow<string>('FIREBASE_GOOGLE_SERVER_CLIENT_ID');
    const configuredAudiences = [
      serverClientId,
      config.get<string>('FIREBASE_GOOGLE_ANDROID_CLIENT_ID'),
      config.get<string>('FIREBASE_GOOGLE_IOS_CLIENT_ID'),
    ];
    this.allowedAudiences = Array.from(new Set(
      configuredAudiences.filter((value): value is string => Boolean(value && !value.startsWith('replace-with-'))),
    ));
    this.googleClient = new OAuth2Client();
    this.logger.log('Google OAuth token verifier initialized.');
  }

  async createSession(idToken: string) {
    this.logger.log('Google session request received; verifying token...');
    
    let payload;
    try {
      const ticket = await this.googleClient.verifyIdToken({
        idToken,
        audience: this.allowedAudiences,
      });
      payload = ticket.getPayload();
    } catch (error) {
      const reason = this.classifyTokenError(error);
      this.logger.warn(`Google ID token verification failed; reason=${reason}.`);

      throw new UnauthorizedException({
        code: 'google_token_invalid',
        message: 'Google identity token is invalid or expired.',
      });
    }

    const email = payload?.email?.trim();
    const googleSubject = payload?.sub;
    if (!email || !googleSubject || payload?.email_verified !== true) {
      this.logger.warn('Google ID token verified, but required subject/email verification claims were missing.');
      throw new UnauthorizedException('A Google account with a verified email is required.');
    }
    this.logger.log('Google ID token verified; looking up the email in PostgreSQL (email omitted).');

    let result = await this.db.query(
      `SELECT id, firebase_uid, email, role
       FROM app_users WHERE lower(email) = lower($1)`,
      [email],
    );
    let record = result.rows[0];
    this.logger.log(
      record ? `PostgreSQL account found; role=${record.role}.` : 'No PostgreSQL account found; registering as role=user.',
    );
    if (!record) {
      // New Google accounts are auto-registered as ordinary users. A pre-seeded
      // email invitation wins the unique-email race and retains its database role.
      const created = await this.db.query(
        `INSERT INTO app_users (email, email_verified, display_name, role)
         VALUES ($1, true, $2, 'user')
         ON CONFLICT (lower(email)) WHERE email IS NOT NULL DO NOTHING
         RETURNING id, firebase_uid, email, role`,
        [email, payload?.name ?? null],
      );
      record = created.rows[0];
      if (record) this.logger.log('New Google account registered in PostgreSQL with role=user.');
      if (!record) {
        result = await this.db.query(
          `SELECT id, firebase_uid, email, role
           FROM app_users WHERE lower(email) = lower($1)`,
          [email],
        );
        record = result.rows[0];
      }
      if (!record) throw new ForbiddenException({ code: 'user_not_registered' });
    }

    if (record.role === 'admin') {
      throw new ForbiddenException({
        code: 'admin_password_required',
        message: 'Administrator accounts must sign in with email and password.',
      });
    }

    let firebaseUser;
    if (record.firebase_uid) {
      try {
        firebaseUser = await this.firebaseAuth.getUser(record.firebase_uid);
      } catch {
        this.logger.warn('PostgreSQL account references a Firebase user that could not be loaded.');
        throw new ForbiddenException({ code: 'user_not_registered' });
      }
      if (firebaseUser.disabled || firebaseUser.email?.toLowerCase() !== email.toLowerCase()) {
        this.logger.warn('The linked Firebase account is disabled or its email does not match the verified Google email.');
        throw new ForbiddenException({ code: 'user_not_registered' });
      }
    } else {
      // A PostgreSQL row without a Firebase UID is an explicit invitation.
      try {
        firebaseUser = await this.firebaseAuth.getUserByEmail(email);
        this.logger.log('Matched the verified Google identity to an existing Firebase account.');
      } catch (error) {
        const code = (error as { code?: string })?.code;
        if (code === 'auth/email-already-exists') {
          firebaseUser = await this.firebaseAuth.getUserByEmail(email);
        } else if (code === 'auth/user-not-found') {
          firebaseUser = await this.firebaseAuth.createUser({
            email,
            emailVerified: true,
            displayName: payload?.name ?? undefined,
          });
          this.logger.log('Created a Firebase account for the verified Google identity.');
        } else {
          throw error;
        }
      }
      if (firebaseUser.disabled || firebaseUser.email?.toLowerCase() !== email.toLowerCase()) {
        throw new ForbiddenException({ code: 'user_not_registered' });
      }
      let linked;
      try {
        linked = await this.db.query(
          `UPDATE app_users
           SET firebase_uid = $2, email = $3, email_verified = true,
               display_name = COALESCE($4, display_name), last_seen_at = now(), updated_at = now()
           WHERE id = $1 AND firebase_uid IS NULL
           RETURNING id, firebase_uid, email, role`,
          [record.id, firebaseUser.uid, email, payload?.name ?? null],
        );
      } catch (error) {
        // The same verified Google identity can be processed concurrently, or
        // its Firebase UID may already belong to a different PostgreSQL row.
        // Never overwrite either row's role or turn a unique violation into a 500.
        if ((error as { code?: string })?.code !== '23505') throw error;
        const [uidOwner, emailOwner] = await Promise.all([
          this.db.query(
            'SELECT id, email, role FROM app_users WHERE firebase_uid = $1',
            [firebaseUser.uid],
          ),
          this.db.query(
            'SELECT id FROM app_users WHERE lower(email) = lower($1)',
            [email],
          ),
        ]);
        const owner = uidOwner.rows[0];
        if (owner?.id === record.id && owner.email?.toLowerCase() === email.toLowerCase()) {
          linked = { rows: [{ ...owner, firebase_uid: firebaseUser.uid }], rowCount: 1 };
        } else {
          this.logger.warn(
            `Refused conflicting Google identity link; firebaseUidOwnerFound=${Boolean(owner)}, emailOwnerMatchesInvite=${emailOwner.rows[0]?.id === record.id}.`,
          );
          throw new ConflictException({
            code: 'account_identity_conflict',
            message: 'This Google account is linked to a different app account. Contact support to resolve it.',
          });
        }
      }
      if (linked.rowCount) {
        record = linked.rows[0];
        this.logger.log('Linked Firebase identity to the PostgreSQL account.');
      } else {
        const racedLink = await this.db.query(
          `SELECT id, firebase_uid, email, role FROM app_users
           WHERE id = $1 AND firebase_uid = $2`,
          [record.id, firebaseUser.uid],
        );
        if (!racedLink.rowCount) {
          throw new ForbiddenException({ code: 'user_not_registered' });
        }
        record = racedLink.rows[0];
      }
    }

    firebaseUser = await this.firebaseAuth.updateUser(firebaseUser.uid, {
      email,
      emailVerified: true,
      displayName: payload?.name ?? firebaseUser.displayName,
    });

    await this.db.query(
      `UPDATE app_users SET email = $2, email_verified = true,
         display_name = COALESCE($3, display_name), created_by_id = COALESCE(created_by_id, $4),
         last_seen_at = now(), updated_at = now()
       WHERE id = $1`,
      [record.id, email, payload?.name ?? null, firebaseUser.uid],
    );

    // Synchronize custom user claims in Firebase Auth so client getIdTokenResult(true) preserves admin role!
    await this.firebaseAuth.setCustomUserClaims(firebaseUser.uid, {
      admin: record.role === 'admin',
      role: record.role,
    });

    const firebaseCustomToken = await this.firebaseAuth.createCustomToken(
      firebaseUser.uid,
      { admin: record.role === 'admin', role: record.role },
    );
    this.logger.log(`Google session created successfully; role=${record.role}.`);
    return { firebaseCustomToken, email, displayName: payload?.name ?? null, role: record.role };
  }

  async createFirebaseGoogleSession(principal: FirebasePrincipal) {
    if (principal.sign_in_provider !== 'google.com' || principal.email_verified !== true || !principal.email) {
      throw new ForbiddenException({ code: 'google_account_required', message: 'Sign in with a verified Google account.' });
    }
    if (principal.role === 'admin') {
      throw new ForbiddenException({
        code: 'admin_password_required',
        message: 'Administrator accounts must sign in with email and password.',
      });
    }
    const email = principal.email.trim().toLowerCase();
    const client = await this.db.connect();
    let record;
    try {
      await client.query('BEGIN');
      const byUid = await client.query(
        `SELECT id, firebase_uid, email, role FROM app_users WHERE firebase_uid = $1 FOR UPDATE`,
        [principal.uid],
      );
      if (byUid.rowCount) {
        record = byUid.rows[0];
        if (record.email?.toLowerCase() !== email) {
          throw new ConflictException({ code: 'account_identity_conflict', message: 'This Google account is linked to a different email.' });
        }
      } else {
        const byEmail = await client.query(
          `SELECT id, firebase_uid, email, role FROM app_users WHERE lower(email) = $1 FOR UPDATE`,
          [email],
        );
        // A verified Google identity may take over the Firebase UID attached to
        // this same PostgreSQL email. This preserves seeded/admin roles while
        // allowing password-created Firebase identities to move to Google.
        // The unique UID constraint still blocks a UID owned by another row.
        if (byEmail.rowCount) {
          const linked = await client.query(
            `UPDATE app_users SET firebase_uid = $2, email_verified = true,
               created_by_id = COALESCE(created_by_id, $2),
               display_name = COALESCE($3, display_name), last_seen_at = now(), updated_at = now()
             WHERE id = $1 RETURNING id, firebase_uid, email, role`,
            [byEmail.rows[0].id, principal.uid, principal.name ?? null],
          );
          record = linked.rows[0];
        } else {
          const created = await client.query(
            `INSERT INTO app_users (firebase_uid, email, email_verified, display_name, role, created_by_id)
             VALUES ($1, $2, true, $3, 'user', $1) RETURNING id, firebase_uid, email, role`,
            [principal.uid, email, principal.name ?? null],
          );
          record = created.rows[0];
        }
      }
      await client.query('UPDATE app_users SET email_verified = true, last_seen_at = now(), updated_at = now() WHERE id = $1', [record.id]);
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK').catch(() => undefined);
      if ((error as { code?: string })?.code === '23505') {
        throw new ConflictException({ code: 'account_identity_conflict', message: 'This Google account is already linked to another app account.' });
      }
      throw error;
    } finally {
      client.release();
    }
    await this.firebaseAuth.setCustomUserClaims(principal.uid, { admin: record.role === 'admin', role: record.role });
    const firebaseCustomToken = await this.firebaseAuth.createCustomToken(principal.uid, { admin: record.role === 'admin', role: record.role });
    this.logger.log(`Web Google session linked; role=${record.role}.`);
    return { firebaseCustomToken, email, displayName: principal.name ?? null, role: record.role };
  }

  private classifyTokenError(error: unknown): string {
    const message = error instanceof Error ? error.message.toLowerCase() : '';
    if (message.includes('audience') || message.includes('recipient')) return 'audience_mismatch';
    if (message.includes('expired') || message.includes('expiration')) return 'expired';
    if (message.includes('signature')) return 'invalid_signature';
    if (message.includes('issuer')) return 'invalid_issuer';
    if (message.includes('used too early') || message.includes('issued in the future')) {
      return 'not_yet_valid_or_clock_skew';
    }
    return 'verification_failed';
  }
}
